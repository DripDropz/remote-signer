mod blake2b;
mod challenge;

pub mod remotesigner {
    tonic::include_proto!("remotesigner");
}

pub mod signer {
    use std::thread::sleep;
    use std::time::Duration;

    use bech32::{self, FromBase32};
    use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
    use log::{debug, error, info, trace, warn};
    use tokio::sync::oneshot;
    use tokio::time::timeout;
    use tonic::metadata::MetadataValue;
    use tonic::transport::Channel;
    use tonic::{Code, Request, Status, Streaming};

    use crate::blake2b::{blake2b_224, blake2b_256};
    use crate::challenge::generate_random_challenge;
    use crate::remotesigner::client_message::ClientMessageWrapper::{Handshake, Pong};
    use crate::remotesigner::server_message::ServerMessageWrapper::{
        HandshakeReply, Ping, Transaction,
    };
    use crate::remotesigner::{
        client_message, ClientMessage, HandshakeMessage, PingMessage, ServerMessage,
        SignatureMessage,
    };

    use super::remotesigner::remote_signer_client::RemoteSignerClient;

    pub async fn start(
        host: String,
        port: u16,
        host_public_key: String,
        address: String,
        private_key: String,
        public_key: String,
        jwt_token: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        debug!("host: {}", host);
        debug!("port: {}", port);
        debug!("host_public_key: {}", host_public_key);
        debug!("address: {}", address);
        debug!("private_key: {}", private_key);
        debug!("public_key: {}", public_key);
        debug!("jwt_token: {}", jwt_token);

        let host_public_key_bytes: Vec<u8> = hex::decode(host_public_key)?;
        let host_public_key = PublicKey::from_bytes(&host_public_key_bytes)?;
        let (_, address_base32, _) = bech32::decode(&address)?;
        let address_bytes: Vec<u8> = Vec::<u8>::from_base32(&address_base32)?;
        let vkey = hex::decode(public_key)?;
        let vkey_hash = blake2b_224(&vkey);

        debug!("host_public_key_bytes: {:?}", host_public_key_bytes);
        debug!("address_bytes: {}", hex::encode(&address_bytes));
        debug!("vkey_hash: {}", hex::encode(&vkey_hash));

        if address_bytes[1..] != vkey_hash[..] {
            return Err("vkey_hash does not match address!".into());
        }

        let skey = hex::decode(private_key)?;
        let mut keypair_bytes: Vec<u8> = vec![];
        keypair_bytes.extend(skey.iter());
        keypair_bytes.extend(vkey.iter());
        let keypair: &'static Keypair = Box::leak(Box::new(Keypair::from_bytes(&keypair_bytes)?));

        let dst = format!("https://{host}:{port}");
        let dst: &'static str = Box::leak(dst.into_boxed_str());
        let token: MetadataValue<_> = format!("Bearer {jwt_token}").parse()?;

        let address: &'static str = Box::leak(address.into_boxed_str());
        let vkey: &'static [u8] = Box::leak(vkey.into_boxed_slice());

        loop {
            let challenge = generate_random_challenge(keypair)?;

            match Channel::from_static(dst)
                .connect_timeout(Duration::from_secs(3))
                .connect()
                .await
            {
                Ok(channel) => {
                    let mut client =
                        RemoteSignerClient::with_interceptor(channel, |mut req: Request<()>| {
                            req.metadata_mut().insert("authorization", token.clone());
                            Ok(req)
                        });
                    let (sender, receiver) =
                        oneshot::channel::<tonic::codec::Streaming<ServerMessage>>();
                    let (completed_sender, completed_receiver) = oneshot::channel::<bool>();
                    let outbound = async_stream::stream! {
                        debug!("started outbound stream!");
                        let handshake_message = ClientMessage {
                            client_message_wrapper: Some(
                                Handshake(
                                    HandshakeMessage {
                                        address: address.to_string(),
                                        vkey: vkey.to_vec(),
                                        challenge: challenge.challenge,
                                        challenge_signature: challenge.challenge_signature,
                                    }
                                )
                            ),
                        };
                        debug!("sent handshake_message: {:?}", handshake_message);
                        yield handshake_message;

                        let mut inbound = receiver.await.unwrap();
                        debug!("got inbound stream!");
                        loop {
                            let message_result = match timeout(Duration::from_secs(10), inbound.message()).await {
                                Ok(message_result) => {message_result}
                                Err(_elapsed) => {Err(Status::new(Code::Internal, "10 Second Timeout Elapsed"))}
                            };
                            let server_message_opt = match message_result {
                              Ok(server_message_opt) => server_message_opt,
                                Err(x2) => {
                                    error!("gRPC error status: {x2}");
                                    None
                                },
                            };
                            let server_message_wrapper = server_message_opt.unwrap().server_message_wrapper.unwrap();

                            match server_message_wrapper {
                                HandshakeReply(handshake_reply_message) => {
                                    debug!("HandshakeReply: {:?}", handshake_reply_message);
                                    // Verify the challenge signature
                                    match Signature::from_bytes(&handshake_reply_message.challenge_signature) {
                                        Ok(challenge_signature) => {
                                            match host_public_key.verify(&challenge.challenge_hash.clone(), &challenge_signature) {
                                                Ok(()) => {
                                                    info!("Remote Host Signature Verified! Connected...");
                                                }
                                                Err(verify_error) => {
                                                    error!("Host Challenge Error: {}", verify_error);
                                                    break;
                                                }
                                            };
                                        }
                                        Err(signature_error) => {
                                            error!("Handshake signature load error: {}", signature_error);
                                            break;
                                        }
                                    };
                                }
                                Transaction(transaction_message) => {
                                    debug!("Transaction: {:?}", transaction_message);
                                    let tx_id = blake2b_256(&transaction_message.cbor);
                                    let signature = keypair.sign(&tx_id).to_bytes().to_vec();
                                    let tx_reply = ClientMessage {
                                        client_message_wrapper: Some(
                                            client_message::ClientMessageWrapper::Signature(
                                                SignatureMessage{
                                                    request_id: transaction_message.request_id,
                                                    signature: signature,
                                                }
                                            )
                                        )
                                    };
                                    info!("Signed tx_id: {}", hex::encode(tx_id));
                                    yield tx_reply;
                                }
                                Ping(ping_message) => {
                                    trace!("Ping: {:?}", ping_message);
                                    let pong_message = ClientMessage {
                                        client_message_wrapper: Some(
                                            Pong(
                                                PingMessage {
                                                    message: "pong".to_owned()
                                                }
                                            )
                                        )
                                    };
                                    trace!("Sent Pong: {:?}", pong_message);
                                    yield pong_message;
                                }
                            }
                        }

                        if let Err(error) = completed_sender.send(true) {
                            error!("completed_sender receiver dropped: {}", error);
                        };
                    }; // end stream!

                    match client.connect_to_server(outbound).await {
                        Ok(response) => {
                            let inbound: Streaming<ServerMessage> = response.into_inner();
                            match sender.send(inbound) {
                                Ok(_) => {
                                    match completed_receiver.await {
                                        Ok(_) => {}
                                        Err(_) => {
                                            error!("Failure completed_receiver");
                                        }
                                    };
                                }
                                Err(_error) => {
                                    error!("error sending inbound stream!");
                                }
                            }
                        }
                        Err(status) => {
                            error!("connect_to_server gRPC error: {status}");
                        }
                    };
                }
                Err(error) => {
                    error!("Connection Error: {}", error);
                }
            };

            warn!("Disconnected. Wait 5 seconds to reconnect...");
            sleep(Duration::from_secs(5));
        }
    }
}
