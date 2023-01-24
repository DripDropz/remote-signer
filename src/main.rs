use std::env::{set_var, var};
use std::{panic, process};

use clap::builder::ValueParser;
use clap::error::ErrorKind;
use clap::{Error, Parser};

use remote_signer::signer;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    #[arg(long, env = "RSIGNER_HOST", help = "Server dns name or ip address")]
    host: String,

    #[arg(long, env = "RSIGNER_PORT", value_parser = clap::value_parser ! (u16).range(3000..), help = "Server dns name or ip address.")]
    port: u16,

    #[arg(long, env = "RSIGNER_HOST_PUBLIC_KEY", value_parser = validator_regex("^[a-f0-9]{64}$"), help = "Public master key for the remote host as hex.")]
    host_public_key: String,

    #[arg(long, env = "RSIGNER_ADDRESS", value_parser = validator_regex("^addr(_test)?1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{53}$"), help = "Cardano address that holds funds we'll be signing for.")]
    address: String,

    #[arg(long, env = "RSIGNER_SKEY", value_parser = validator_regex("^[a-f0-9]{64}$"), help = "Private skey value as hex.")]
    private_key: String,

    #[arg(long, env = "RSIGNER_VKEY", value_parser = validator_regex("^[a-f0-9]{64}$"), help = "Public vkey value as hex.")]
    public_key: String,

    #[arg(
        long,
        env = "RSIGNER_JWT_TOKEN",
        help = "JWT authentication token for the server."
    )]
    jwt_token: String,
}

pub fn validator_regex(r: &'static str) -> ValueParser {
    ValueParser::from(move |s: &str| -> Result<String, Error> {
        let reg = regex::Regex::new(r).unwrap();
        match reg.is_match(s) {
            true => Ok(s.to_owned()),
            false => Err(Error::raw(
                ErrorKind::ValueValidation,
                format!("not matches {r}"),
            )),
        }
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match var("RUST_LOG") {
        Ok(_) => {}
        Err(_) => {
            // set a default logging level of info if unset.
            set_var("RUST_LOG", "info");
        }
    }
    pretty_env_logger::init_timed();

    // take_hook() returns the default hook in case when a custom one is not set
    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        // invoke the default handler and exit the process
        orig_hook(panic_info);
        process::exit(1);
    }));

    let args = CliArgs::parse();
    signer::start(
        args.host,
        args.port,
        args.host_public_key,
        args.address,
        args.private_key,
        args.public_key,
        args.jwt_token,
    )
    .await?;

    Ok(())
}
