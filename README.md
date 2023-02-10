# remote-signer
Self-custody solution for interacting with the DripDropz platform.

```
Usage: remote-signer --host <HOST> --port <PORT> --host-public-key <HOST_PUBLIC_KEY> --address <ADDRESS> --private-key <PRIVATE_KEY> --public-key <PUBLIC_KEY> --jwt-token <JWT_TOKEN>

Options:
      --host <HOST>
          Server dns name or ip address [env: RSIGNER_HOST=]
      --port <PORT>
          Server dns name or ip address. [env: RSIGNER_PORT=]
      --host-public-key <HOST_PUBLIC_KEY>
          Public master key for the remote host as hex. [env: RSIGNER_HOST_PUBLIC_KEY=]
      --address <ADDRESS>
          Cardano address that holds funds we'll be signing for. [env: RSIGNER_ADDRESS=]
      --private-key <PRIVATE_KEY>
          Private skey value as hex. [env: RSIGNER_SKEY=]
      --public-key <PUBLIC_KEY>
          Public vkey value as hex. [env: RSIGNER_VKEY=]
      --jwt-token <JWT_TOKEN>
          JWT authentication token for the server. [env: RSIGNER_JWT_TOKEN=]
  -h, --help
          Print help
  -V, --version
          Print version
```