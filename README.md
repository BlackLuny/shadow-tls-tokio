# shadow-tls-tokio

A Tokio-based implementation of the [ShadowTLS](https://github.com/ihciah/shadow-tls) protocol.

## Features

- **V3 Protocol Support**: Full implementation of the ShadowTLS V3 protocol with HMAC-based authentication
- **Session ID Signing**: Uses `rustls-fork-shadow-tls` for custom session ID generation (full V3 compatibility)
- **Tokio Runtime**: Built on Tokio for high-performance async I/O
- **Generic I/O**: Works with any `AsyncRead + AsyncWrite` stream, not just TCP
- **Compatible**: Designed to be compatible with the original shadow-tls implementation
- **Library + Binaries**: Can be used as a library in your own projects or as standalone binaries

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
shadow-tls-tokio = { git = "https://github.com/user/shadow-tls-tokio" }
```

## Usage

### As a Library

#### Client

```rust
use shadow_tls::{ShadowTlsClient, V3Mode};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = ShadowTlsClient::new(
        "shadow-server.example.com:443".to_string(),
        vec!["www.example.com".to_string()],
        "your-password".to_string(),
        None,
        V3Mode::Lossy,
    )?;

    // Accept incoming connection
    let in_stream = TcpStream::connect("127.0.0.1:1080").await?;
    
    // Connect to ShadowTLS server
    let server_stream = TcpStream::connect(client.target_addr()).await?;
    
    // Relay
    client.relay(in_stream, server_stream).await?;
    
    Ok(())
}
```

#### Server

```rust
use shadow_tls::{ShadowTlsServer, TlsAddrs, V3Mode};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let tls_addr = TlsAddrs::try_from("www.example.com")?;
    
    let server = ShadowTlsServer::new(
        "127.0.0.1:8080".to_string(),  // Backend data server
        tls_addr,
        "your-password".to_string(),
        V3Mode::Lossy,
    );

    // Accept client connection
    let client_stream = /* ... */;
    
    // Relay with custom connectors
    server.relay(
        client_stream,
        |addr| async move { TcpStream::connect(addr).await },
        || async move { TcpStream::connect("127.0.0.1:8080").await },
    ).await?;
    
    Ok(())
}
```

### As Binaries

#### Client Binary

```bash
# Build
cargo build --release --bin shadow-tls-client

# Run
./target/release/shadow-tls-client \
    --listen 127.0.0.1:1080 \
    --server shadow-server.example.com:443 \
    --sni "www.example.com" \
    --password "your-password" \
    --v3 true
```

#### Server Binary

```bash
# Build
cargo build --release --bin shadow-tls-server

# Run
./target/release/shadow-tls-server \
    --listen 0.0.0.0:443 \
    --server 127.0.0.1:8080 \
    --tls "www.example.com" \
    --password "your-password" \
    --v3 true
```

## Command Line Options

### Client

| Option | Description | Default |
|--------|-------------|---------|
| `-l, --listen` | Listen address | `127.0.0.1:1080` |
| `-s, --server` | ShadowTLS server address | Required |
| `--sni` | TLS SNI names (semicolon separated) | Required |
| `-p, --password` | Authentication password | Required |
| `--alpn` | ALPN protocols (semicolon separated) | None |
| `--v3` | Enable V3 protocol | `true` |
| `--strict` | Require TLS 1.3 | `false` |

### Server

| Option | Description | Default |
|--------|-------------|---------|
| `-l, --listen` | Listen address | `0.0.0.0:443` |
| `-s, --server` | Backend data server address | Required |
| `--tls` | TLS handshake server address(es) | Required |
| `-p, --password` | Authentication password | Required |
| `--wildcard-sni` | Wildcard SNI mode: off, authed, all | `off` |
| `--v3` | Enable V3 protocol | `true` |
| `--strict` | Require TLS 1.3 | `false` |

## Protocol Compatibility

This implementation is designed to be compatible with the original [shadow-tls](https://github.com/ihciah/shadow-tls) implementation. You can use:

- This client with the original shadow-tls server
- The original shadow-tls client with this server
- Both this client and server together

## V3 Mode

The V3 protocol provides enhanced security through:

- **HMAC Authentication**: All data is authenticated using HMAC-SHA1
- **TLS 1.3 Support**: Optional strict mode requires TLS 1.3
- **XOR Encryption**: Application data is XOR-encrypted during handshake

### Modes

- `V3Mode::Disabled`: Use V2 protocol (not implemented in this version)
- `V3Mode::Lossy`: V3 protocol, allows TLS 1.2 fallback
- `V3Mode::Strict`: V3 protocol, requires TLS 1.3

## License

MIT
