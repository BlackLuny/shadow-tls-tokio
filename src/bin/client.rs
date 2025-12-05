//! ShadowTLS Client Binary

use clap::Parser;
use shadow_tls::{ShadowTlsClient, TlsExtConfig, V3Mode};
use tokio::net::{TcpListener, TcpStream};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser, Debug)]
#[command(author, version, about = "ShadowTLS Client (Tokio)")]
struct Args {
    /// Listen address (e.g., "127.0.0.1:1080")
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    listen: String,

    /// ShadowTLS server address (e.g., "server.example.com:443")
    #[arg(short, long)]
    server: String,

    /// TLS SNI names, semicolon separated (e.g., "www.example.com;example.com")
    #[arg(long)]
    sni: String,

    /// Password for authentication
    #[arg(short, long)]
    password: String,

    /// ALPN protocols, semicolon separated (e.g., "h2;http/1.1")
    #[arg(long)]
    alpn: Option<String>,

    /// Enable V3 protocol (default: true)
    #[arg(long, default_value = "true")]
    v3: bool,

    /// Enable strict mode (require TLS 1.3)
    #[arg(long, default_value = "false")]
    strict: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    let args = Args::parse();

    // Parse TLS names
    let tls_names: Vec<String> = args.sni.split(';').map(|s| s.trim().to_string()).collect();

    // Parse ALPN
    let tls_ext = args.alpn.map(|alpn| {
        let alpns: Vec<Vec<u8>> = alpn
            .split(';')
            .map(|s| s.trim().as_bytes().to_vec())
            .collect();
        TlsExtConfig::new(Some(alpns))
    });

    // Determine V3 mode
    let v3_mode = match (args.v3, args.strict) {
        (true, true) => V3Mode::Strict,
        (true, false) => V3Mode::Lossy,
        (false, _) => V3Mode::Disabled,
    };

    // Create client
    let client = ShadowTlsClient::new(
        args.server.clone(),
        tls_names,
        args.password,
        tls_ext,
        v3_mode,
    )?;

    tracing::info!(
        "ShadowTLS client listening on {}, connecting to {}",
        args.listen,
        args.server
    );

    // Start listening
    let listener = TcpListener::bind(&args.listen).await?;

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tracing::info!("Accepted connection from {}", addr);
                let client = client.clone();
                let server_addr = args.server.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_connection(client, stream, &server_addr).await {
                        tracing::error!("Connection error: {}", e);
                    }
                    tracing::debug!("Connection from {} closed", addr);
                });
            }
            Err(e) => {
                tracing::error!("Accept error: {}", e);
            }
        }
    }
}

async fn handle_connection(
    client: ShadowTlsClient,
    in_stream: TcpStream,
    server_addr: &str,
) -> anyhow::Result<()> {
    in_stream.set_nodelay(true)?;

    // Connect to ShadowTLS server
    let server_stream = TcpStream::connect(server_addr).await?;
    server_stream.set_nodelay(true)?;

    // Relay
    client.relay(in_stream, server_stream).await?;

    Ok(())
}
