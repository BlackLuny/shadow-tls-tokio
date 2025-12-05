//! ShadowTLS Server Binary

use clap::Parser;
use shadow_tls::{ShadowTlsServer, TlsAddrs, V3Mode, WildcardSNI};
use tokio::net::{TcpListener, TcpStream};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser, Debug)]
#[command(author, version, about = "ShadowTLS Server (Tokio)")]
struct Args {
    /// Listen address (e.g., "0.0.0.0:443")
    #[arg(short, long, default_value = "0.0.0.0:443")]
    listen: String,

    /// Backend data server address (e.g., "127.0.0.1:8080")
    #[arg(short, long)]
    server: String,

    /// TLS handshake server address(es)
    /// Format: "fallback" or "sni1:addr1;sni2:addr2;fallback"
    #[arg(long)]
    tls: String,

    /// Password for authentication
    #[arg(short, long)]
    password: String,

    /// Wildcard SNI mode: off, authed, all
    #[arg(long, default_value = "off")]
    wildcard_sni: String,

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

    // Parse TLS addresses
    let mut tls_addr = TlsAddrs::try_from(args.tls.as_str())?;

    // Set wildcard SNI mode
    let wildcard_sni = match args.wildcard_sni.to_lowercase().as_str() {
        "off" => WildcardSNI::Off,
        "authed" => WildcardSNI::Authed,
        "all" => WildcardSNI::All,
        _ => anyhow::bail!("invalid wildcard-sni value: {}", args.wildcard_sni),
    };
    tls_addr.set_wildcard_sni(wildcard_sni);

    // Determine V3 mode
    let v3_mode = match (args.v3, args.strict) {
        (true, true) => V3Mode::Strict,
        (true, false) => V3Mode::Lossy,
        (false, _) => V3Mode::Disabled,
    };

    // Create server
    let server = ShadowTlsServer::new(args.server.clone(), tls_addr, args.password, v3_mode);

    tracing::info!(
        "ShadowTLS server listening on {}, backend: {}",
        args.listen,
        args.server
    );

    // Start listening
    let listener = TcpListener::bind(&args.listen).await?;
    let data_server_addr = args.server.clone();

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tracing::info!("Accepted connection from {}", addr);
                let server = server.clone();
                let data_addr = data_server_addr.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_connection(server, stream, &data_addr).await {
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
    server: ShadowTlsServer,
    client_stream: TcpStream,
    data_server_addr: &str,
) -> anyhow::Result<()> {
    client_stream.set_nodelay(true)?;

    let data_addr = data_server_addr.to_string();

    // Relay with connectors
    server
        .relay(
            client_stream,
            |handshake_addr| async move { TcpStream::connect(handshake_addr).await },
            || async move { TcpStream::connect(data_addr).await },
        )
        .await?;

    Ok(())
}
