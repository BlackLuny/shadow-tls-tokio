//! ShadowTLS Tokio Implementation
//!
//! A tokio-based implementation of the ShadowTLS protocol, compatible with the original
//! monoio-based implementation. This library provides both client and server functionality
//! for the ShadowTLS V3 protocol.
//!
//! # Features
//!
//! - Full V3 protocol support with HMAC-based authentication
//! - Generic over any `AsyncRead + AsyncWrite` stream (not just TCP)
//! - Compatible with the original shadow-tls implementation
//!
//! # Cargo features
//!
//! - `client` (default): the ShadowTLS client half. It is the only user of the
//!   rustls **0.20** fork (`rustls-fork-shadow-tls`), which is the sole published
//!   rustls exposing the ClientHello `session_id` generation hook V3 needs. Turn it
//!   off (`default-features = false`) for server-only consumers to keep the legacy
//!   ring 0.16 / webpki 0.22 TLS stack out of the dependency graph.
//! - `bin`: the two CLI binaries (`clap` + `tracing-subscriber`). Implies `client`.
//!
//! # Example
//!
//! ```rust,no_run
//! # #[cfg(feature = "client")]
//! # fn main() {
//! use shadow_tls::{ShadowTlsClient, ShadowTlsServer, V3Mode};
//!
//! // Client usage
//! async fn run_client() -> anyhow::Result<()> {
//!     let client = ShadowTlsClient::new(
//!         "server.example.com:443".to_string(),
//!         vec!["www.example.com".to_string()],
//!         "password".to_string(),
//!         None,
//!         V3Mode::Strict,
//!     )?;
//!     
//!     // Handle an incoming connection
//!     // let stream = tokio::net::TcpStream::connect("...").await?;
//!     // client.relay(stream).await?;
//!     Ok(())
//! }
//! # }
//! # #[cfg(not(feature = "client"))]
//! # fn main() {}
//! ```

#[cfg(feature = "client")]
mod client;
mod crypto;
mod protocol;
mod server;
mod stream;

#[cfg(feature = "client")]
pub use client::{ShadowTlsClient, ShadowTlsClientStream, TlsExtConfig, TlsNames};
pub use protocol::V3Mode;
pub use server::{ShadowTlsServer, ShadowTlsServerStream, TlsAddrs, WildcardSNI};
