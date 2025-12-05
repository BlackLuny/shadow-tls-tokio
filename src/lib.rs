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
//! # Example
//!
//! ```rust,no_run
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
//! ```

mod client;
mod crypto;
mod protocol;
mod server;
mod stream;

pub use client::{ShadowTlsClient, TlsExtConfig, TlsNames};
pub use protocol::V3Mode;
pub use server::{ShadowTlsServer, TlsAddrs, WildcardSNI};
