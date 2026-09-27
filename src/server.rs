//! ShadowTLS Server implementation.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{self, Cursor, Read};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use byteorder::BigEndian;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::crypto::{kdf, Hmac};
use crate::protocol::*;

/// Wildcard SNI mode for server.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum WildcardSNI {
    /// Disabled
    #[default]
    Off,
    /// For authenticated client only
    Authed,
    /// For all requests
    All,
}

impl std::fmt::Display for WildcardSNI {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WildcardSNI::Off => write!(f, "off"),
            WildcardSNI::Authed => write!(f, "authed"),
            WildcardSNI::All => write!(f, "all"),
        }
    }
}

/// TLS server addresses configuration.
#[derive(Clone, Debug)]
pub struct TlsAddrs {
    dispatch: HashMap<String, String>,
    fallback: String,
    wildcard_sni: WildcardSNI,
}

impl TlsAddrs {
    /// Create new TlsAddrs with a fallback address.
    pub fn new(fallback: String) -> Self {
        Self {
            dispatch: HashMap::new(),
            fallback,
            wildcard_sni: WildcardSNI::Off,
        }
    }

    /// Add a dispatch rule.
    pub fn add_dispatch(&mut self, sni: String, addr: String) {
        self.dispatch.insert(sni, addr);
    }

    /// Set wildcard SNI mode.
    pub fn set_wildcard_sni(&mut self, mode: WildcardSNI) {
        self.wildcard_sni = mode;
    }

    /// Find the address for a given SNI.
    pub fn find(&self, key: Option<&str>, auth: bool) -> Cow<'_, str> {
        match key {
            Some(k) => match self.dispatch.get(k) {
                Some(v) => Cow::Borrowed(v),
                None => match self.wildcard_sni {
                    WildcardSNI::Authed if auth => Cow::Owned(format!("{}:443", k)),
                    WildcardSNI::All => Cow::Owned(format!("{}:443", k)),
                    _ => Cow::Borrowed(&self.fallback),
                },
            },
            None => Cow::Borrowed(&self.fallback),
        }
    }

    /// Check if dispatch map is empty.
    pub fn is_empty(&self) -> bool {
        self.dispatch.is_empty()
    }
}

impl TryFrom<&str> for TlsAddrs {
    type Error = anyhow::Error;

    fn try_from(arg: &str) -> Result<Self, Self::Error> {
        let mut rev_parts: Vec<_> = arg.split(';').rev().collect();
        let fallback = rev_parts
            .pop()
            .and_then(|x| if x.trim().is_empty() { None } else { Some(x) })
            .ok_or_else(|| anyhow::anyhow!("empty server addrs"))?;

        let fallback = if !fallback.contains(':') {
            format!("{}:443", fallback)
        } else {
            fallback.to_string()
        };

        let mut dispatch = HashMap::new();
        for p in rev_parts.into_iter().rev() {
            let parts: Vec<_> = p.trim().split(':').collect();
            match parts.len() {
                1 => {
                    // Just hostname, use as both key and value with port 443
                    let host = parts[0];
                    dispatch.insert(host.to_string(), format!("{}:443", host));
                }
                2 => {
                    // hostname:port or sni:hostname
                    if parts[1].parse::<u16>().is_ok() {
                        // hostname:port
                        dispatch.insert(parts[0].to_string(), p.to_string());
                    } else {
                        // sni:hostname
                        dispatch.insert(parts[0].to_string(), format!("{}:443", parts[1]));
                    }
                }
                3 => {
                    // sni:hostname:port
                    dispatch.insert(parts[0].to_string(), format!("{}:{}", parts[1], parts[2]));
                }
                _ => anyhow::bail!("invalid server addr format: {}", p),
            }
        }

        Ok(TlsAddrs {
            dispatch,
            fallback,
            wildcard_sni: WildcardSNI::Off,
        })
    }
}

impl std::fmt::Display for TlsAddrs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(wildcard-sni:{})", self.wildcard_sni)?;
        for (k, v) in self.dispatch.iter() {
            write!(f, "{}->{};", k, v)?;
        }
        write!(f, "fallback->{}", self.fallback)
    }
}

/// ShadowTLS Server.
///
/// The server accepts connections from ShadowTLS clients, performs TLS handshake
/// with a real TLS server, and then relays authenticated data to a backend server.
#[derive(Clone)]
pub struct ShadowTlsServer {
    target_addr: Arc<String>,
    tls_addr: Arc<TlsAddrs>,
    password: Arc<String>,
    v3: V3Mode,
}

/// Result of the handshake before an unauthenticated connection is relayed.
/// The caller owns both streams on the fallback path and may use its own relay.
pub enum ShadowTlsAccept<S, HIO> {
    Authenticated(ShadowTlsServerStream<S>, Vec<u8>),
    Fallback {
        client: S,
        handshake: HIO,
        reason: io::ErrorKind,
    },
}

impl ShadowTlsServer {
    /// Create a new ShadowTLS server.
    ///
    /// # Arguments
    /// * `target_addr` - The address of the backend data server
    /// * `tls_addr` - TLS handshake server addresses
    /// * `password` - Shared password for HMAC authentication
    /// * `v3` - V3 protocol mode
    pub fn new(target_addr: String, tls_addr: TlsAddrs, password: String, v3: V3Mode) -> Self {
        Self {
            target_addr: Arc::new(target_addr),
            tls_addr: Arc::new(tls_addr),
            password: Arc::new(password),
            v3,
        }
    }

    /// Get the target address.
    pub fn target_addr(&self) -> &str {
        &self.target_addr
    }

    /// Get the TLS address.
    pub fn tls_addr(&self) -> &TlsAddrs {
        &self.tls_addr
    }

    /// Accept a ShadowTLS client connection and return a wrapped stream.
    ///
    /// This method performs the TLS handshake with the handshake server and returns
    /// a `ShadowTlsServerStream` that implements `AsyncRead` and `AsyncWrite`.
    /// Data written to this stream will be automatically wrapped with ShadowTLS
    /// protocol framing, and data read from it will be automatically unwrapped.
    ///
    /// # Type Parameters
    /// * `S` - The client stream type
    /// * `HC` - Handshake connector function type
    /// * `HS` - Handshake future type
    /// * `HIO` - Handshake IO type
    ///
    /// # Returns
    /// A tuple of `(ShadowTlsServerStream, Vec<u8>)` where the Vec contains any
    /// initial data that was received during the handshake phase.
    pub async fn accept<S, HC, HS, HIO>(
        &self,
        client_stream: S,
        handshake_connector: HC,
    ) -> io::Result<(ShadowTlsServerStream<S>, Vec<u8>)>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
        HC: FnOnce(String) -> HS,
        HIO: AsyncRead + AsyncWrite + Unpin + Send,
        HS: std::future::Future<Output = io::Result<HIO>>,
    {
        match self.accept_with_fallback(client_stream, handshake_connector).await? {
            ShadowTlsAccept::Authenticated(stream, prefix) => Ok((stream, prefix)),
            ShadowTlsAccept::Fallback { mut client, mut handshake, reason } => {
                tokio::io::copy_bidirectional(&mut client, &mut handshake).await?;
                let message = match reason {
                    io::ErrorKind::PermissionDenied => "client verification failed",
                    io::ErrorKind::InvalidData => "failed to extract server random",
                    io::ErrorKind::Unsupported => "TLS 1.3 not supported in strict mode",
                    _ => "ShadowTLS handshake fallback",
                };
                Err(io::Error::new(reason, message))
            }
        }
    }

    /// Perform the handshake and return unauthenticated TCP streams to the caller.
    /// The first ClientHello (and, for `InvalidData`/`Unsupported`, the first
    /// server frame) has already been forwarded to the other side, so it will not
    /// be read again from the returned streams; count it separately if needed.
    /// `reason` tells a failed client HMAC (`PermissionDenied`) apart from an
    /// authenticated client whose handshake server is unusable (`InvalidData`,
    /// `Unsupported`).
    pub async fn accept_with_fallback<S, HC, HS, HIO>(
        &self,
        mut client_stream: S,
        handshake_connector: HC,
    ) -> io::Result<ShadowTlsAccept<S, HIO>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
        HC: FnOnce(String) -> HS,
        HIO: AsyncRead + AsyncWrite + Unpin + Send,
        HS: std::future::Future<Output = io::Result<HIO>>,
    {
        if !self.v3.enabled() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "V2 protocol not implemented in tokio version",
            ));
        }

        tracing::debug!("starting V3 server accept");

        // Stage 1.1: Read and validate ClientHello
        let first_client_frame = read_tls_frame(&mut client_stream).await?;
        let (client_hello_pass, sni) = verified_extract_sni(&first_client_frame, &self.password);

        tracing::debug!("client_hello_pass: {}, sni: {:?}", client_hello_pass, sni);

        // Connect to handshake server
        let server_name = sni.and_then(|s| String::from_utf8(s).ok());
        let handshake_addr = self
            .tls_addr
            .find(server_name.as_deref(), client_hello_pass);
        tracing::debug!("connecting to handshake server: {}", handshake_addr);

        let mut handshake_stream = handshake_connector(handshake_addr.into_owned()).await?;

        tracing::debug!("connected to handshake server success",);

        // Forward ClientHello to handshake server
        handshake_stream.write_all(&first_client_frame).await?;

        handshake_stream.flush().await?;

        tracing::debug!("forwarded ClientHello to handshake server success",);

        if !client_hello_pass {
            // Client verification failed, work as SNI proxy
            tracing::warn!("ClientHello verify failed, working as SNI proxy");
            return Ok(ShadowTlsAccept::Fallback {
                client: client_stream,
                handshake: handshake_stream,
                reason: io::ErrorKind::PermissionDenied,
            });
        }
        tracing::debug!("ClientHello verify success");

        // Stage 1.2: Read ServerHello and extract server random
        let first_server_frame = read_tls_frame(&mut handshake_stream).await?;
        client_stream.write_all(&first_server_frame).await?;
        client_stream.flush().await?;

        let server_random = match extract_server_random(&first_server_frame) {
            Some(sr) => sr,
            None => {
                tracing::warn!("ServerRandom extract failed, using transparent fallback");
                return Ok(ShadowTlsAccept::Fallback {
                    client: client_stream,
                    handshake: handshake_stream,
                    reason: io::ErrorKind::InvalidData,
                });
            }
        };
        tracing::debug!("ServerRandom extracted: {:?}", server_random);

        let use_tls13 = support_tls13(&first_server_frame);
        if self.v3.strict() && !use_tls13 {
            tracing::error!("V3 strict mode and TLS 1.3 not supported");
            return Ok(ShadowTlsAccept::Fallback {
                client: client_stream,
                handshake: handshake_stream,
                reason: io::ErrorKind::Unsupported,
            });
        }

        // Stage 1.3: Create HMACs and relay handshake
        let mut hmac_sr_c = Hmac::new(&self.password, (&server_random, b"C"));
        let hmac_sr_s = Hmac::new(&self.password, (&server_random, b"S"));
        let mut hmac_sr = Hmac::new(&self.password, (&server_random, &[]));
        let key = kdf(&self.password, &server_random);

        // Relay handshake until we get authenticated data from client
        let (pure_data, hmac_sr_c) = relay_handshake(
            &mut client_stream,
            &mut handshake_stream,
            &mut hmac_sr_c,
            &mut hmac_sr,
            &key,
        )
        .await?;

        tracing::debug!(
            "handshake relay finished, got {} bytes of pure data",
            pure_data.len()
        );

        // Create the wrapped stream
        let stream = ShadowTlsServerStream::new(
            client_stream,
            hmac_sr_s, // for writing (server -> client)
            hmac_sr_c, // for reading (client -> server)
            !use_tls13,
        );

        Ok(ShadowTlsAccept::Authenticated(stream, pure_data))
    }

    /// Relay a connection from a ShadowTLS client.
    ///
    /// This method handles the ShadowTLS protocol and relays data between
    /// the client and the backend server.
    ///
    /// # Type Parameters
    /// * `S` - The client stream type
    ///
    /// # Arguments
    /// * `client_stream` - The incoming client connection
    /// * `handshake_connector` - A function to connect to the handshake server
    /// * `data_connector` - A function to connect to the data server
    pub async fn relay<S, HC, DC, HS, DS, HIO, DIO>(
        &self,
        client_stream: S,
        handshake_connector: HC,
        data_connector: DC,
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
        HC: FnOnce(String) -> HS,
        DC: FnOnce() -> DS,
        HIO: AsyncRead + AsyncWrite + Unpin + Send,
        DIO: AsyncRead + AsyncWrite + Unpin + Send,
        HS: std::future::Future<Output = io::Result<HIO>>,
        DS: std::future::Future<Output = io::Result<DIO>>,
    {
        if self.v3.enabled() {
            self.relay_v3(client_stream, handshake_connector, data_connector)
                .await
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "V2 protocol not implemented in tokio version",
            ))
        }
    }

    /// Relay using V3 protocol.
    async fn relay_v3<S, HC, DC, HS, DS, HIO, DIO>(
        &self,
        mut client_stream: S,
        handshake_connector: HC,
        data_connector: DC,
    ) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
        HC: FnOnce(String) -> HS,
        DC: FnOnce() -> DS,
        HIO: AsyncRead + AsyncWrite + Unpin + Send,
        DIO: AsyncRead + AsyncWrite + Unpin + Send,
        HS: std::future::Future<Output = io::Result<HIO>>,
        DS: std::future::Future<Output = io::Result<DIO>>,
    {
        tracing::debug!("starting V3 server relay");

        // Stage 1.1: Read and validate ClientHello
        let first_client_frame = read_tls_frame(&mut client_stream).await?;
        let (client_hello_pass, sni) = verified_extract_sni(&first_client_frame, &self.password);

        tracing::debug!("client_hello_pass: {}, sni: {:?}", client_hello_pass, sni);

        // Connect to handshake server
        let server_name = sni.and_then(|s| String::from_utf8(s).ok());
        let handshake_addr = self
            .tls_addr
            .find(server_name.as_deref(), client_hello_pass);
        tracing::debug!("connecting to handshake server: {}", handshake_addr);

        let mut handshake_stream = handshake_connector(handshake_addr.into_owned()).await?;

        tracing::debug!("connected to handshake server success",);

        // Forward ClientHello to handshake server
        handshake_stream.write_all(&first_client_frame).await?;
        handshake_stream.flush().await?;

        if !client_hello_pass {
            // Client verification failed, work as SNI proxy
            tracing::warn!("ClientHello verify failed, working as SNI proxy");
            tokio::io::copy_bidirectional(&mut client_stream, &mut handshake_stream).await?;
            return Ok(());
        }
        tracing::debug!("ClientHello verify success");

        // Stage 1.2: Read ServerHello and extract server random
        let first_server_frame = read_tls_frame(&mut handshake_stream).await?;
        client_stream.write_all(&first_server_frame).await?;
        client_stream.flush().await?;

        let server_random = match extract_server_random(&first_server_frame) {
            Some(sr) => sr,
            None => {
                tracing::warn!("ServerRandom extract failed, copying bidirectional");
                tokio::io::copy_bidirectional(&mut client_stream, &mut handshake_stream).await?;
                return Ok(());
            }
        };
        tracing::debug!("ServerRandom extracted: {:?}", server_random);

        let use_tls13 = support_tls13(&first_server_frame);
        if self.v3.strict() && !use_tls13 {
            tracing::error!("V3 strict mode and TLS 1.3 not supported");
            tokio::io::copy_bidirectional(&mut client_stream, &mut handshake_stream).await?;
            return Ok(());
        }

        // Stage 1.3: Create HMACs and relay handshake
        let mut hmac_sr_c = Hmac::new(&self.password, (&server_random, b"C"));
        let hmac_sr_s = Hmac::new(&self.password, (&server_random, b"S"));
        let mut hmac_sr = Hmac::new(&self.password, (&server_random, &[]));
        let key = kdf(&self.password, &server_random);

        // Relay handshake until we get authenticated data from client
        let (pure_data, hmac_sr_c) = relay_handshake(
            &mut client_stream,
            &mut handshake_stream,
            &mut hmac_sr_c,
            &mut hmac_sr,
            &key,
        )
        .await?;

        tracing::debug!(
            "handshake relay finished, got {} bytes of pure data",
            pure_data.len()
        );

        // Stage 2: Connect to data server and relay
        let mut data_stream = data_connector().await?;
        // data_stream.set_nodelay(true)?;

        // Send the initial pure data
        data_stream.write_all(&pure_data).await?;
        data_stream.flush().await?;

        // Verified relay
        verified_relay(data_stream, client_stream, hmac_sr_s, hmac_sr_c, !use_tls13).await
    }
}

#[cfg(test)]
mod fallback_tests {
    use super::*;

    #[test]
    fn invalid_client_hello_returns_both_streams_after_forwarding_prefix() {
        tokio_test::block_on(async {
            let server = ShadowTlsServer::new(
                "unused".into(), TlsAddrs::new("fake:443".into()),
                "secret".into(), V3Mode::Strict,
            );
            let (mut client_peer, client) = tokio::io::duplex(64);
            let (handshake, mut target_peer) = tokio::io::duplex(64);
            let hello = [22, 3, 3, 0, 0];
            client_peer.write_all(&hello).await.unwrap();
            client_peer.write_all(b"after hello").await.unwrap();
            let outcome = server.accept_with_fallback(client, |_| async { Ok(handshake) })
                .await.unwrap();
            let ShadowTlsAccept::Fallback { mut client, mut handshake, reason } = outcome else {
                panic!("invalid ClientHello must fall back");
            };
            assert_eq!(reason, io::ErrorKind::PermissionDenied);
            let mut got_hello = [0; 5];
            target_peer.read_exact(&mut got_hello).await.unwrap();
            assert_eq!(got_hello, hello);
            let mut next = [0; 11];
            client.read_exact(&mut next).await.unwrap();
            assert_eq!(&next, b"after hello");
            handshake.write_all(b"response").await.unwrap();
            let mut response = [0; 8];
            target_peer.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"response");
        });
    }

    #[test]
    fn original_accept_still_relays_fallback_until_both_sides_close() {
        tokio_test::block_on(async {
            let server = ShadowTlsServer::new(
                "unused".into(), TlsAddrs::new("fake:443".into()),
                "secret".into(), V3Mode::Strict,
            );
            let (mut client_peer, client) = tokio::io::duplex(64);
            let (handshake, mut target_peer) = tokio::io::duplex(64);
            let client_task = async {
                client_peer.write_all(&[22, 3, 3, 0, 0]).await.unwrap();
                client_peer.write_all(b"payload").await.unwrap();
                client_peer.shutdown().await.unwrap();
                let mut response = Vec::new();
                client_peer.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, b"response");
            };
            let target_task = async {
                let mut input = Vec::new();
                target_peer.read_to_end(&mut input).await.unwrap();
                assert_eq!(input, b"\x16\x03\x03\0\0payload");
                target_peer.write_all(b"response").await.unwrap();
                target_peer.shutdown().await.unwrap();
            };
            let (outcome, (), ()) = tokio::join!(
                server.accept(client, |_| async { Ok(handshake) }),
                client_task,
                target_task,
            );
            assert_eq!(outcome.err().unwrap().kind(), io::ErrorKind::PermissionDenied);
        });
    }

    /// Minimal ClientHello whose session id carries a valid ShadowTLS HMAC.
    fn authed_client_hello(password: &str) -> Vec<u8> {
        let body_len = 1 + 3 + 2 + TLS_RANDOM_SIZE + 1 + TLS_SESSION_ID_SIZE;
        let mut frame = vec![HANDSHAKE, TLS_MAJOR, TLS_MINOR_TLS10, 0, body_len as u8];
        frame.extend_from_slice(&[CLIENT_HELLO, 0, 0, (body_len - 4) as u8, TLS_MAJOR, TLS_MINOR_TLS12]);
        frame.extend_from_slice(&[7; TLS_RANDOM_SIZE]);
        frame.push(TLS_SESSION_ID_SIZE as u8);
        frame.extend_from_slice(&[9; TLS_SESSION_ID_SIZE]);
        let hmac_idx = SESSION_ID_LEN_IDX + 1 + TLS_SESSION_ID_SIZE - HMAC_SIZE;
        frame[hmac_idx..hmac_idx + HMAC_SIZE].fill(0);
        let mut hmac = Hmac::new(password, (&[], &[]));
        hmac.update(&frame[TLS_HEADER_SIZE..]);
        let tag = hmac.finalize();
        frame[hmac_idx..hmac_idx + HMAC_SIZE].copy_from_slice(&tag);
        assert!(verified_extract_sni(&frame, password).0);
        frame
    }

    /// Authenticated client, unusable first server frame: the frame reaches the
    /// client before the handoff and the reason names the server-side cause.
    async fn authed_fallback(server_frame: &[u8]) -> io::ErrorKind {
        let server = ShadowTlsServer::new(
            "unused".into(), TlsAddrs::new("fake:443".into()),
            "secret".into(), V3Mode::Strict,
        );
        let (mut client_peer, client) = tokio::io::duplex(256);
        let (handshake, mut target_peer) = tokio::io::duplex(256);
        let hello = authed_client_hello("secret");
        client_peer.write_all(&hello).await.unwrap();
        target_peer.write_all(server_frame).await.unwrap();
        let outcome = server.accept_with_fallback(client, |_| async { Ok(handshake) })
            .await.unwrap();
        let ShadowTlsAccept::Fallback { mut client, mut handshake, reason } = outcome else {
            panic!("unusable server frame must fall back");
        };
        let mut got_hello = vec![0; hello.len()];
        target_peer.read_exact(&mut got_hello).await.unwrap();
        assert_eq!(got_hello, hello);
        let mut got_frame = vec![0; server_frame.len()];
        client_peer.read_exact(&mut got_frame).await.unwrap();
        assert_eq!(got_frame, server_frame);
        client_peer.write_all(b"up").await.unwrap();
        let mut up = [0; 2];
        client.read_exact(&mut up).await.unwrap();
        assert_eq!(&up, b"up");
        handshake.write_all(b"down").await.unwrap();
        let mut down = [0; 4];
        target_peer.read_exact(&mut down).await.unwrap();
        assert_eq!(&down, b"down");
        reason
    }

    #[test]
    fn authed_client_with_non_server_hello_falls_back_as_invalid_data() {
        tokio_test::block_on(async {
            // A handshake record that is not a ServerHello has no server random.
            let frame = [HANDSHAKE, TLS_MAJOR, TLS_MINOR_TLS12, 0, 1, 0x0b];
            assert_eq!(authed_fallback(&frame).await, io::ErrorKind::InvalidData);
        });
    }

    #[test]
    fn authed_client_without_tls13_falls_back_as_unsupported_in_strict_mode() {
        tokio_test::block_on(async {
            // ServerHello truncated after the random: no supported_versions extension.
            let body_len = 1 + 3 + 2 + TLS_RANDOM_SIZE;
            let mut frame = vec![HANDSHAKE, TLS_MAJOR, TLS_MINOR_TLS12, 0, body_len as u8];
            frame.extend_from_slice(&[SERVER_HELLO, 0, 0, (body_len - 4) as u8, TLS_MAJOR, TLS_MINOR_TLS12]);
            frame.extend_from_slice(&[5; TLS_RANDOM_SIZE]);
            assert_eq!(authed_fallback(&frame).await, io::ErrorKind::Unsupported);
        });
    }
}

/// Read a complete TLS frame.
async fn read_tls_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut header = [0u8; TLS_HEADER_SIZE];
    reader.read_exact(&mut header).await?;

    let data_size = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut frame = vec![0u8; TLS_HEADER_SIZE + data_size];
    frame[..TLS_HEADER_SIZE].copy_from_slice(&header);
    reader.read_exact(&mut frame[TLS_HEADER_SIZE..]).await?;

    Ok(frame)
}

/// Verify ClientHello and extract SNI.
fn verified_extract_sni(frame: &[u8], password: &str) -> (bool, Option<Vec<u8>>) {
    const MIN_LEN: usize = TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE + 1 + TLS_SESSION_ID_SIZE;
    const HMAC_IDX: usize = SESSION_ID_LEN_IDX + 1 + TLS_SESSION_ID_SIZE - HMAC_SIZE;
    const ZERO4B: [u8; HMAC_SIZE] = [0; HMAC_SIZE];

    if frame.len() < SESSION_ID_LEN_IDX || frame[0] != HANDSHAKE || frame[5] != CLIENT_HELLO {
        return (false, None);
    }

    let pass = if frame.len() < MIN_LEN || frame[SESSION_ID_LEN_IDX] != TLS_SESSION_ID_SIZE as u8 {
        false
    } else {
        let mut hmac = Hmac::new(password, (&[], &[]));
        hmac.update(&frame[TLS_HEADER_SIZE..HMAC_IDX]);
        hmac.update(&ZERO4B);
        hmac.update(&frame[HMAC_IDX + HMAC_SIZE..]);
        hmac.finalize() == frame[HMAC_IDX..HMAC_IDX + HMAC_SIZE]
    };

    // Extract SNI
    let sni = extract_sni_from_client_hello(frame);
    (pass, sni)
}

/// Extract SNI from ClientHello.
fn extract_sni_from_client_hello(frame: &[u8]) -> Option<Vec<u8>> {
    use byteorder::ReadBytesExt;

    if frame.len() < SESSION_ID_LEN_IDX {
        return None;
    }

    let mut cursor = Cursor::new(&frame[SESSION_ID_LEN_IDX..]);

    macro_rules! read_ok {
        ($res:expr) => {
            match $res {
                Ok(r) => r,
                Err(_) => return None,
            }
        };
    }

    // Skip session id
    let session_id_len = read_ok!(ReadBytesExt::read_u8(&mut cursor)) as usize;
    read_ok!(cursor_skip(&mut cursor, session_id_len));
    // Skip cipher suites
    let cipher_len = read_ok!(ReadBytesExt::read_u16::<BigEndian>(&mut cursor)) as usize;
    read_ok!(cursor_skip(&mut cursor, cipher_len));
    // Skip compression methods
    let comp_len = read_ok!(ReadBytesExt::read_u8(&mut cursor)) as usize;
    read_ok!(cursor_skip(&mut cursor, comp_len));
    // Extensions length
    let _ext_len = read_ok!(ReadBytesExt::read_u16::<BigEndian>(&mut cursor));

    loop {
        let ext_type = read_ok!(ReadBytesExt::read_u16::<BigEndian>(&mut cursor));
        let ext_len = read_ok!(ReadBytesExt::read_u16::<BigEndian>(&mut cursor)) as usize;

        if ext_type != SNI_EXT_TYPE {
            read_ok!(cursor_skip(&mut cursor, ext_len));
            continue;
        }

        // SNI extension
        let _sni_list_len = read_ok!(ReadBytesExt::read_u16::<BigEndian>(&mut cursor));
        let name_type = read_ok!(ReadBytesExt::read_u8(&mut cursor));
        if name_type != 0 {
            return None;
        }
        let name_len = read_ok!(ReadBytesExt::read_u16::<BigEndian>(&mut cursor)) as usize;
        let mut name = vec![0u8; name_len];
        read_ok!(Read::read_exact(&mut cursor, &mut name));
        return Some(name);
    }
}

/// Skip n bytes in a cursor.
fn cursor_skip<T: AsRef<[u8]>>(cursor: &mut Cursor<T>, n: usize) -> io::Result<()> {
    let pos = cursor.position() as usize;
    let len = cursor.get_ref().as_ref().len();
    if pos + n > len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "skip past end",
        ));
    }
    cursor.set_position((pos + n) as u64);
    Ok(())
}

/// Relay handshake between client and handshake server.
/// Returns (pure_data, updated_hmac_c) where updated_hmac_c is the HMAC state after processing.
async fn relay_handshake<C, H>(
    client: &mut C,
    handshake: &mut H,
    hmac_c: &mut Hmac,
    hmac_sr: &mut Hmac,
    key: &[u8],
) -> io::Result<(Vec<u8>, Hmac)>
where
    C: AsyncRead + AsyncWrite + Unpin,
    H: AsyncRead + AsyncWrite + Unpin,
{
    let (mut c_read, mut c_write) = tokio::io::split(client);
    let (mut h_read, mut h_write) = tokio::io::split(handshake);

    // Use channels to coordinate between the two copy tasks
    let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
    let mut tx = Some(tx);

    let hmac_c_clone = hmac_c.to_owned();
    let key_clone = key.to_vec();

    // Copy client -> handshake until HMAC matches
    // Returns (pure_data, updated_hmac)
    let client_to_handshake = async {
        let mut hmac = hmac_c_clone;
        loop {
            let frame = read_tls_frame(&mut c_read).await?;

            if frame.len() > TLS_HMAC_HEADER_SIZE && frame[0] == APPLICATION_DATA {
                // Check HMAC
                let mut tmp_hmac = hmac.to_owned();
                tmp_hmac.update(&frame[TLS_HMAC_HEADER_SIZE..]);
                let h = tmp_hmac.finalize();

                if frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE] == h {
                    // HMAC matches! Update state and return pure data
                    hmac.update(&frame[TLS_HMAC_HEADER_SIZE..]);
                    hmac.update(&frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE]);
                    let pure_data = frame[TLS_HMAC_HEADER_SIZE..].to_vec();
                    return Ok::<_, io::Error>((pure_data, hmac));
                }
            }

            // Forward to handshake server
            h_write.write_all(&frame).await?;
            h_write.flush().await?;
        }
    };

    // Copy handshake -> client with modification
    let handshake_to_client = async {
        let mut hmac = hmac_sr.to_owned();
        loop {
            tokio::select! {
                _ = &mut rx => {
                    // Client side found matching HMAC, stop
                    return Ok::<_, io::Error>(());
                }
                frame_result = read_tls_frame(&mut h_read) => {
                    let mut frame = frame_result?;

                    if frame[0] == APPLICATION_DATA {
                        // Modify: XOR data, add HMAC
                        xor_slice(&mut frame[TLS_HEADER_SIZE..], &key_clone);
                        hmac.update(&frame[TLS_HEADER_SIZE..]);
                        let hash = hmac.finalize();

                        // Insert HMAC after header
                        let old_len = frame.len();
                        frame.resize(old_len + HMAC_SIZE, 0);
                        frame.copy_within(TLS_HEADER_SIZE..old_len, TLS_HMAC_HEADER_SIZE);
                        frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE].copy_from_slice(&hash);

                        // Update length in header
                        let new_data_len = (frame.len() - TLS_HEADER_SIZE) as u16;
                        frame[3..5].copy_from_slice(&new_data_len.to_be_bytes());
                    }

                    c_write.write_all(&frame).await?;
                    c_write.flush().await?;
                }
            }
        }
    };

    tokio::select! {
        result = client_to_handshake => {
            let (pure_data, updated_hmac) = result?;
            // Signal the other task to stop
            if let Some(tx) = tx.take() {
                let _ = tx.send(());
            }
            Ok((pure_data, updated_hmac))
        }
        result = handshake_to_client => {
            result?;
            Err(io::Error::new(io::ErrorKind::Other, "handshake relay ended unexpectedly"))
        }
    }
}

/// Verified relay between data server and client.
async fn verified_relay<D, C>(
    mut data: D,
    mut client: C,
    mut hmac_add: Hmac,
    mut hmac_verify: Hmac,
    alert_enabled: bool,
) -> io::Result<()>
where
    D: AsyncRead + AsyncWrite + Unpin,
    C: AsyncRead + AsyncWrite + Unpin,
{
    tracing::debug!("starting verified relay");

    let (mut data_read, mut data_write) = tokio::io::split(&mut data);
    let (mut client_read, mut client_write) = tokio::io::split(&mut client);

    let data_to_client = async {
        copy_add_appdata(
            &mut data_read,
            &mut client_write,
            &mut hmac_add,
            alert_enabled,
        )
        .await
    };

    let client_to_data = async {
        copy_remove_appdata_and_verify(&mut client_read, &mut data_write, &mut hmac_verify).await
    };

    tokio::select! {
        r = data_to_client => r,
        r = client_to_data => r,
    }
}

/// Copy from data stream, add application data header and HMAC.
async fn copy_add_appdata<R, W>(
    read: &mut R,
    write: &mut W,
    hmac: &mut Hmac,
    alert_enabled: bool,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; COPY_BUF_SIZE];
    let mut frame = Vec::with_capacity(COPY_BUF_SIZE + TLS_HMAC_HEADER_SIZE);

    loop {
        let n = read.read(&mut buffer).await?;
        if n == 0 {
            if alert_enabled {
                send_alert(write).await?;
            }
            return Ok(());
        }

        // Build the frame
        frame.clear();
        frame.push(APPLICATION_DATA);
        frame.push(TLS_MAJOR);
        frame.push(TLS_MINOR_TLS12);

        let frame_len = HMAC_SIZE + n;
        frame.extend_from_slice(&(frame_len as u16).to_be_bytes());

        // Calculate and add HMAC
        hmac.update(&buffer[..n]);
        let hmac_val = hmac.finalize();
        hmac.update(&hmac_val);
        frame.extend_from_slice(&hmac_val);

        // Add data
        frame.extend_from_slice(&buffer[..n]);

        write.write_all(&frame).await?;
        write.flush().await?;
    }
}

/// Copy from client stream, remove application data header and verify HMAC.
async fn copy_remove_appdata_and_verify<R, W>(
    read: &mut R,
    write: &mut W,
    hmac_verify: &mut Hmac,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = Vec::with_capacity(COPY_BUF_SIZE);

    loop {
        // Read TLS frame header
        buffer.clear();
        buffer.resize(TLS_HEADER_SIZE, 0);
        match read.read_exact(&mut buffer[..TLS_HEADER_SIZE]).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }

        let frame_type = buffer[0];
        let data_size = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;

        // Read frame body
        buffer.resize(TLS_HEADER_SIZE + data_size, 0);
        read.read_exact(&mut buffer[TLS_HEADER_SIZE..]).await?;

        match frame_type {
            ALERT => {
                tracing::debug!("received alert, closing");
                return Ok(());
            }
            APPLICATION_DATA => {
                if buffer.len() < TLS_HMAC_HEADER_SIZE {
                    tracing::debug!("application data too short");
                    return Ok(());
                }

                // Verify HMAC
                hmac_verify.update(&buffer[TLS_HMAC_HEADER_SIZE..]);
                let hmac_real = hmac_verify.finalize();
                hmac_verify.update(&hmac_real);

                if buffer[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE] != hmac_real {
                    tracing::debug!("HMAC verification failed");
                    return Ok(());
                }

                // Write the data without the header
                write.write_all(&buffer[TLS_HMAC_HEADER_SIZE..]).await?;
                write.flush().await?;
            }
            _ => {
                tracing::debug!("unexpected frame type: {}", frame_type);
                return Ok(());
            }
        }
    }
}

/// Send a TLS alert.
async fn send_alert<W: AsyncWrite + Unpin>(write: &mut W) -> io::Result<()> {
    const FULL_SIZE: usize = 31;
    let mut buf = vec![0u8; FULL_SIZE];
    buf[0] = ALERT;
    buf[1] = TLS_MAJOR;
    buf[2] = TLS_MINOR_TLS12;
    buf[3] = 0x00;
    buf[4] = (FULL_SIZE - TLS_HEADER_SIZE) as u8;
    rand::fill(&mut buf[TLS_HEADER_SIZE..]);
    write.write_all(&buf).await?;
    write.flush().await
}

/// A wrapped stream that implements AsyncRead/AsyncWrite for ShadowTLS server.
///
/// This stream handles the ShadowTLS V3 protocol automatically:
/// - Writes are wrapped with TLS application data framing and HMAC (server -> client)
/// - Reads unwrap TLS frames and verify HMAC (client -> server)
///
/// # Example
/// ```ignore
/// let server = ShadowTlsServer::new(...);
/// let client_stream = listener.accept().await?;
/// let (mut stream, initial_data) = server.accept(client_stream, |addr| {
///     TcpStream::connect(addr)
/// }).await?;
///
/// // Handle initial_data first if needed
/// process(&initial_data);
///
/// // Now use stream like a normal async stream
/// let mut buf = [0u8; 1024];
/// let n = stream.read(&mut buf).await?;
/// stream.write_all(b"response").await?;
/// ```
pub struct ShadowTlsServerStream<S> {
    inner: S,
    /// HMAC for adding to outgoing data (server -> client)
    hmac_write: Hmac,
    /// HMAC for verifying incoming data (client -> server)
    hmac_read: Hmac,
    /// Whether to send alert on close (TLS 1.2 mode)
    alert_enabled: bool,

    // Read state machine
    read_state: ServerReadState,
    read_frame_buf: Vec<u8>,
    read_header_pos: usize,
    read_body_to_read: usize,
    read_body_pos: usize,
    read_out_buf: Vec<u8>,
    read_out_pos: usize,

    // Write state machine
    write_state: ServerWriteState,
    write_frame: Vec<u8>,
    write_pos: usize,

    // Shutdown state
    shutdown_state: ShutdownState,
    alert_buf: Option<Vec<u8>>,
    alert_pos: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ServerReadState {
    /// Reading TLS frame header
    ReadingHeader,
    /// Reading TLS frame body
    ReadingBody,
    /// Have data ready to output
    HasData,
    /// Stream closed
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ServerWriteState {
    /// Ready to accept new data
    Idle,
    /// Writing a frame
    Writing,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ShutdownState {
    /// Not started
    NotStarted,
    /// Sending alert
    SendingAlert,
    /// Alert sent, shutting down inner
    ShuttingDown,
}

impl<S> ShadowTlsServerStream<S> {
    /// Create a new ShadowTlsServerStream.
    fn new(inner: S, hmac_write: Hmac, hmac_read: Hmac, alert_enabled: bool) -> Self {
        Self {
            inner,
            hmac_write,
            hmac_read,
            alert_enabled,
            read_state: ServerReadState::ReadingHeader,
            read_frame_buf: Vec::with_capacity(COPY_BUF_SIZE + TLS_HEADER_SIZE),
            read_header_pos: 0,
            read_body_to_read: 0,
            read_body_pos: 0,
            read_out_buf: Vec::new(),
            read_out_pos: 0,
            write_state: ServerWriteState::Idle,
            write_frame: Vec::with_capacity(COPY_BUF_SIZE + TLS_HMAC_HEADER_SIZE),
            write_pos: 0,
            shutdown_state: ShutdownState::NotStarted,
            alert_buf: None,
            alert_pos: 0,
        }
    }

    /// Get a reference to the inner stream.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Get a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consume this stream and return the inner stream.
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Process a complete TLS frame and extract payload data.
    /// Returns true if data was extracted and is ready to read.
    fn process_read_frame(&mut self) -> bool {
        let frame = &self.read_frame_buf[..TLS_HEADER_SIZE + self.read_body_to_read];
        let frame_type = frame[0];

        match frame_type {
            ALERT => {
                tracing::debug!("received alert, closing stream");
                self.read_state = ServerReadState::Closed;
                false
            }
            APPLICATION_DATA => {
                if frame.len() < TLS_HMAC_HEADER_SIZE {
                    tracing::debug!("application data too short");
                    self.read_state = ServerReadState::Closed;
                    return false;
                }

                // Verify HMAC
                self.hmac_read.update(&frame[TLS_HMAC_HEADER_SIZE..]);
                let hmac_real = self.hmac_read.finalize();
                self.hmac_read.update(&hmac_real);

                if frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE] == hmac_real {
                    // Extract payload (skip TLS header + HMAC)
                    self.read_out_buf.clear();
                    self.read_out_buf
                        .extend_from_slice(&frame[TLS_HMAC_HEADER_SIZE..]);
                    self.read_out_pos = 0;
                    self.read_state = ServerReadState::HasData;
                    true
                } else {
                    tracing::debug!("HMAC verification failed");
                    self.read_state = ServerReadState::Closed;
                    false
                }
            }
            _ => {
                tracing::debug!("unexpected frame type: {}", frame_type);
                self.read_state = ServerReadState::Closed;
                false
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ShadowTlsServerStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            match this.read_state {
                ServerReadState::Closed => {
                    return Poll::Ready(Ok(()));
                }
                ServerReadState::HasData => {
                    // Return buffered data
                    if this.read_out_pos < this.read_out_buf.len() {
                        let to_copy =
                            (this.read_out_buf.len() - this.read_out_pos).min(buf.remaining());
                        buf.put_slice(
                            &this.read_out_buf[this.read_out_pos..this.read_out_pos + to_copy],
                        );
                        this.read_out_pos += to_copy;
                        if this.read_out_pos >= this.read_out_buf.len() {
                            // All data consumed, read next frame
                            this.read_state = ServerReadState::ReadingHeader;
                            this.read_header_pos = 0;
                        }
                        return Poll::Ready(Ok(()));
                    }
                    // Should not reach here, but reset state
                    this.read_state = ServerReadState::ReadingHeader;
                    this.read_header_pos = 0;
                }
                ServerReadState::ReadingHeader => {
                    // Read TLS frame header
                    this.read_frame_buf.resize(TLS_HEADER_SIZE, 0);
                    while this.read_header_pos < TLS_HEADER_SIZE {
                        let start = this.read_header_pos;
                        let mut temp_buf =
                            ReadBuf::new(&mut this.read_frame_buf[start..TLS_HEADER_SIZE]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut temp_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = temp_buf.filled().len();
                                if n == 0 {
                                    this.read_state = ServerReadState::Closed;
                                    return Poll::Ready(Ok(()));
                                }
                                this.read_header_pos += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    // Header complete
                    this.read_body_to_read =
                        u16::from_be_bytes([this.read_frame_buf[3], this.read_frame_buf[4]])
                            as usize;
                    this.read_frame_buf
                        .resize(TLS_HEADER_SIZE + this.read_body_to_read, 0);
                    this.read_body_pos = 0;
                    this.read_state = ServerReadState::ReadingBody;
                }
                ServerReadState::ReadingBody => {
                    // Read TLS frame body
                    let end = TLS_HEADER_SIZE + this.read_body_to_read;
                    while TLS_HEADER_SIZE + this.read_body_pos < end {
                        let start = TLS_HEADER_SIZE + this.read_body_pos;
                        let mut temp_buf = ReadBuf::new(&mut this.read_frame_buf[start..end]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut temp_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = temp_buf.filled().len();
                                if n == 0 {
                                    this.read_state = ServerReadState::Closed;
                                    return Poll::Ready(Ok(()));
                                }
                                this.read_body_pos += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    // Frame complete, process it
                    this.process_read_frame();
                    // Loop continues to handle the new state
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ShadowTlsServerStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let this = self.get_mut();

        // If we're still writing a previous frame, finish it first
        if this.write_state == ServerWriteState::Writing {
            // Continue writing the current frame
            while this.write_pos < this.write_frame.len() {
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_frame[this.write_pos..])
                {
                    Poll::Ready(Ok(n)) => {
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "failed to write frame",
                            )));
                        }
                        this.write_pos += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            // Frame complete, reset state and return the bytes we already committed
            this.write_state = ServerWriteState::Idle;
            this.write_pos = 0;
            // Return success for the previous write - caller will call again with new data
            return Poll::Ready(Ok(buf.len()));
        }

        // Build the TLS application data frame with HMAC
        this.write_frame.clear();
        this.write_frame.push(APPLICATION_DATA);
        this.write_frame.push(TLS_MAJOR);
        this.write_frame.push(TLS_MINOR_TLS12);

        let frame_len = HMAC_SIZE + buf.len();
        this.write_frame
            .extend_from_slice(&(frame_len as u16).to_be_bytes());

        // Calculate and add HMAC
        this.hmac_write.update(buf);
        let hmac_val = this.hmac_write.finalize();
        this.hmac_write.update(&hmac_val);
        this.write_frame.extend_from_slice(&hmac_val);

        // Add data
        this.write_frame.extend_from_slice(buf);

        // Write the frame
        this.write_pos = 0;
        this.write_state = ServerWriteState::Writing;

        while this.write_pos < this.write_frame.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_frame[this.write_pos..]) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "failed to write frame",
                        )));
                    }
                    this.write_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Frame complete
        this.write_state = ServerWriteState::Idle;
        this.write_pos = 0;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // First, finish any pending frame write
        if this.write_state == ServerWriteState::Writing {
            while this.write_pos < this.write_frame.len() {
                match Pin::new(&mut this.inner).poll_write(cx, &this.write_frame[this.write_pos..])
                {
                    Poll::Ready(Ok(n)) => {
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "failed to write frame",
                            )));
                        }
                        this.write_pos += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            this.write_state = ServerWriteState::Idle;
            this.write_pos = 0;
        }

        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            match this.shutdown_state {
                ShutdownState::NotStarted => {
                    // First, flush any pending write
                    if this.write_state == ServerWriteState::Writing {
                        while this.write_pos < this.write_frame.len() {
                            match Pin::new(&mut this.inner)
                                .poll_write(cx, &this.write_frame[this.write_pos..])
                            {
                                Poll::Ready(Ok(n)) => {
                                    if n == 0 {
                                        // Can't write more, proceed anyway
                                        break;
                                    }
                                    this.write_pos += n;
                                }
                                Poll::Ready(Err(_)) => break,
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                        this.write_state = ServerWriteState::Idle;
                    }

                    if this.alert_enabled {
                        // Prepare alert buffer
                        const FULL_SIZE: usize = 31;
                        let mut alert_buf = vec![0u8; FULL_SIZE];
                        alert_buf[0] = ALERT;
                        alert_buf[1] = TLS_MAJOR;
                        alert_buf[2] = TLS_MINOR_TLS12;
                        alert_buf[3] = 0x00;
                        alert_buf[4] = (FULL_SIZE - TLS_HEADER_SIZE) as u8;
                        rand::fill(&mut alert_buf[TLS_HEADER_SIZE..]);
                        this.alert_buf = Some(alert_buf);
                        this.alert_pos = 0;
                        this.shutdown_state = ShutdownState::SendingAlert;
                    } else {
                        this.shutdown_state = ShutdownState::ShuttingDown;
                    }
                }
                ShutdownState::SendingAlert => {
                    if let Some(ref alert_buf) = this.alert_buf {
                        while this.alert_pos < alert_buf.len() {
                            match Pin::new(&mut this.inner)
                                .poll_write(cx, &alert_buf[this.alert_pos..])
                            {
                                Poll::Ready(Ok(n)) => {
                                    if n == 0 {
                                        // Can't write more, proceed anyway
                                        break;
                                    }
                                    this.alert_pos += n;
                                }
                                Poll::Ready(Err(_)) => break,
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                    }
                    this.alert_buf = None;
                    this.alert_enabled = false;
                    this.shutdown_state = ShutdownState::ShuttingDown;
                }
                ShutdownState::ShuttingDown => {
                    return Pin::new(&mut this.inner).poll_shutdown(cx);
                }
            }
        }
    }
}
