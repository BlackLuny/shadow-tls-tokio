//! ShadowTLS Client implementation.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rand::seq::SliceRandom;
use rand::Rng;
use rustls_fork_shadow_tls::{OwnedTrustAnchor, RootCertStore, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_rustls_fork_shadow_tls::TlsConnector;

use crate::crypto::{kdf, Hmac};
use crate::protocol::*;

/// TLS server names for client connections.
#[derive(Clone, Debug, PartialEq)]
pub struct TlsNames(Vec<ServerName>);

impl TlsNames {
    /// Create new TlsNames from a list of server names.
    pub fn new(names: Vec<String>) -> anyhow::Result<Self> {
        let names: Result<Vec<_>, _> = names
            .into_iter()
            .map(|s| {
                ServerName::try_from(s.as_str()).map_err(|_| anyhow::anyhow!("invalid server name"))
            })
            .collect();
        let names = names?;
        if names.is_empty() {
            anyhow::bail!("empty tls names");
        }
        Ok(Self(names))
    }

    /// Randomly choose a server name.
    #[inline]
    pub fn random_choose(&self) -> &ServerName {
        self.0.choose(&mut rand::thread_rng()).unwrap()
    }
}

impl TryFrom<&str> for TlsNames {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let names: Vec<String> = value.trim().split(';').map(|s| s.to_string()).collect();
        Self::new(names)
    }
}

impl std::fmt::Display for TlsNames {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

/// TLS extension configuration.
#[derive(Default, Debug, Clone)]
pub struct TlsExtConfig {
    pub alpn: Option<Vec<Vec<u8>>>,
}

impl TlsExtConfig {
    pub fn new(alpn: Option<Vec<Vec<u8>>>) -> Self {
        Self { alpn }
    }
}

impl From<Option<Vec<String>>> for TlsExtConfig {
    fn from(maybe_alpns: Option<Vec<String>>) -> Self {
        Self {
            alpn: maybe_alpns.map(|alpns| alpns.into_iter().map(Into::into).collect()),
        }
    }
}

impl std::fmt::Display for TlsExtConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.alpn.as_ref() {
            Some(alpns) => {
                write!(f, "ALPN(Some(")?;
                for alpn in alpns.iter() {
                    write!(f, "{},", String::from_utf8_lossy(alpn))?;
                }
                write!(f, "))")?;
            }
            None => {
                write!(f, "ALPN(None)")?;
            }
        }
        Ok(())
    }
}

/// ShadowTLS Client.
///
/// The client connects to a ShadowTLS server and performs a real TLS handshake
/// with a handshake server. After the handshake, data is relayed with HMAC
/// authentication.
#[derive(Clone)]
pub struct ShadowTlsClient {
    target_addr: Arc<String>,
    tls_connector: TlsConnector,
    tls_names: Arc<TlsNames>,
    password: Arc<String>,
    v3: V3Mode,
}

impl ShadowTlsClient {
    /// Create a new ShadowTLS client.
    ///
    /// # Arguments
    /// * `target_addr` - The address of the ShadowTLS server
    /// * `tls_names` - List of SNI names to use for TLS handshake
    /// * `password` - Shared password for HMAC authentication
    /// * `tls_ext_config` - Optional TLS extension configuration (ALPN, etc.)
    /// * `v3` - V3 protocol mode
    pub fn new(
        target_addr: String,
        tls_names: Vec<String>,
        password: String,
        tls_ext_config: Option<TlsExtConfig>,
        v3: V3Mode,
    ) -> anyhow::Result<Self> {
        let tls_names = TlsNames::new(tls_names)?;

        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        // TLS 1.2 and TLS 1.3 is enabled.
        let mut config = rustls_fork_shadow_tls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        if let Some(ext) = tls_ext_config {
            if let Some(alpn) = ext.alpn {
                config.alpn_protocols = alpn;
            }
        }

        let tls_connector = TlsConnector::from(config);

        Ok(Self {
            target_addr: Arc::new(target_addr),
            tls_connector,
            tls_names: Arc::new(tls_names),
            password: Arc::new(password),
            v3,
        })
    }

    /// Get the target address.
    pub fn target_addr(&self) -> &str {
        &self.target_addr
    }

    /// Get the SNI name.
    pub fn get_sni(&self) -> &ServerName {
        self.tls_names.random_choose()
    }

    /// Connect to ShadowTLS server and return a wrapped stream.
    ///
    /// This method performs the TLS handshake and returns a `ShadowTlsClientStream`
    /// that implements `AsyncRead` and `AsyncWrite`. Data written to this stream
    /// will be automatically wrapped with ShadowTLS protocol framing, and data
    /// read from it will be automatically unwrapped.
    ///
    /// # Type Parameters
    /// * `T` - The server stream type (to the ShadowTLS server)
    ///
    /// # Returns
    /// A `ShadowTlsClientStream` that can be used like a normal async stream.
    pub async fn connect<T>(&self, server_stream: T) -> io::Result<ShadowTlsClientStream<T>>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if !self.v3.enabled() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "V2 protocol not implemented in tokio version",
            ));
        }

        tracing::debug!("starting V3 connect");

        // Stage 1: TLS handshake with custom session ID generator
        let sni = self.tls_names.random_choose().clone();
        let hmac_init = Hmac::new(&self.password, (&[], &[]));

        // Wrap the server stream to intercept handshake data
        let wrapper = StreamWrapper::new(server_stream, &self.password);

        // Perform TLS handshake with session ID generator
        let tls_stream = self
            .tls_connector
            .connect_with_session_id_generator(sni, wrapper, move |data| {
                generate_session_id(&hmac_init, data)
            })
            .await
            .map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("TLS handshake failed: {}", e))
            })?;

        tracing::debug!("TLS handshake success");

        // Get the inner wrapper back
        let (io, session) = tls_stream.into_parts();

        // Check authorization
        let authorized = io.authorized();
        let tls13 = io.tls13;
        let maybe_srh = io
            .state()
            .as_ref()
            .map(|s| (s.server_random, s.hmac.to_owned()));
        let server_stream = io.into_inner();

        // Check strict mode
        if (maybe_srh.is_none() || !authorized) && self.v3.strict() {
            tracing::warn!("V3 strict enabled: traffic hijacked or TLS1.3 is not supported");
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "traffic hijacked or TLS1.3 not supported",
            ));
        }

        drop(session);
        let (server_random, hmac_sr) = maybe_srh.ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "failed to extract server random")
        })?;

        tracing::debug!("Authorized, ServerRandom extracted: {:?}", server_random);

        // Create HMAC instances for read/write
        let hmac_client = Hmac::new(&self.password, (&server_random, b"C"));
        let hmac_server = Hmac::new(&self.password, (&server_random, b"S"));

        Ok(ShadowTlsClientStream::new(
            server_stream,
            hmac_client,
            hmac_server,
            Some(hmac_sr),
            !tls13,
        ))
    }

    /// Relay a connection through ShadowTLS using a pre-established server connection.
    ///
    /// This is the main entry point for relaying data. It handles the TLS handshake
    /// and then relays data between the incoming stream and the server.
    ///
    /// # Type Parameters
    /// * `S` - The incoming stream type (from the local application)
    /// * `T` - The server stream type (to the ShadowTLS server)
    pub async fn relay<S, T>(&self, in_stream: S, server_stream: T) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if self.v3.enabled() {
            self.relay_v3(in_stream, server_stream).await
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "V2 protocol not implemented in tokio version",
            ))
        }
    }

    /// Relay using V3 protocol.
    async fn relay_v3<S, T>(&self, in_stream: S, server_stream: T) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
        T: AsyncRead + AsyncWrite + Unpin + Send,
    {
        tracing::debug!("starting V3 relay");

        // Stage 1: TLS handshake with custom session ID generator
        let sni = self.tls_names.random_choose().clone();
        let hmac_init = Hmac::new(&self.password, (&[], &[]));

        // Wrap the server stream to intercept handshake data
        let wrapper = StreamWrapper::new(server_stream, &self.password);

        // Perform TLS handshake with session ID generator
        let tls_stream = self
            .tls_connector
            .connect_with_session_id_generator(sni, wrapper, move |data| {
                generate_session_id(&hmac_init, data)
            })
            .await
            .map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("TLS handshake failed: {}", e))
            })?;

        tracing::debug!("TLS handshake success");

        // Get the inner wrapper back
        let (io, session) = tls_stream.into_parts();

        // Check authorization
        let authorized = io.authorized();
        let tls13 = io.tls13;
        let maybe_srh = io
            .state()
            .as_ref()
            .map(|s| (s.server_random, s.hmac.to_owned()));
        let server_stream = io.into_inner();

        // Check strict mode
        if (maybe_srh.is_none() || !authorized) && self.v3.strict() {
            tracing::warn!("V3 strict enabled: traffic hijacked or TLS1.3 is not supported");
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "traffic hijacked or TLS1.3 not supported",
            ));
        }

        drop(session);
        let (server_random, hmac_sr) = maybe_srh.ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "failed to extract server random")
        })?;

        tracing::debug!("Authorized, ServerRandom extracted: {:?}", server_random);

        // Stage 2: Verified relay
        let hmac_sr_s = Hmac::new(&self.password, (&server_random, b"S"));
        let hmac_sr_c = Hmac::new(&self.password, (&server_random, b"C"));

        self.verified_relay(
            in_stream,
            server_stream,
            hmac_sr_c,
            hmac_sr_s,
            Some(hmac_sr),
            !tls13,
        )
        .await
    }

    /// Verified relay between client and server.
    async fn verified_relay<R, W>(
        &self,
        mut raw: R,
        mut tls: W,
        mut hmac_add: Hmac,
        mut hmac_verify: Hmac,
        hmac_ignore: Option<Hmac>,
        alert_enabled: bool,
    ) -> io::Result<()>
    where
        R: AsyncRead + AsyncWrite + Unpin + Send,
        W: AsyncRead + AsyncWrite + Unpin + Send,
    {
        tracing::debug!("starting verified relay, alert_enabled: {}", alert_enabled);

        let (mut raw_read, mut raw_write) = tokio::io::split(&mut raw);
        let (mut tls_read, mut tls_write) = tokio::io::split(&mut tls);

        let copy_to_raw = async {
            copy_remove_appdata_and_verify(
                &mut tls_read,
                &mut raw_write,
                &mut hmac_verify,
                hmac_ignore,
            )
            .await
        };

        let copy_to_tls = async {
            copy_add_appdata(&mut raw_read, &mut tls_write, &mut hmac_add, alert_enabled).await
        };

        tokio::select! {
            r = copy_to_raw => r,
            r = copy_to_tls => r,
        }
    }
}

/// Copy from TLS stream, remove application data header and verify HMAC.
async fn copy_remove_appdata_and_verify<R, W>(
    read: &mut R,
    write: &mut W,
    hmac_verify: &mut Hmac,
    mut hmac_ignore: Option<Hmac>,
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
            Ok(_) => {
                tracing::trace!("read TLS header: {:?}", &buffer[..TLS_HEADER_SIZE]);
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                tracing::debug!("copy_remove_appdata: EOF");
                return Ok(());
            }
            Err(e) => {
                tracing::debug!("copy_remove_appdata: read error: {}", e);
                return Err(e);
            }
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

                // Try to ignore using hmac_ignore first
                if let Some(ref mut hi) = hmac_ignore {
                    if verify_appdata(&buffer, hi, false) {
                        tracing::debug!("useless data skipped");
                        continue;
                    } else {
                        tracing::debug!("useless data detector disabled");
                        hmac_ignore = None;
                    }
                }

                // Verify HMAC
                if verify_appdata(&buffer, hmac_verify, true) {
                    // Write the data without the header
                    write.write_all(&buffer[TLS_HMAC_HEADER_SIZE..]).await?;
                    write.flush().await?;
                } else {
                    tracing::debug!("HMAC verification failed");
                    return Ok(());
                }
            }
            _ => {
                tracing::debug!("unexpected frame type: {}", frame_type);
                return Ok(());
            }
        }
    }
}

/// Verify application data HMAC.
fn verify_appdata(frame: &[u8], hmac: &mut Hmac, sep: bool) -> bool {
    if frame[1] != TLS_MAJOR || frame[2] != TLS_MINOR_TLS12 || frame.len() < TLS_HMAC_HEADER_SIZE {
        return false;
    }
    hmac.update(&frame[TLS_HMAC_HEADER_SIZE..]);
    let hmac_real = hmac.finalize();
    if sep {
        hmac.update(&hmac_real);
    }
    frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE] == hmac_real
}

/// Copy to TLS stream, add application data header and HMAC.
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
            tracing::debug!("copy_add_appdata: EOF from raw stream");
            if alert_enabled {
                send_alert(write).await?;
            }
            return Ok(());
        }

        tracing::debug!("copy_add_appdata: read {} bytes from raw", n);

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

        tracing::debug!("copy_add_appdata: writing {} bytes to tls", frame.len());
        write.write_all(&frame).await?;
        write.flush().await?;
        tracing::debug!("copy_add_appdata: write complete");
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
    rand::thread_rng().fill(&mut buf[TLS_HEADER_SIZE..]);
    write.write_all(&buf).await?;
    write.flush().await
}

/// Stream wrapper for intercepting TLS handshake and extracting server random.
///
/// This wrapper intercepts reads to extract the ServerHello and decode
/// application data frames during the handshake.
pub struct StreamWrapper<S> {
    raw: S,
    password: String,
    // Buffer for reading complete TLS frames
    frame_buf: Vec<u8>,
    frame_pos: usize,
    // Output buffer after processing
    out_buf: Vec<u8>,
    out_pos: usize,
    // State
    read_state: Option<State>,
    read_authorized: bool,
    pub tls13: bool,
    // Reading state machine
    header_read: usize,
    body_to_read: usize,
}

#[derive(Clone)]
pub struct State {
    pub server_random: [u8; TLS_RANDOM_SIZE],
    pub hmac: Hmac,
    pub key: Vec<u8>,
}

impl<S> StreamWrapper<S> {
    pub fn new(raw: S, password: &str) -> Self {
        Self {
            raw,
            password: password.to_string(),
            frame_buf: Vec::with_capacity(16384 + TLS_HEADER_SIZE),
            frame_pos: 0,
            out_buf: Vec::new(),
            out_pos: 0,
            read_state: None,
            read_authorized: false,
            tls13: false,
            header_read: 0,
            body_to_read: 0,
        }
    }

    pub fn authorized(&self) -> bool {
        self.read_authorized
    }

    pub fn state(&self) -> &Option<State> {
        &self.read_state
    }

    pub fn into_inner(self) -> S {
        self.raw
    }

    /// Process a complete TLS frame and optionally transform it.
    fn process_frame(&mut self) {
        let frame = &self.frame_buf[..self.frame_pos];

        match frame[0] {
            HANDSHAKE => {
                if frame.len() > SERVER_RANDOM_IDX + TLS_RANDOM_SIZE
                    && frame.len() > 5
                    && frame[5] == SERVER_HELLO
                {
                    let mut server_random = [0u8; TLS_RANDOM_SIZE];
                    server_random.copy_from_slice(
                        &frame[SERVER_RANDOM_IDX..SERVER_RANDOM_IDX + TLS_RANDOM_SIZE],
                    );
                    self.tls13 = support_tls13(frame);

                    let hmac = Hmac::new(&self.password, (&server_random, &[]));
                    let key = kdf(&self.password, &server_random);
                    self.read_state = Some(State {
                        server_random,
                        hmac,
                        key,
                    });

                    tracing::debug!(
                        "extracted server random: {:?}, tls13: {}",
                        server_random,
                        self.tls13
                    );
                }
                // Output frame as-is
                self.out_buf.clear();
                self.out_buf.extend_from_slice(frame);
                self.out_pos = 0;
            }
            APPLICATION_DATA => {
                self.read_authorized = false;
                if frame.len() > TLS_HMAC_HEADER_SIZE {
                    if let Some(state) = self.read_state.as_mut() {
                        // Verify HMAC: update with data after HMAC header
                        state.hmac.update(&frame[TLS_HMAC_HEADER_SIZE..]);
                        let expected_hmac = state.hmac.finalize();

                        if frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE] == expected_hmac {
                            // Decode: XOR the data
                            let mut decoded = frame[TLS_HMAC_HEADER_SIZE..].to_vec();
                            xor_slice(&mut decoded, &state.key);

                            // Rebuild frame without HMAC
                            let new_len = decoded.len();
                            self.out_buf.clear();
                            self.out_buf.push(APPLICATION_DATA);
                            self.out_buf.push(TLS_MAJOR);
                            self.out_buf.push(TLS_MINOR_TLS12);
                            self.out_buf
                                .extend_from_slice(&(new_len as u16).to_be_bytes());
                            self.out_buf.extend_from_slice(&decoded);
                            self.out_pos = 0;
                            self.read_authorized = true;
                            return;
                        } else {
                            tracing::debug!("app data verification failed");
                        }
                    }
                }
                // Output frame as-is if verification failed
                self.out_buf.clear();
                self.out_buf.extend_from_slice(frame);
                self.out_pos = 0;
            }
            _ => {
                // Output frame as-is
                self.out_buf.clear();
                self.out_buf.extend_from_slice(frame);
                self.out_pos = 0;
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for StreamWrapper<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::pin::Pin;
        use std::task::Poll;

        let this = self.get_mut();

        loop {
            // If we have output data, return it first
            if this.out_pos < this.out_buf.len() {
                let to_copy = (this.out_buf.len() - this.out_pos).min(buf.remaining());
                buf.put_slice(&this.out_buf[this.out_pos..this.out_pos + to_copy]);
                this.out_pos += to_copy;
                return Poll::Ready(Ok(()));
            }

            // Need to read a new frame
            // Step 1: Read header if not done
            if this.header_read < TLS_HEADER_SIZE {
                this.frame_buf.resize(TLS_HEADER_SIZE, 0);
                let start = this.header_read;
                let mut temp_buf =
                    tokio::io::ReadBuf::new(&mut this.frame_buf[start..TLS_HEADER_SIZE]);
                match Pin::new(&mut this.raw).poll_read(cx, &mut temp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = temp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Ok(())); // EOF
                        }
                        this.header_read += n;
                        if this.header_read < TLS_HEADER_SIZE {
                            continue; // Need more header bytes
                        }
                        // Header complete, calculate body size
                        this.body_to_read =
                            u16::from_be_bytes([this.frame_buf[3], this.frame_buf[4]]) as usize;
                        this.frame_buf
                            .resize(TLS_HEADER_SIZE + this.body_to_read, 0);
                        this.frame_pos = TLS_HEADER_SIZE;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // Step 2: Read body
            let end = TLS_HEADER_SIZE + this.body_to_read;
            if this.frame_pos < end {
                let start = this.frame_pos;
                let mut temp_buf = tokio::io::ReadBuf::new(&mut this.frame_buf[start..end]);
                match Pin::new(&mut this.raw).poll_read(cx, &mut temp_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = temp_buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Ok(())); // EOF
                        }
                        this.frame_pos += n;
                        if this.frame_pos < end {
                            continue; // Need more body bytes
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // Frame complete, process it
            this.process_frame();

            // Reset for next frame
            this.header_read = 0;
            this.body_to_read = 0;
            this.frame_pos = 0;
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for StreamWrapper<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.raw).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.raw).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.raw).poll_shutdown(cx)
    }
}

/// Generate a session ID with HMAC signature.
///
/// This is used by the V3 protocol to sign the ClientHello.
#[allow(dead_code)]
pub fn generate_session_id(hmac: &Hmac, client_hello: &[u8]) -> [u8; TLS_SESSION_ID_SIZE] {
    const SESSION_ID_START: usize = 1 + 3 + 2 + TLS_RANDOM_SIZE + 1;

    if client_hello.len() < SESSION_ID_START + TLS_SESSION_ID_SIZE {
        tracing::warn!("unexpected client hello length");
        return [0; TLS_SESSION_ID_SIZE];
    }

    let mut session_id = [0u8; TLS_SESSION_ID_SIZE];
    rand::thread_rng().fill(&mut session_id[..TLS_SESSION_ID_SIZE - HMAC_SIZE]);

    let mut hmac = hmac.to_owned();
    hmac.update(&client_hello[..SESSION_ID_START]);
    hmac.update(&session_id);
    hmac.update(&client_hello[SESSION_ID_START + TLS_SESSION_ID_SIZE..]);
    let hmac_val = hmac.finalize();

    session_id[TLS_SESSION_ID_SIZE - HMAC_SIZE..].copy_from_slice(&hmac_val);
    session_id
}

/// A wrapped stream that implements AsyncRead/AsyncWrite for ShadowTLS client.
///
/// This stream handles the ShadowTLS V3 protocol automatically:
/// - Writes are wrapped with TLS application data framing and HMAC
/// - Reads unwrap TLS frames and verify HMAC
///
/// # Example
/// ```ignore
/// let client = ShadowTlsClient::new(...)?;
/// let server_stream = TcpStream::connect(server_addr).await?;
/// let mut stream = client.connect(server_stream).await?;
///
/// // Now use stream like a normal async stream
/// stream.write_all(b"hello").await?;
/// let mut buf = [0u8; 1024];
/// let n = stream.read(&mut buf).await?;
/// ```
pub struct ShadowTlsClientStream<S> {
    inner: S,
    /// HMAC for adding to outgoing data (client -> server)
    hmac_write: Hmac,
    /// HMAC for verifying incoming data (server -> client)
    hmac_read: Hmac,
    /// HMAC for ignoring useless data during initial phase
    hmac_ignore: Option<Hmac>,
    /// Whether to send alert on close (TLS 1.2 mode)
    alert_enabled: bool,

    // Read state machine
    read_state: ReadState,
    read_frame_buf: Vec<u8>,
    read_header_pos: usize,
    read_body_to_read: usize,
    read_body_pos: usize,
    read_out_buf: Vec<u8>,
    read_out_pos: usize,

    // Write state machine
    write_state: ClientWriteState,
    write_frame: Vec<u8>,
    write_pos: usize,

    // Shutdown state
    shutdown_state: ClientShutdownState,
    alert_buf: Option<Vec<u8>>,
    alert_pos: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ReadState {
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
enum ClientWriteState {
    /// Ready to accept new data
    Idle,
    /// Writing a frame
    Writing,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ClientShutdownState {
    /// Not started
    NotStarted,
    /// Sending alert
    SendingAlert,
    /// Alert sent, shutting down inner
    ShuttingDown,
}

impl<S> ShadowTlsClientStream<S> {
    /// Create a new ShadowTlsClientStream.
    fn new(
        inner: S,
        hmac_write: Hmac,
        hmac_read: Hmac,
        hmac_ignore: Option<Hmac>,
        alert_enabled: bool,
    ) -> Self {
        Self {
            inner,
            hmac_write,
            hmac_read,
            hmac_ignore,
            alert_enabled,
            read_state: ReadState::ReadingHeader,
            read_frame_buf: Vec::with_capacity(COPY_BUF_SIZE + TLS_HEADER_SIZE),
            read_header_pos: 0,
            read_body_to_read: 0,
            read_body_pos: 0,
            read_out_buf: Vec::new(),
            read_out_pos: 0,
            write_state: ClientWriteState::Idle,
            write_frame: Vec::with_capacity(COPY_BUF_SIZE + TLS_HMAC_HEADER_SIZE),
            write_pos: 0,
            shutdown_state: ClientShutdownState::NotStarted,
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
                self.read_state = ReadState::Closed;
                false
            }
            APPLICATION_DATA => {
                if frame.len() < TLS_HMAC_HEADER_SIZE {
                    tracing::debug!("application data too short");
                    self.read_state = ReadState::Closed;
                    return false;
                }

                // Try to ignore using hmac_ignore first
                if let Some(ref mut hi) = self.hmac_ignore {
                    if verify_appdata(frame, hi, false) {
                        tracing::debug!("useless data skipped");
                        // Reset to read next frame
                        self.read_state = ReadState::ReadingHeader;
                        self.read_header_pos = 0;
                        return false;
                    } else {
                        tracing::debug!("useless data detector disabled");
                        self.hmac_ignore = None;
                    }
                }

                // Verify HMAC
                if verify_appdata(frame, &mut self.hmac_read, true) {
                    // Extract payload (skip TLS header + HMAC)
                    self.read_out_buf.clear();
                    self.read_out_buf
                        .extend_from_slice(&frame[TLS_HMAC_HEADER_SIZE..]);
                    self.read_out_pos = 0;
                    self.read_state = ReadState::HasData;
                    true
                } else {
                    tracing::debug!("HMAC verification failed");
                    self.read_state = ReadState::Closed;
                    false
                }
            }
            _ => {
                tracing::debug!("unexpected frame type: {}", frame_type);
                self.read_state = ReadState::Closed;
                false
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ShadowTlsClientStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            match this.read_state {
                ReadState::Closed => {
                    return Poll::Ready(Ok(()));
                }
                ReadState::HasData => {
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
                            this.read_state = ReadState::ReadingHeader;
                            this.read_header_pos = 0;
                        }
                        return Poll::Ready(Ok(()));
                    }
                    // Should not reach here, but reset state
                    this.read_state = ReadState::ReadingHeader;
                    this.read_header_pos = 0;
                }
                ReadState::ReadingHeader => {
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
                                    this.read_state = ReadState::Closed;
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
                    this.read_state = ReadState::ReadingBody;
                }
                ReadState::ReadingBody => {
                    // Read TLS frame body
                    let end = TLS_HEADER_SIZE + this.read_body_to_read;
                    while TLS_HEADER_SIZE + this.read_body_pos < end {
                        let start = TLS_HEADER_SIZE + this.read_body_pos;
                        let mut temp_buf = ReadBuf::new(&mut this.read_frame_buf[start..end]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut temp_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = temp_buf.filled().len();
                                if n == 0 {
                                    this.read_state = ReadState::Closed;
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

impl<S: AsyncWrite + Unpin> AsyncWrite for ShadowTlsClientStream<S> {
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
        if this.write_state == ClientWriteState::Writing {
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
            // Frame complete, reset state and return the bytes we already committed
            this.write_state = ClientWriteState::Idle;
            this.write_pos = 0;
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
        this.write_state = ClientWriteState::Writing;

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
        this.write_state = ClientWriteState::Idle;
        this.write_pos = 0;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // First, finish any pending frame write
        if this.write_state == ClientWriteState::Writing {
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
            this.write_state = ClientWriteState::Idle;
            this.write_pos = 0;
        }

        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            match this.shutdown_state {
                ClientShutdownState::NotStarted => {
                    // First, flush any pending write
                    if this.write_state == ClientWriteState::Writing {
                        while this.write_pos < this.write_frame.len() {
                            match Pin::new(&mut this.inner).poll_write(cx, &this.write_frame[this.write_pos..]) {
                                Poll::Ready(Ok(n)) => {
                                    if n == 0 {
                                        break;
                                    }
                                    this.write_pos += n;
                                }
                                Poll::Ready(Err(_)) => break,
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                        this.write_state = ClientWriteState::Idle;
                    }

                    if this.alert_enabled {
                        const FULL_SIZE: usize = 31;
                        let mut alert_buf = vec![0u8; FULL_SIZE];
                        alert_buf[0] = ALERT;
                        alert_buf[1] = TLS_MAJOR;
                        alert_buf[2] = TLS_MINOR_TLS12;
                        alert_buf[3] = 0x00;
                        alert_buf[4] = (FULL_SIZE - TLS_HEADER_SIZE) as u8;
                        rand::thread_rng().fill(&mut alert_buf[TLS_HEADER_SIZE..]);
                        this.alert_buf = Some(alert_buf);
                        this.alert_pos = 0;
                        this.shutdown_state = ClientShutdownState::SendingAlert;
                    } else {
                        this.shutdown_state = ClientShutdownState::ShuttingDown;
                    }
                }
                ClientShutdownState::SendingAlert => {
                    if let Some(ref alert_buf) = this.alert_buf {
                        while this.alert_pos < alert_buf.len() {
                            match Pin::new(&mut this.inner).poll_write(cx, &alert_buf[this.alert_pos..]) {
                                Poll::Ready(Ok(n)) => {
                                    if n == 0 {
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
                    this.shutdown_state = ClientShutdownState::ShuttingDown;
                }
                ClientShutdownState::ShuttingDown => {
                    return Pin::new(&mut this.inner).poll_shutdown(cx);
                }
            }
        }
    }
}
