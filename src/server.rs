//! ShadowTLS Server implementation.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{self, Cursor, Read};
use std::sync::Arc;

use byteorder::BigEndian;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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

        // Connect to handshake server
        let server_name = sni.and_then(|s| String::from_utf8(s).ok());
        let handshake_addr = self
            .tls_addr
            .find(server_name.as_deref(), client_hello_pass);
        tracing::debug!("connecting to handshake server: {}", handshake_addr);

        let mut handshake_stream = handshake_connector(handshake_addr.into_owned()).await?;
        // handshake_stream.set_nodelay(true)?;

        // Forward ClientHello to handshake server
        handshake_stream.write_all(&first_client_frame).await?;

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
        let pure_data = relay_handshake(
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

        // Verified relay
        verified_relay(data_stream, client_stream, hmac_sr_s, hmac_sr_c, !use_tls13).await
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
async fn relay_handshake<C, H>(
    client: &mut C,
    handshake: &mut H,
    hmac_c: &mut Hmac,
    hmac_sr: &mut Hmac,
    key: &[u8],
) -> io::Result<Vec<u8>>
where
    C: AsyncRead + AsyncWrite + Unpin,
    H: AsyncRead + AsyncWrite + Unpin,
{
    let (mut c_read, mut c_write) = tokio::io::split(client);
    let (mut h_read, mut h_write) = tokio::io::split(handshake);

    // Use channels to coordinate between the two copy tasks
    let (tx, mut rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    let mut tx = Some(tx);

    let hmac_c_clone = hmac_c.to_owned();
    let key_clone = key.to_vec();

    // Copy client -> handshake until HMAC matches
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
                    return Ok::<_, io::Error>(frame[TLS_HMAC_HEADER_SIZE..].to_vec());
                }
            }

            // Forward to handshake server
            h_write.write_all(&frame).await?;
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
                }
            }
        }
    };

    tokio::select! {
        result = client_to_handshake => {
            let pure_data = result?;
            // Signal the other task to stop
            if let Some(tx) = tx.take() {
                let _ = tx.send(Vec::new());
            }
            Ok(pure_data)
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
    rand::thread_rng().fill(&mut buf[TLS_HEADER_SIZE..]);
    write.write_all(&buf).await
}
