//! TLS protocol constants and utilities.

#![allow(dead_code)]

use std::io::{Cursor, Read};

use byteorder::{BigEndian, ReadBytesExt};

// TLS version constants
pub const TLS_MAJOR: u8 = 0x03;
pub const TLS_MINOR_TLS12: u8 = 0x03;
pub const TLS_MINOR_TLS10: u8 = 0x01;
pub const TLS_13: u16 = 0x0304;

// TLS record types
pub const HANDSHAKE: u8 = 0x16;
pub const APPLICATION_DATA: u8 = 0x17;
pub const ALERT: u8 = 0x15;
pub const CHANGE_CIPHER_SPEC: u8 = 0x14;

// Handshake message types
pub const CLIENT_HELLO: u8 = 0x01;
pub const SERVER_HELLO: u8 = 0x02;

// TLS extension types
pub const SNI_EXT_TYPE: u16 = 0;
pub const SUPPORTED_VERSIONS_TYPE: u16 = 43;

// Size constants
pub const TLS_HEADER_SIZE: usize = 5;
pub const TLS_RANDOM_SIZE: usize = 32;
pub const TLS_SESSION_ID_SIZE: usize = 32;
pub const HMAC_SIZE: usize = 4;
pub const TLS_HMAC_HEADER_SIZE: usize = TLS_HEADER_SIZE + HMAC_SIZE;
pub const COPY_BUF_SIZE: usize = 4096;

// Calculated offsets
pub const SERVER_RANDOM_IDX: usize = TLS_HEADER_SIZE + 1 + 3 + 2;
pub const SESSION_ID_LEN_IDX: usize = TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE;

/// V3 protocol mode.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum V3Mode {
    /// V3 protocol disabled (use V2)
    Disabled,
    /// V3 protocol enabled with lossy mode (allow TLS 1.2 fallback)
    #[default]
    Lossy,
    /// V3 protocol enabled with strict mode (require TLS 1.3)
    Strict,
}

impl std::fmt::Display for V3Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            V3Mode::Disabled => write!(f, "disabled"),
            V3Mode::Lossy => write!(f, "enabled(lossy)"),
            V3Mode::Strict => write!(f, "enabled(strict)"),
        }
    }
}

impl V3Mode {
    #[inline]
    pub fn enabled(&self) -> bool {
        !matches!(self, V3Mode::Disabled)
    }

    #[inline]
    pub fn strict(&self) -> bool {
        matches!(self, V3Mode::Strict)
    }
}

/// A helper trait for fast read and skip operations on Cursor.
#[allow(dead_code)]
pub trait CursorExt {
    fn read_by_u16(&mut self) -> std::io::Result<Vec<u8>>;
    fn skip(&mut self, n: usize) -> std::io::Result<()>;
    fn skip_by_u8(&mut self) -> std::io::Result<u8>;
    fn skip_by_u16(&mut self) -> std::io::Result<u16>;
}

impl<T> CursorExt for Cursor<T>
where
    Cursor<T>: Read,
{
    #[inline]
    fn read_by_u16(&mut self) -> std::io::Result<Vec<u8>> {
        let len = self.read_u16::<BigEndian>()?;
        let mut buf = vec![0; len as usize];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }

    #[inline]
    fn skip(&mut self, n: usize) -> std::io::Result<()> {
        for _ in 0..n {
            self.read_u8()?;
        }
        Ok(())
    }

    #[inline]
    fn skip_by_u8(&mut self) -> std::io::Result<u8> {
        let len = self.read_u8()?;
        self.skip(len as usize)?;
        Ok(len)
    }

    #[inline]
    fn skip_by_u16(&mut self) -> std::io::Result<u16> {
        let len = self.read_u16::<BigEndian>()?;
        self.skip(len as usize)?;
        Ok(len)
    }
}

/// Parse ServerHello and return if TLS 1.3 is supported.
pub fn support_tls13(frame: &[u8]) -> bool {
    if frame.len() < SESSION_ID_LEN_IDX {
        return false;
    }
    let mut cursor = Cursor::new(&frame[SESSION_ID_LEN_IDX..]);

    macro_rules! read_ok {
        ($res: expr) => {
            match $res {
                Ok(r) => r,
                Err(_) => return false,
            }
        };
    }

    // skip session id
    read_ok!(cursor.skip_by_u8());
    // skip cipher suites (2 bytes) + compression method (1 byte)
    read_ok!(cursor.skip(3));
    // read extensions length
    let _ext_len = read_ok!(cursor.read_u16::<BigEndian>());

    loop {
        let ext_type = read_ok!(cursor.read_u16::<BigEndian>());
        if ext_type != SUPPORTED_VERSIONS_TYPE {
            read_ok!(cursor.skip_by_u16());
            continue;
        }
        let ext_len = read_ok!(cursor.read_u16::<BigEndian>());
        let ext_val = read_ok!(cursor.read_u16::<BigEndian>());
        let use_tls13 = ext_len == 2 && ext_val == TLS_13;
        tracing::debug!("found supported_versions extension, tls1.3: {use_tls13}");
        return use_tls13;
    }
}

/// Extract server random from ServerHello frame.
pub fn extract_server_random(frame: &[u8]) -> Option<[u8; TLS_RANDOM_SIZE]> {
    const MIN_LEN: usize = TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE;

    if frame.len() < MIN_LEN || frame[0] != HANDSHAKE || frame[5] != SERVER_HELLO {
        return None;
    }

    let mut server_random = [0; TLS_RANDOM_SIZE];
    server_random.copy_from_slice(&frame[SERVER_RANDOM_IDX..SERVER_RANDOM_IDX + TLS_RANDOM_SIZE]);
    Some(server_random)
}

/// XOR a slice with a key (cycling).
#[inline]
pub fn xor_slice(data: &mut [u8], key: &[u8]) {
    data.iter_mut()
        .zip(key.iter().cycle())
        .for_each(|(d, k)| *d ^= k);
}
