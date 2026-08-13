//! Cryptographic utilities for ShadowTLS protocol.

use hmac::{KeyInit, Mac};
use sha2::{Digest, Sha256};

use crate::protocol::HMAC_SIZE;

/// HMAC wrapper for ShadowTLS authentication.
#[derive(Clone)]
pub struct Hmac(hmac::Hmac<sha1::Sha1>);

impl Hmac {
    /// Create a new HMAC instance with password and initial data.
    #[inline]
    pub fn new(password: &str, init_data: (&[u8], &[u8])) -> Self {
        let mut hmac: hmac::Hmac<sha1::Sha1> =
            hmac::Hmac::new_from_slice(password.as_bytes()).expect("unable to build hmac instance");
        hmac.update(init_data.0);
        hmac.update(init_data.1);
        Self(hmac)
    }

    /// Update HMAC with additional data.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Finalize and return the first 4 bytes of the HMAC.
    #[inline]
    pub fn finalize(&self) -> [u8; HMAC_SIZE] {
        let hmac = self.0.clone();
        let hash = hmac.finalize().into_bytes();
        let mut res = [0; HMAC_SIZE];
        res.copy_from_slice(&hash[..HMAC_SIZE]);
        res
    }

    /// Clone the HMAC state.
    #[inline]
    pub fn to_owned(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Key derivation function using SHA-256.
#[inline]
pub fn kdf(password: &str, server_random: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(server_random);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer vectors. These bytes go on the wire (the 4-byte HMAC tag in the
    /// ShadowTLS session id / frame header, and the KDF output keying the V3 stream),
    /// so they pin interoperability with every other ShadowTLS implementation. They
    /// exist to catch a silent behaviour change when the RustCrypto generation
    /// underneath (hmac/sha1/sha2) is bumped — the reference values were produced
    /// independently with Python `hmac`/`hashlib`.
    #[test]
    fn hmac_sha1_known_answer() {
        let mut h = Hmac::new("password", (b"abc", b"C"));
        h.update(b"hello");
        assert_eq!(h.finalize(), [0x14, 0xf9, 0xfb, 0xde]);
    }

    #[test]
    fn kdf_known_answer() {
        let out = kdf("password", &[1, 2, 3]);
        assert_eq!(
            hex_lower(&out),
            "c54139075c8cc46cd6decb74d35c415e5ab097a63afa76e222431d386b224a9e"
        );
    }

    fn hex_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
