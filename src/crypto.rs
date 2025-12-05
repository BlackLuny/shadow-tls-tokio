//! Cryptographic utilities for ShadowTLS protocol.

use hmac::Mac;
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
