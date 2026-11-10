//! Core of sophos-pin-oracle.
//!
//! Three pieces, deliberately backend-agnostic:
//!   * [`generate`] / [`hotp`] — RFC 6238 / RFC 4226 code generation.
//!   * [`KeyProvider`] — the trait every hardware/cloud backend implements.
//!   * [`Envelope`] — the self-describing blob persisted on disk; it names the
//!     backend and carries the TOTP parameters, so the `code` path needs no flags.
//!
//! The seed is never embedded here. A backend wraps it at rest so a copied
//! binary is inert on any other machine; see the crate docs for the threat model.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

mod envelope;
pub use envelope::{Envelope, EnvelopeError};

/// HMAC hash used by the TOTP computation. SHA-1 is the authenticator default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algo {
    Sha1,
    Sha256,
    Sha512,
}

impl Algo {
    pub fn as_u8(self) -> u8 {
        match self {
            Algo::Sha1 => 0,
            Algo::Sha256 => 1,
            Algo::Sha512 => 2,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Algo::Sha1),
            1 => Some(Algo::Sha256),
            2 => Some(Algo::Sha512),
            _ => None,
        }
    }
}

/// TOTP parameters. Defaults match Google Authenticator (6 digits, 30s, SHA-1).
#[derive(Clone, Copy, Debug)]
pub struct TotpParams {
    pub digits: u8,
    pub step: u16,
    pub algo: Algo,
}

impl Default for TotpParams {
    fn default() -> Self {
        Self {
            digits: 6,
            step: 30,
            algo: Algo::Sha1,
        }
    }
}

/// Compute a TOTP code for the given Unix time (RFC 6238, T0 = 0).
pub fn generate(seed: &[u8], unix_time: u64, p: &TotpParams) -> String {
    let counter = unix_time / u64::from(p.step.max(1));
    hotp(seed, counter, p.digits, p.algo)
}

/// Compute an HOTP code for an explicit counter (RFC 4226).
pub fn hotp(seed: &[u8], counter: u64, digits: u8, algo: Algo) -> String {
    let msg = counter.to_be_bytes();
    let mac = match algo {
        Algo::Sha1 => mac_of::<Hmac<Sha1>>(seed, &msg),
        Algo::Sha256 => mac_of::<Hmac<Sha256>>(seed, &msg),
        Algo::Sha512 => mac_of::<Hmac<Sha512>>(seed, &msg),
    };
    // Dynamic truncation, RFC 4226 §5.3.
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(mac[offset] & 0x7f) << 24)
        | (u32::from(mac[offset + 1]) << 16)
        | (u32::from(mac[offset + 2]) << 8)
        | u32::from(mac[offset + 3]);
    let modulo = 10u32.pow(u32::from(digits));
    format!("{:0width$}", bin % modulo, width = usize::from(digits))
}

fn mac_of<M: Mac + hmac::digest::KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
    // HMAC accepts a key of any length, so `new_from_slice` cannot fail here.
    let mut m = <M as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

/// Decode a base32 authenticator setup key (RFC 4648, case-insensitive,
/// spaces and padding tolerated) into raw seed bytes.
pub fn decode_setup_key(key: &str) -> Result<Zeroizing<Vec<u8>>, SeedError> {
    let cleaned: String = key
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.is_empty() {
        return Err(SeedError::Empty);
    }
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned)
        .map(Zeroizing::new)
        .ok_or(SeedError::NotBase32)
}

#[derive(thiserror::Error, Debug)]
pub enum SeedError {
    #[error("setup key is empty")]
    Empty,
    #[error("setup key is not valid base32")]
    NotBase32,
}

/// A backend that wraps the seed at rest and binds it to this machine.
///
/// `wrap` runs once at enrollment and returns an opaque payload; `unwrap`
/// runs on every code generation and must return the raw seed. The payload is
/// stored verbatim inside an [`Envelope`] under the provider's [`id`](KeyProvider::id),
/// so it must be enough for `unwrap` to recover the seed on its own.
pub trait KeyProvider {
    /// Stable identifier recorded in the envelope (e.g. `"secrets"`).
    fn id(&self) -> &'static str;

    /// Whether this backend can be used on the current host right now.
    fn available(&self) -> bool;

    /// Wrap a raw seed. Returns the payload to persist in the envelope.
    fn wrap(&self, seed: &[u8]) -> Result<Vec<u8>, ProviderError>;

    /// Recover the raw seed from a payload produced by [`wrap`](KeyProvider::wrap).
    fn unwrap(&self, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProviderError>;
}

#[derive(thiserror::Error, Debug)]
pub enum ProviderError {
    #[error("backend unavailable on this host")]
    Unavailable,
    #[error("backend not implemented yet")]
    NotImplemented,
    #[error("backend error: {0}")]
    Backend(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors, SHA-1, seed = ASCII "12345678901234567890",
    // 8 digits, step = 30, T0 = 0.
    const SEED_SHA1: &[u8] = b"12345678901234567890";

    fn code8(t: u64) -> String {
        generate(
            SEED_SHA1,
            t,
            &TotpParams {
                digits: 8,
                step: 30,
                algo: Algo::Sha1,
            },
        )
    }

    #[test]
    fn rfc6238_sha1_vectors() {
        assert_eq!(code8(59), "94287082");
        assert_eq!(code8(1111111109), "07081804");
        assert_eq!(code8(1111111111), "14050471");
        assert_eq!(code8(1234567890), "89005924");
        assert_eq!(code8(2000000000), "69279037");
        assert_eq!(code8(20000000000), "65353130");
    }

    #[test]
    fn rfc6238_sha256_sha512_vectors() {
        // SHA-256 uses a 32-byte seed, SHA-512 a 64-byte one (RFC 6238 Appendix B).
        let seed256 = b"12345678901234567890123456789012";
        let seed512 = b"1234567890123456789012345678901234567890123456789012345678901234";
        let p256 = TotpParams {
            digits: 8,
            step: 30,
            algo: Algo::Sha256,
        };
        let p512 = TotpParams {
            digits: 8,
            step: 30,
            algo: Algo::Sha512,
        };
        assert_eq!(generate(seed256, 59, &p256), "46119246");
        assert_eq!(generate(seed512, 59, &p512), "90693936");
    }

    #[test]
    fn six_digits_zero_padded() {
        let c = generate(SEED_SHA1, 0, &TotpParams::default());
        assert_eq!(c.len(), 6);
        assert!(c.chars().all(|ch| ch.is_ascii_digit()));
    }

    #[test]
    fn setup_key_decodes_with_spaces_and_lowercase() {
        // "JBSWY3DPEHPK3PXP" is the canonical base32 for "Hello!\xde\xad\xbe\xef".
        let a = decode_setup_key("JBSWY3DPEHPK3PXP").unwrap();
        let b = decode_setup_key("jbsw y3dp ehpk 3pxp").unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
        assert!(!a.is_empty());
    }
}
