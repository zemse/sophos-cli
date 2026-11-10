//! On-disk format for an enrolled seed.
//!
//! Layout (all integers big-endian):
//! ```text
//!   magic   "SPO1"        4 bytes
//!   version 0x01          1 byte
//!   algo    0|1|2         1 byte   (sha1 / sha256 / sha512)
//!   digits                1 byte
//!   step                  2 bytes
//!   id_len                1 byte
//!   provider id           id_len bytes (utf-8)
//!   payload               remaining bytes (backend-specific)
//! ```
//! The seed is never present; only the backend id and the backend's own
//! wrapped payload are, so reading the file reveals nothing usable off-machine.

use crate::{Algo, TotpParams};

const MAGIC: &[u8; 4] = b"SPO1";
const VERSION: u8 = 1;

#[derive(Clone, Debug)]
pub struct Envelope {
    pub params: TotpParams,
    pub provider_id: String,
    pub payload: Vec<u8>,
}

impl Envelope {
    pub fn new(provider_id: impl Into<String>, params: TotpParams, payload: Vec<u8>) -> Self {
        Self {
            params,
            provider_id: provider_id.into(),
            payload,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, EnvelopeError> {
        let id = self.provider_id.as_bytes();
        if id.len() > u8::MAX as usize {
            return Err(EnvelopeError::IdTooLong);
        }
        let mut out = Vec::with_capacity(10 + id.len() + self.payload.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(self.params.algo.as_u8());
        out.push(self.params.digits);
        out.extend_from_slice(&self.params.step.to_be_bytes());
        out.push(id.len() as u8);
        out.extend_from_slice(id);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() < 10 {
            return Err(EnvelopeError::Truncated);
        }
        if &bytes[0..4] != MAGIC {
            return Err(EnvelopeError::BadMagic);
        }
        if bytes[4] != VERSION {
            return Err(EnvelopeError::UnsupportedVersion(bytes[4]));
        }
        let algo = Algo::from_u8(bytes[5]).ok_or(EnvelopeError::BadAlgo(bytes[5]))?;
        let digits = bytes[6];
        let step = u16::from_be_bytes([bytes[7], bytes[8]]);
        let id_len = bytes[9] as usize;
        let id_start = 10;
        let id_end = id_start + id_len;
        if bytes.len() < id_end {
            return Err(EnvelopeError::Truncated);
        }
        let provider_id = std::str::from_utf8(&bytes[id_start..id_end])
            .map_err(|_| EnvelopeError::BadId)?
            .to_owned();
        let payload = bytes[id_end..].to_vec();
        Ok(Self {
            params: TotpParams { digits, step, algo },
            provider_id,
            payload,
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum EnvelopeError {
    #[error("not a sophos-pin-oracle envelope (bad magic)")]
    BadMagic,
    #[error("envelope truncated")]
    Truncated,
    #[error("unsupported envelope version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown hash algorithm {0}")]
    BadAlgo(u8),
    #[error("provider id is not valid utf-8")]
    BadId,
    #[error("provider id exceeds 255 bytes")]
    IdTooLong,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let env = Envelope::new(
            "secrets",
            TotpParams {
                digits: 6,
                step: 30,
                algo: Algo::Sha1,
            },
            b"totp/default".to_vec(),
        );
        let bytes = env.encode().unwrap();
        let back = Envelope::decode(&bytes).unwrap();
        assert_eq!(back.provider_id, "secrets");
        assert_eq!(back.payload, b"totp/default");
        assert_eq!(back.params.digits, 6);
        assert_eq!(back.params.step, 30);
        assert_eq!(back.params.algo, Algo::Sha1);
    }

    #[test]
    fn rejects_foreign_bytes() {
        assert!(matches!(
            Envelope::decode(b"not an envelope at all"),
            Err(EnvelopeError::BadMagic)
        ));
    }
}
