//! Seed backend for cloud Linux hosts without a TPM (e.g. plain EC2).
//!
//! STUB — to be implemented. Target design (bind to the instance IAM role, not
//! to local hardware):
//!   * KMS mode — `wrap`: `kms:Encrypt` the seed under a CMK (optionally with an
//!     EncryptionContext pinned to the instance id); payload = ciphertext blob.
//!     `unwrap`: `kms:Decrypt` via the instance profile credentials from IMDSv2.
//!   * Secrets Manager mode — `wrap`: store the seed; payload = secret ARN/name.
//!     `unwrap`: `GetSecretValue`.
//!
//! A copied binary off the instance has no IAM role, so the payload is inert
//! (threat model: stolen binary). Enforce IMDSv2 on the instance.

use totp_core::{KeyProvider, ProviderError};
use zeroize::Zeroizing;

pub struct AwsProvider {
    _private: (),
}

impl AwsProvider {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for AwsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyProvider for AwsProvider {
    fn id(&self) -> &'static str {
        "aws"
    }

    fn available(&self) -> bool {
        // TODO: probe IMDS / configured region + key.
        false
    }

    fn wrap(&self, _seed: &[u8]) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::NotImplemented)
    }

    fn unwrap(&self, _payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        Err(ProviderError::NotImplemented)
    }
}
