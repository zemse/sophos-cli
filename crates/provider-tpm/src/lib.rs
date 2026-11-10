//! Seed backend built on a TPM 2.0 (including AWS NitroTPM).
//!
//! STUB — to be implemented. Target design (shell out, no C-linked crate):
//!   * `wrap`: seal the seed to the TPM via `systemd-creds encrypt
//!     --with-key=tpm2` (preferred) or `tpm2-tools`, return the sealed blob.
//!   * `unwrap`: unseal via `systemd-creds decrypt` / `tpm2_unseal`.
//!   * `available`: true when a TPM resource manager and the chosen tool exist.
//!
//! Keeping this as a subprocess backend means the crate compiles on macOS too
//! (it just reports unavailable there), so one codebase covers every target.

use totp_core::{KeyProvider, ProviderError};
use zeroize::Zeroizing;

pub struct TpmProvider {
    _private: (),
}

impl TpmProvider {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for TpmProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyProvider for TpmProvider {
    fn id(&self) -> &'static str {
        "tpm"
    }

    fn available(&self) -> bool {
        // TODO: probe for a TPM + systemd-creds/tpm2-tools.
        false
    }

    fn wrap(&self, _seed: &[u8]) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::NotImplemented)
    }

    fn unwrap(&self, _payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        Err(ProviderError::NotImplemented)
    }
}
