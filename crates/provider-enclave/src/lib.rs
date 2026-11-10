//! Seed backend built on the macOS Secure Enclave.
//!
//! STUB — to be implemented. Target design:
//!   * `wrap`: generate (or reuse) a non-exportable P-256 key in the Secure
//!     Enclave, ECIES-encrypt the seed to its public key, return the ciphertext
//!     as the payload. The private key never leaves hardware.
//!   * `unwrap`: ask the Secure Enclave to decrypt the payload.
//!   * `available`: true only on Apple-silicon / T2 macOS with an enclave.
//!
//! The enclave key is bound to this machine, so the ciphertext payload is inert
//! on any other host (threat model: stolen binary).

use totp_core::{KeyProvider, ProviderError};
use zeroize::Zeroizing;

pub struct EnclaveProvider {
    _private: (),
}

impl EnclaveProvider {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for EnclaveProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyProvider for EnclaveProvider {
    fn id(&self) -> &'static str {
        "enclave"
    }

    fn available(&self) -> bool {
        // TODO: probe for a usable Secure Enclave.
        false
    }

    fn wrap(&self, _seed: &[u8]) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::NotImplemented)
    }

    fn unwrap(&self, _payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        Err(ProviderError::NotImplemented)
    }
}
