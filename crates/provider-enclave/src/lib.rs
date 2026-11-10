//! Seed backend built on the macOS Secure Enclave.
//!
//! `wrap` creates a non-exportable P-256 key inside the Secure Enclave and
//! ECIES-encrypts the seed to it (ephemeral ECDH, HKDF-SHA256, AES-256-GCM).
//! The payload carries the ciphertext plus the key's CryptoKit
//! `dataRepresentation`, an opaque blob that is itself encrypted to this
//! machine's enclave. `unwrap` hands the blob back to the enclave, which does
//! the ECDH inside hardware, so the private key never leaves it.
//!
//! A copied binary + payload on another host cannot load the key blob, so it is
//! inert (threat model: stolen binary). Access control is
//! `WhenUnlockedThisDeviceOnly` + `privateKeyUsage` with no user-presence or
//! biometry flag, so the runtime path never prompts.
//!
//! Why CryptoKit and not `SecKey` (security-framework): a persisted Secure
//! Enclave `SecKey` needs a keychain item, and adding one fails with
//! errSecMissingEntitlement (-34018) in an unsigned binary. CryptoKit blobs need
//! no keychain, so the payload is self-contained. The shim is Swift, compiled by
//! build.rs (needs `swiftc`). Non-macOS builds compile to a stub that reports
//! `Unavailable`.

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

#[cfg(target_os = "macos")]
mod ffi {
    use super::*;

    extern "C" {
        fn se_available() -> i32;
        fn se_wrap(seed: *const u8, n: usize, out: *mut *mut u8, len: *mut usize) -> i32;
        fn se_unwrap(payload: *const u8, n: usize, out: *mut *mut u8, len: *mut usize) -> i32;
        fn se_free(p: *mut u8);
    }

    pub fn available() -> bool {
        unsafe { se_available() == 1 }
    }

    /// Calls a shim entry point; on success returns the output bytes (zeroized
    /// on drop), on failure the shim's message.
    fn call(
        f: unsafe extern "C" fn(*const u8, usize, *mut *mut u8, *mut usize) -> i32,
        input: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut len = 0usize;
        // SAFETY: `out`/`len` are written by the shim; the buffer is copied
        // then wiped and freed below.
        unsafe {
            let rc = f(input.as_ptr(), input.len(), &mut out, &mut len);
            if out.is_null() {
                return Err(ProviderError::Backend(
                    "enclave shim returned no data".into(),
                ));
            }
            let slice = std::slice::from_raw_parts_mut(out, len);
            let bytes = Zeroizing::new(slice.to_vec());
            slice.fill(0);
            se_free(out);
            if rc == 0 {
                Ok(bytes)
            } else {
                Err(ProviderError::Backend(
                    String::from_utf8_lossy(&bytes).into_owned(),
                ))
            }
        }
    }

    pub fn wrap(seed: &[u8]) -> Result<Vec<u8>, ProviderError> {
        call(se_wrap, seed).map(|z| z.to_vec())
    }

    pub fn unwrap(payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        call(se_unwrap, payload)
    }
}

#[cfg(target_os = "macos")]
impl KeyProvider for EnclaveProvider {
    fn id(&self) -> &'static str {
        "enclave"
    }

    fn available(&self) -> bool {
        ffi::available()
    }

    fn wrap(&self, seed: &[u8]) -> Result<Vec<u8>, ProviderError> {
        ffi::wrap(seed)
    }

    fn unwrap(&self, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        ffi::unwrap(payload)
    }
}

#[cfg(not(target_os = "macos"))]
impl KeyProvider for EnclaveProvider {
    fn id(&self) -> &'static str {
        "enclave"
    }

    fn available(&self) -> bool {
        false
    }

    fn wrap(&self, _seed: &[u8]) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::Unavailable)
    }

    fn unwrap(&self, _payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        Err(ProviderError::Unavailable)
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// Uses the live Secure Enclave (no persistent state is created). Run with
    /// `cargo test -p provider-enclave -- --ignored`.
    #[test]
    #[ignore]
    fn roundtrip_live() {
        let p = EnclaveProvider::new();
        assert!(p.available());
        let seed = b"12345678901234567890";
        let payload = p.wrap(seed).unwrap();
        assert!(!payload.windows(seed.len()).any(|w| w == seed));
        assert_eq!(&p.unwrap(&payload).unwrap()[..], &seed[..]);

        let mut bad = payload.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(p.unwrap(&bad).is_err());
    }
}
