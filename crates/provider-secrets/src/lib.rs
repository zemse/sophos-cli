//! Seed backend built on the `secrets` CLI (zemse/macos-secrets), a
//! hardware-backed store fronted by the `secretsd` broker.
//!
//! The seed itself lives in `secretsd`, bound to this machine; the envelope
//! payload is only the secret's *name*. A copied binary + envelope on another
//! host has no store to read, so it is inert (threat model: stolen binary).
//!
//! Enrollment stores the seed with `--allow never` by default, so the runtime
//! `get` never prompts and the code generates with no interaction. Pass a
//! different allow spec (e.g. `ask`, `5m`) to require Touch ID per use instead.

use std::io::Write;
use std::process::{Command, Stdio};

use totp_core::{KeyProvider, ProviderError};
use zeroize::Zeroizing;

/// Default allow setting at enrollment: never prompt (zero-interaction runtime).
pub const DEFAULT_ALLOW: &str = "never";

pub struct SecretsProvider {
    /// Secret name under which the seed is stored (also the envelope payload).
    name: String,
    /// `--allow` spec passed to `secrets set` at enrollment.
    allow: String,
}

impl SecretsProvider {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            allow: DEFAULT_ALLOW.to_owned(),
        }
    }

    pub fn with_allow(mut self, allow: impl Into<String>) -> Self {
        self.allow = allow.into();
        self
    }

    /// Resolve the `secrets` binary: PATH first, then the standard install path.
    fn bin() -> String {
        if Command::new("secrets")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return "secrets".to_owned();
        }
        if let Some(home) = std::env::var_os("HOME") {
            let p = std::path::Path::new(&home).join(".local/bin/secrets");
            if p.exists() {
                return p.to_string_lossy().into_owned();
            }
        }
        "secrets".to_owned()
    }
}

impl KeyProvider for SecretsProvider {
    fn id(&self) -> &'static str {
        "secrets"
    }

    fn available(&self) -> bool {
        Command::new(Self::bin())
            .arg("status")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn wrap(&self, seed: &[u8]) -> Result<Vec<u8>, ProviderError> {
        // Store the raw seed as hex text (the CLI value channel is text).
        let hex = Zeroizing::new(to_hex(seed));
        let mut child = Command::new(Self::bin())
            .args(["set", &self.name, "--allow", &self.allow])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .take()
            .ok_or_else(|| ProviderError::Backend("could not open stdin to secrets".into()))?
            .write_all(hex.as_bytes())?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            return Err(ProviderError::Backend(format!(
                "secrets set failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(self.name.clone().into_bytes())
    }

    fn unwrap(&self, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        let name = std::str::from_utf8(payload)
            .map_err(|_| ProviderError::Backend("secret name is not utf-8".into()))?;
        let out = Command::new(Self::bin()).args(["get", name]).output()?;
        if !out.status.success() {
            return Err(ProviderError::Backend(format!(
                "secrets get failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let hex = Zeroizing::new(String::from_utf8_lossy(&out.stdout).trim().to_owned());
        from_hex(&hex).map(Zeroizing::new)
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn from_hex(s: &str) -> Result<Vec<u8>, ProviderError> {
    if s.len() % 2 != 0 {
        return Err(ProviderError::Backend(
            "stored seed has odd hex length".into(),
        ));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| ProviderError::Backend("stored seed is not hex".into()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let data = [0x00u8, 0x0f, 0xa5, 0xff, 0x10];
        assert_eq!(to_hex(&data), "000fa5ff10");
        assert_eq!(from_hex("000fa5ff10").unwrap(), data);
    }

    #[test]
    fn from_hex_rejects_garbage() {
        assert!(from_hex("xyz").is_err());
        assert!(from_hex("abc").is_err()); // odd length
    }
}
