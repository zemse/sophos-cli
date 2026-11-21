//! Library half of `authn`: backend selection, enrollment and import. The
//! `sophos` VPN daemon links this to read codes from the same envelopes.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod import;

use totp_core::{generate, Envelope, KeyProvider, ProviderError, TotpParams};
use zeroize::Zeroizing;

use provider_aws::AwsProvider;
#[cfg(target_os = "macos")]
use provider_enclave::EnclaveProvider;
use provider_secrets::SecretsProvider;
use provider_tpm::TpmProvider;

pub use provider_secrets::DEFAULT_ALLOW;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Stores the seed unencrypted in the envelope. Only file permissions protect it,
/// so it is never picked by `auto`; use it where no hardware or cloud backend exists.
pub struct PlainProvider;

impl KeyProvider for PlainProvider {
    fn id(&self) -> &'static str {
        "plain"
    }

    fn available(&self) -> bool {
        true
    }

    fn wrap(&self, seed: &[u8]) -> Result<Vec<u8>, ProviderError> {
        Ok(seed.to_vec())
    }

    fn unwrap(&self, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        Ok(Zeroizing::new(payload.to_vec()))
    }
}

/// Construct a backend by id. `name`/`allow` only matter for enrollment with the
/// `secrets` backend; the code path recovers everything it needs from the payload.
pub fn build_provider(id: &str, name: &str, allow: &str) -> Option<Box<dyn KeyProvider>> {
    match id {
        "secrets" => Some(Box::new(SecretsProvider::new(name).with_allow(allow))),
        "tpm" => Some(Box::new(TpmProvider::new())),
        "aws" => Some(Box::new(AwsProvider::new())),
        "plain" => Some(Box::new(PlainProvider)),
        #[cfg(target_os = "macos")]
        "enclave" => Some(Box::new(EnclaveProvider::new())),
        _ => None,
    }
}

/// Backend preference order for `auto`, per platform.
pub fn auto_order() -> Vec<&'static str> {
    #[cfg(target_os = "macos")]
    {
        vec!["secrets", "enclave", "aws"]
    }
    #[cfg(target_os = "linux")]
    {
        vec!["tpm", "aws", "secrets"]
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        vec!["aws", "secrets"]
    }
}

/// Every backend compiled into this build, `auto` candidates first.
pub fn all_providers() -> Vec<&'static str> {
    let mut ids = auto_order();
    #[cfg(target_os = "macos")]
    if !ids.contains(&"enclave") {
        ids.push("enclave");
    }
    for id in ["tpm", "aws", "secrets", "plain"] {
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    ids
}

/// Resolve `auto` or a backend name to an available backend.
pub fn choose_provider(
    provider: &str,
    name: &str,
    allow: &str,
) -> Result<Box<dyn KeyProvider>, Error> {
    if provider == "auto" {
        return auto_order()
            .into_iter()
            .filter_map(|id| build_provider(id, name, allow))
            .find(|p| p.available())
            .ok_or_else(|| "no backend is available on this host; see `providers`".into());
    }
    let p = build_provider(provider, name, allow)
        .ok_or_else(|| format!("unknown backend `{provider}`"))?;
    if !p.available() {
        return Err(format!("backend `{provider}` is not available on this host").into());
    }
    Ok(p)
}

pub fn read_envelope(store: &Path) -> Result<Envelope, Error> {
    let bytes = fs::read(store).map_err(|e| {
        format!(
            "cannot read {} ({e}); enroll or import a key first",
            store.display()
        )
    })?;
    Ok(Envelope::decode(&bytes)?)
}

/// Recover the raw seed through the backend the envelope names.
pub fn unwrap_seed(env: &Envelope) -> Result<Zeroizing<Vec<u8>>, Error> {
    let provider = build_provider(&env.provider_id, "", DEFAULT_ALLOW)
        .ok_or_else(|| format!("envelope names unknown backend `{}`", env.provider_id))?;
    Ok(provider.unwrap(&env.payload)?)
}

pub fn current_code(store: &Path) -> Result<String, Error> {
    let env = read_envelope(store)?;
    let seed = unwrap_seed(&env)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(generate(&seed, now, &env.params))
}

/// Wrap `seed` and write a new envelope. Existing paths are refused, and a
/// failed wrap removes the half-created file.
pub fn write_envelope(
    store: &Path,
    provider: &dyn KeyProvider,
    seed: &[u8],
    params: TotpParams,
) -> Result<(), Error> {
    if let Some(parent) = store.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(store).map_err(|_| {
        "cannot create envelope; choose a new --store path and check directory permissions"
    })?;
    let result = (|| -> Result<(), Error> {
        let payload = provider
            .wrap(seed)
            .map_err(|_| format!("{} enrollment failed", provider.id()))?;
        let envelope = Envelope::new(provider.id(), params, payload);
        file.write_all(&envelope.encode()?)?;
        file.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        drop(file);
        let _ = fs::remove_file(store);
    }
    result
}

pub fn default_store() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("sophos-pin-oracle")
        .join("seed.envelope")
}
