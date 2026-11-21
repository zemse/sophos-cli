//! Private configuration and secret ownership.

use anyhow::{bail, Context};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn duplicate(&self) -> Self {
        Self::new(self.expose().to_owned())
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.expose())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub profile: PathBuf,
    /// Plaintext Base32 seed. Prefer `totp_envelope`.
    pub totp_seed: Option<Secret>,
    /// Envelope written by `sophos totp import`, unwrapped by its backend on each login.
    pub totp_envelope: Option<PathBuf>,
    pub username: Option<String>,
    pub password: Option<Secret>,
    pub gateway: Option<String>,
    #[serde(default = "default_openvpn")]
    pub openvpn: PathBuf,
    #[serde(default = "default_route_mode")]
    pub route_mode: String,
    pub socket: Option<PathBuf>,
    pub operator_uid: Option<u32>,
}

fn default_openvpn() -> PathBuf {
    if cfg!(target_os = "macos") {
        "/opt/homebrew/sbin/openvpn".into()
    } else {
        "/usr/sbin/openvpn".into()
    }
}
fn default_route_mode() -> String {
    "github".into()
}

pub fn default_config() -> anyhow::Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".config"),
    };
    Ok(base.join("sophos-cli/config.json"))
}

/// Root-owned config used by the boot service templates.
pub fn system_config() -> PathBuf {
    if cfg!(target_os = "macos") {
        "/Library/Application Support/sophos-cli/config.json".into()
    } else {
        "/etc/sophos-cli/config.json".into()
    }
}

/// Control socket of the boot service; written into its config by `sophos setup --system`.
pub const SYSTEM_SOCKET: &str = "/var/run/sophos-cli/control.sock";

pub fn default_socket(config: &Path) -> anyhow::Result<PathBuf> {
    Ok(config
        .parent()
        .context("config path needs a parent")?
        .join("run/control.sock"))
}

pub fn read_private(path: &Path, owner: u32, limit: u64) -> anyhow::Result<Zeroizing<String>> {
    let bytes = read_private_bytes(path, owner, limit)?;
    Ok(Zeroizing::new(
        std::str::from_utf8(&bytes)
            .context("private file is not UTF-8")?
            .to_owned(),
    ))
}

pub fn read_private_bytes(
    path: &Path,
    owner: u32,
    limit: u64,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening private file {}", path.display()))?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.permissions().mode() & 0o777 != 0o600
        || (meta.uid() != owner && meta.uid() != 0)
    {
        bail!("private file must be regular, mode 0600 and owned by its operator or root");
    }
    let mut content = Zeroizing::new(Vec::new());
    file.take(limit + 1).read_to_end(&mut content)?;
    if content.len() as u64 > limit {
        bail!("private file is too large");
    }
    Ok(content)
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<(Self, u32)> {
        let meta = fs::symlink_metadata(path)?;
        let euid = unsafe { libc::geteuid() };
        if euid != 0 && meta.uid() != euid {
            bail!("config belongs to another user");
        }
        let parent = path.parent().context("config needs a parent directory")?;
        let parent_meta = fs::symlink_metadata(parent)?;
        if !parent_meta.is_dir()
            || parent_meta.uid() != meta.uid()
            || parent_meta.permissions().mode() & 0o777 != 0o700
        {
            bail!("config directory must be 0700 and owned by the config owner");
        }
        let sudo_uid = std::env::var("SUDO_UID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok());
        if euid == 0 && meta.uid() != 0 && sudo_uid != Some(meta.uid()) {
            bail!("a root service needs root-owned config; user config is allowed only through its owner's sudo session");
        }
        let content = read_private(path, meta.uid(), 65536)?;
        let config: Self = serde_json::from_str(&content)
            .map_err(|_| anyhow::anyhow!("invalid config JSON or unknown field"))?;
        let operator = config.operator_uid.unwrap_or(meta.uid());
        if euid != 0 && operator != euid {
            bail!("only root can select another operator UID");
        }
        if !config.profile.is_absolute() || !config.openvpn.is_absolute() {
            bail!("profile and openvpn paths must be absolute");
        }
        if config.socket.as_ref().is_some_and(|p| !p.is_absolute()) {
            bail!("socket path must be absolute");
        }
        if config
            .gateway
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.chars().any(char::is_whitespace))
        {
            bail!("gateway must be a single hostname or IP");
        }
        if crate::ovpn::RouteMode::parse(&config.route_mode).is_none() {
            bail!("route_mode must be github, full or pushed");
        }
        match (&config.totp_seed, &config.totp_envelope) {
            (Some(_), Some(_)) => bail!("set totp_seed or totp_envelope, not both"),
            (Some(seed), None) => {
                crate::totp::Totp::new(seed.expose())?;
            }
            (None, Some(path)) => {
                if !path.is_absolute() {
                    bail!("totp_envelope path must be absolute");
                }
                load_envelope(path, meta.uid())?;
            }
            (None, None) => {}
        }
        Ok((config, operator))
    }

    /// No automatic TOTP source: every login waits for a code from `sophos connect` or `sophos otp`.
    pub fn manual_otp(&self) -> bool {
        self.totp_seed.is_none() && self.totp_envelope.is_none()
    }
}

/// Read and decode an envelope without unwrapping its seed.
pub fn load_envelope(path: &Path, owner: u32) -> anyhow::Result<totp_core::Envelope> {
    let bytes = read_private_bytes(path, owner, 65536)?;
    let envelope = totp_core::Envelope::decode(&bytes).context("invalid TOTP envelope")?;
    if authn_cli::build_provider(&envelope.provider_id, "", authn_cli::DEFAULT_ALLOW).is_none() {
        bail!(
            "TOTP envelope names backend `{}`, which this build lacks",
            envelope.provider_id
        );
    }
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_errors_do_not_echo_values() {
        let error = serde_json::from_str::<Config>(
            "{\"totp_seed\":\"PUBLIC_TEST_VALUE\",\"unexpected\":1}",
        )
        .err()
        .unwrap();
        assert!(!error.to_string().contains("PUBLIC_TEST_VALUE"));
    }

    #[test]
    fn config_requires_private_directory() {
        use std::io::Write;
        use std::os::unix::fs::DirBuilderExt;
        let dir =
            std::env::temp_dir().join(format!("sophos-config-dir-test-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let path = dir.join("config.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(br#"{"profile":"/public-test/profile.ovpn","totp_seed":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}"#).unwrap();
        assert!(Config::load(&path).is_ok());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Config::load(&path).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn private_files_reject_public_permissions_and_symlinks() {
        let dir = std::env::temp_dir().join(format!("sophos-config-test-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("config");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        use std::io::Write;
        file.write_all(b"public test content").unwrap();
        let uid = unsafe { libc::geteuid() };
        assert!(read_private(&path, uid, 100).is_ok());
        assert!(read_private(&path, uid, 3).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private(&path, uid, 100).is_err());
        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_private(&link, uid, 100).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
