//! Onboarding: the private config directory, the profile copy and `config.json`.

use crate::config::Secret;
use anyhow::{bail, Context};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// OpenVPN locations checked by `sophos setup`, Homebrew first.
const OPENVPN_PATHS: &[&str] = &[
    "/opt/homebrew/sbin/openvpn",
    "/usr/local/sbin/openvpn",
    "/usr/sbin/openvpn",
    "/usr/bin/openvpn",
];

pub fn find_openvpn() -> Option<PathBuf> {
    OPENVPN_PATHS
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

/// Create `dir` as 0700, or check an existing one is a private directory owned by us.
pub fn ensure_private_dir(dir: &Path) -> anyhow::Result<()> {
    if !dir.exists() {
        if let Some(parent) = dir.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::DirBuilder::new()
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let meta = fs::symlink_metadata(dir)?;
    let euid = unsafe { libc::geteuid() };
    if !meta.is_dir() || meta.uid() != euid || meta.mode() & 0o777 != 0o700 {
        bail!(
            "{} must be a directory owned by you with mode 0700",
            dir.display()
        );
    }
    Ok(())
}

/// Write a 0600 file without following symlinks. Existing files are refused unless `replace`.
pub fn write_private(path: &Path, content: &[u8], replace: bool) -> anyhow::Result<()> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    if replace {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options.open(path).with_context(|| {
        if path.exists() && !replace {
            format!("{} exists; pass --force to replace it", path.display())
        } else {
            format!("writing {}", path.display())
        }
    })?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(content)?;
    file.sync_all()?;
    Ok(())
}

pub struct ConfigFile<'a> {
    pub profile: &'a Path,
    pub totp_envelope: Option<&'a Path>,
    pub gateway: Option<&'a str>,
    pub route_mode: &'a str,
    pub openvpn: &'a Path,
    pub username: Option<&'a str>,
    pub password: Option<&'a Secret>,
    pub operator_uid: Option<u32>,
    pub socket: Option<&'a Path>,
}

impl ConfigFile<'_> {
    pub fn render(&self) -> anyhow::Result<zeroize::Zeroizing<String>> {
        let mut map = serde_json::Map::new();
        map.insert("profile".into(), path_value(self.profile)?);
        if let Some(path) = self.totp_envelope {
            map.insert("totp_envelope".into(), path_value(path)?);
        }
        if let Some(gateway) = self.gateway {
            map.insert("gateway".into(), gateway.into());
        }
        map.insert("route_mode".into(), self.route_mode.into());
        map.insert("openvpn".into(), path_value(self.openvpn)?);
        if let Some(username) = self.username {
            map.insert("username".into(), username.into());
        }
        if let Some(password) = self.password {
            map.insert("password".into(), password.expose().into());
        }
        if let Some(uid) = self.operator_uid {
            map.insert("operator_uid".into(), uid.into());
        }
        if let Some(socket) = self.socket {
            map.insert("socket".into(), path_value(socket)?);
        }
        let mut text = serde_json::to_string_pretty(&serde_json::Value::Object(map))?;
        text.push('\n');
        Ok(zeroize::Zeroizing::new(text))
    }
}

fn path_value(path: &Path) -> anyhow::Result<serde_json::Value> {
    Ok(path
        .to_str()
        .context("paths in config.json must be UTF-8")?
        .into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendered_config_loads_and_omits_unset_fields() {
        let dir = std::env::temp_dir().join(format!("sophos-setup-test-{}", std::process::id()));
        ensure_private_dir(&dir).unwrap();
        let profile = dir.join("client.ovpn");
        let config = ConfigFile {
            profile: &profile,
            totp_envelope: None,
            gateway: Some("203.0.113.10"),
            route_mode: "github",
            openvpn: Path::new("/usr/sbin/openvpn"),
            username: None,
            password: None,
            operator_uid: None,
            socket: None,
        }
        .render()
        .unwrap();
        assert!(!config.contains("totp") && !config.contains("password"));
        let path = dir.join("config.json");
        write_private(&path, config.as_bytes(), false).unwrap();
        assert!(write_private(&path, b"{}", false).is_err());
        let (loaded, _) = crate::config::Config::load(&path).unwrap();
        assert!(loaded.manual_otp());
        assert_eq!(loaded.gateway.as_deref(), Some("203.0.113.10"));
        write_private(&path, b"{}", true).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"{}");
        fs::remove_dir_all(dir).unwrap();
    }
}
