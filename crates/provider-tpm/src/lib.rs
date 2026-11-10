//! Seed backend built on a TPM 2.0 (including AWS NitroTPM), via subprocesses.
//!
//! The seed is sealed to this machine's TPM and the sealed blob is the envelope
//! payload. The blob only unseals on the TPM that created it, so a copied
//! binary + envelope on another host is inert (threat model: stolen binary).
//! Unsealing needs no user interaction.
//!
//! Preferred path: `systemd-creds encrypt --with-key=tpm2 --name=<NAME> - -`
//! (seed on stdin, sealed credential on stdout) and the matching
//! `systemd-creds decrypt --name=<NAME> - -`. systemd embeds the name in the
//! credential and decrypt fails if it differs, so the name is a fixed constant.
//! Fallback when systemd-creds is absent: `tpm2-tools` (`tpm2_createprimary`,
//! `tpm2_create`, `tpm2_load`, `tpm2_unseal`) under a deterministic primary key.
//!
//! AWS NitroTPM (enable at instance launch, needs UEFI boot mode and a
//! supported AMI) presents as a standard TPM 2.0 at `/dev/tpmrm0`, so it works
//! through this same path with no special handling.
//!
//! The crate shells out (pure std, no C-linked crate) so it builds on macOS,
//! where `available()` is simply false.
//!
//! LIVE VERIFICATION: the seal/unseal calls have only been exercised for
//! argument construction and payload framing. They must be verified on a Linux
//! host with a TPM (see the crate tests for the pure logic).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use totp_core::{KeyProvider, ProviderError};
use zeroize::Zeroizing;

/// Credential name embedded at encrypt time and required at decrypt time.
pub const CREDENTIAL_NAME: &str = "totp-seed";

const MAGIC: &[u8; 4] = b"TPM1";
const METHOD_SYSTEMD: u8 = 1;
const METHOD_TPM2_TOOLS: u8 = 2;

const TPM_DEVICES: [&str; 2] = ["/dev/tpmrm0", "/dev/tpm0"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Method {
    SystemdCreds,
    Tpm2Tools,
}

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

/// Frame a payload: magic, method byte, then the method-specific body.
fn encode(method: Method, body: &[u8]) -> Vec<u8> {
    let m = match method {
        Method::SystemdCreds => METHOD_SYSTEMD,
        Method::Tpm2Tools => METHOD_TPM2_TOOLS,
    };
    let mut out = Vec::with_capacity(5 + body.len());
    out.extend_from_slice(MAGIC);
    out.push(m);
    out.extend_from_slice(body);
    out
}

fn decode(payload: &[u8]) -> Result<(Method, &[u8]), ProviderError> {
    if payload.len() < 5 || &payload[..4] != MAGIC {
        return Err(ProviderError::Backend("not a tpm payload".into()));
    }
    let method = match payload[4] {
        METHOD_SYSTEMD => Method::SystemdCreds,
        METHOD_TPM2_TOOLS => Method::Tpm2Tools,
        m => return Err(ProviderError::Backend(format!("unknown tpm method {m}"))),
    };
    Ok((method, &payload[5..]))
}

/// tpm2-tools body: u32 BE length of the public blob, public, then private.
fn encode_tpm2_body(public: &[u8], private: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + public.len() + private.len());
    out.extend_from_slice(&(public.len() as u32).to_be_bytes());
    out.extend_from_slice(public);
    out.extend_from_slice(private);
    out
}

fn decode_tpm2_body(body: &[u8]) -> Result<(&[u8], &[u8]), ProviderError> {
    let bad = || ProviderError::Backend("malformed tpm2-tools payload".into());
    let len = body.get(..4).ok_or_else(bad)?;
    let len = u32::from_be_bytes(len.try_into().unwrap()) as usize;
    let rest = &body[4..];
    if len == 0 || len >= rest.len() {
        return Err(bad());
    }
    Ok(rest.split_at(len))
}

fn encrypt_args() -> Vec<String> {
    vec![
        "encrypt".into(),
        "--with-key=tpm2".into(),
        format!("--name={CREDENTIAL_NAME}"),
        "-".into(),
        "-".into(),
    ]
}

fn decrypt_args() -> Vec<String> {
    vec![
        "decrypt".into(),
        format!("--name={CREDENTIAL_NAME}"),
        "-".into(),
        "-".into(),
    ]
}

fn on_path(tool: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|d| d.join(tool).is_file())
}

fn tpm_device_present() -> bool {
    TPM_DEVICES.iter().any(|d| Path::new(d).exists())
}

/// Pick the tool to use, or None when no TPM / no tool.
fn detect() -> Option<Method> {
    if !cfg!(target_os = "linux") || !tpm_device_present() {
        return None;
    }
    if on_path("systemd-creds") {
        Some(Method::SystemdCreds)
    } else if on_path("tpm2_create") && on_path("tpm2_load") && on_path("tpm2_unseal") {
        Some(Method::Tpm2Tools)
    } else {
        None
    }
}

/// Run `cmd` with `input` on stdin, returning stdout. Stdout may hold the seed.
fn run(mut cmd: Command, input: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
    let name = cmd.get_program().to_string_lossy().into_owned();
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    // Write from a thread so a full stdout pipe cannot deadlock us.
    let data = Zeroizing::new(input.to_vec());
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let out = child.wait_with_output()?;
    let _ = writer.join();
    let stdout = Zeroizing::new(out.stdout);
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(ProviderError::Backend(format!(
            "{name} failed ({}): {}",
            out.status,
            err.trim()
        )));
    }
    Ok(stdout)
}

/// Private scratch dir (0700) removed on drop; holds only non-secret TPM blobs
/// and the primary context.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Result<Self, ProviderError> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("tpm-seed-{}-{nanos}", std::process::id()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir(&dir)?;
        Ok(Self(dir))
    }

    fn path(&self, f: &str) -> PathBuf {
        self.0.join(f)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tpm2(args: &[&str], input: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
    let mut c = Command::new(args[0]);
    c.args(&args[1..]);
    run(c, input)
}

/// Recreate the owner-hierarchy primary (deterministic from the TPM's seed and
/// the default template) so only the sealed blob needs persisting.
fn make_primary(s: &Scratch) -> Result<String, ProviderError> {
    let ctx = s.path("primary.ctx").to_string_lossy().into_owned();
    tpm2(&["tpm2_createprimary", "-C", "o", "-c", &ctx], &[])?;
    Ok(ctx)
}

fn path_str(p: PathBuf) -> String {
    p.to_string_lossy().into_owned()
}

fn wrap_tpm2_tools(seed: &[u8]) -> Result<Vec<u8>, ProviderError> {
    let s = Scratch::new()?;
    let primary = make_primary(&s)?;
    let (pubf, privf) = (path_str(s.path("seal.pub")), path_str(s.path("seal.priv")));
    // `-i -` reads the seed from stdin so it never touches disk.
    tpm2(
        &[
            "tpm2_create",
            "-C",
            &primary,
            "-i",
            "-",
            "-u",
            &pubf,
            "-r",
            &privf,
        ],
        seed,
    )?;
    Ok(encode_tpm2_body(
        &std::fs::read(&pubf)?,
        &std::fs::read(&privf)?,
    ))
}

fn unwrap_tpm2_tools(body: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
    let (public, private) = decode_tpm2_body(body)?;
    let s = Scratch::new()?;
    let primary = make_primary(&s)?;
    let (pubf, privf) = (path_str(s.path("seal.pub")), path_str(s.path("seal.priv")));
    std::fs::write(&pubf, public)?;
    std::fs::write(&privf, private)?;
    let keyctx = path_str(s.path("seal.ctx"));
    tpm2(
        &[
            "tpm2_load",
            "-C",
            &primary,
            "-u",
            &pubf,
            "-r",
            &privf,
            "-c",
            &keyctx,
        ],
        &[],
    )?;
    tpm2(&["tpm2_unseal", "-c", &keyctx], &[])
}

impl KeyProvider for TpmProvider {
    fn id(&self) -> &'static str {
        "tpm"
    }

    fn available(&self) -> bool {
        detect().is_some()
    }

    fn wrap(&self, seed: &[u8]) -> Result<Vec<u8>, ProviderError> {
        match detect().ok_or(ProviderError::Unavailable)? {
            Method::SystemdCreds => {
                let mut c = Command::new("systemd-creds");
                c.args(encrypt_args());
                let blob = run(c, seed)?;
                Ok(encode(Method::SystemdCreds, &blob))
            }
            Method::Tpm2Tools => Ok(encode(Method::Tpm2Tools, &wrap_tpm2_tools(seed)?)),
        }
    }

    fn unwrap(&self, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        let (method, body) = decode(payload)?;
        // The payload dictates the tool, but the TPM must still be reachable.
        if !cfg!(target_os = "linux") || !tpm_device_present() {
            return Err(ProviderError::Unavailable);
        }
        match method {
            Method::SystemdCreds => {
                let mut c = Command::new("systemd-creds");
                c.args(decrypt_args());
                run(c, body)
            }
            Method::Tpm2Tools => unwrap_tpm2_tools(body),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_is_tpm() {
        assert_eq!(TpmProvider::new().id(), "tpm");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unavailable_off_linux() {
        let p = TpmProvider::new();
        assert!(!p.available());
        assert!(matches!(p.wrap(b"x"), Err(ProviderError::Unavailable)));
    }

    #[test]
    fn unavailable_without_tpm_device_wrap_errors() {
        let p = TpmProvider::new();
        if !p.available() {
            assert!(matches!(p.wrap(b"x"), Err(ProviderError::Unavailable)));
        }
    }

    #[test]
    fn systemd_args() {
        assert_eq!(
            encrypt_args(),
            ["encrypt", "--with-key=tpm2", "--name=totp-seed", "-", "-"]
        );
        assert_eq!(decrypt_args(), ["decrypt", "--name=totp-seed", "-", "-"]);
    }

    #[test]
    fn payload_roundtrip() {
        let p = encode(Method::SystemdCreds, b"blob");
        let (m, b) = decode(&p).unwrap();
        assert_eq!((m, b), (Method::SystemdCreds, &b"blob"[..]));
    }

    #[test]
    fn payload_rejects_garbage() {
        assert!(decode(b"").is_err());
        assert!(decode(b"XXXX\x01abc").is_err());
        assert!(decode(b"TPM1\x09abc").is_err());
    }

    #[test]
    fn tpm2_body_roundtrip() {
        let b = encode_tpm2_body(b"public", b"private");
        let (pu, pr) = decode_tpm2_body(&b).unwrap();
        assert_eq!((pu, pr), (&b"public"[..], &b"private"[..]));
        assert!(decode_tpm2_body(&[0, 0, 0, 9, 1]).is_err());
        assert!(decode_tpm2_body(&[0, 0]).is_err());
    }

    #[test]
    fn unwrap_bad_payload_errors() {
        assert!(TpmProvider::new().unwrap(b"nope").is_err());
    }
}
