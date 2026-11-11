//! `authn` — prints a 6-digit TOTP code from a seed wrapped by a machine-bound
//! backend. With no subcommand it prints the current code (the hot path).

use std::error::Error;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

mod import;

use clap::{Parser, Subcommand};
use totp_core::{decode_setup_key, generate, Algo, Envelope, KeyProvider, TotpParams};

use provider_aws::AwsProvider;
#[cfg(target_os = "macos")]
use provider_enclave::EnclaveProvider;
use provider_secrets::SecretsProvider;
use provider_tpm::TpmProvider;

#[derive(Parser)]
#[command(name = "authn", about = "Print a TOTP code from a machine-bound seed.")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,

    /// Path to the enrolled seed envelope.
    #[arg(long, global = true)]
    store: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Enroll a base32 setup key into a machine-bound backend.
    Enroll {
        /// Backend to use: auto, secrets, enclave, tpm, aws.
        #[arg(long, default_value = "auto")]
        provider: String,
        /// Setup key (base32). If omitted, read from stdin.
        #[arg(long)]
        key: Option<String>,
        /// Name for the `secrets` backend entry.
        #[arg(long, default_value = "totp/default")]
        name: String,
        /// `secrets` allow setting (never = no prompt at runtime).
        #[arg(long, default_value = provider_secrets::DEFAULT_ALLOW)]
        allow: String,
        #[arg(long, default_value_t = 6)]
        digits: u8,
        #[arg(long, default_value_t = 30)]
        step: u16,
        /// Hash: sha1, sha256, sha512.
        #[arg(long, default_value = "sha1")]
        algo: String,
    },
    /// Import a single TOTP QR from a PNG or JPEG into the secrets backend.
    Import {
        /// Image containing one otpauth TOTP QR code.
        image: PathBuf,
        /// New secret entry name (existing names are refused).
        #[arg(long)]
        name: String,
        /// `secrets` allow setting (never = no prompt at runtime).
        #[arg(long, default_value = provider_secrets::DEFAULT_ALLOW)]
        allow: String,
    },
    /// Print the current code (default when no subcommand is given).
    Code,
    /// List compiled backends and whether each is available on this host.
    Providers,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let store = cli.store.clone().unwrap_or_else(default_store);
    match cli.cmd {
        None | Some(Cmd::Code) => cmd_code(&store),
        Some(Cmd::Providers) => cmd_providers(),
        Some(Cmd::Import { image, name, allow }) => import::run(&image, &store, &name, &allow),
        Some(Cmd::Enroll {
            provider,
            key,
            name,
            allow,
            digits,
            step,
            algo,
        }) => {
            let params = TotpParams {
                digits,
                step,
                algo: parse_algo(&algo)?,
            };
            let key = match key {
                Some(k) => k,
                None => read_stdin()?,
            };
            cmd_enroll(&store, &provider, &key, &name, &allow, params)
        }
    }
}

fn cmd_code(store: &PathBuf) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(store).map_err(|e| {
        format!(
            "cannot read {} ({e}); run `authn enroll` first",
            store.display()
        )
    })?;
    let env = Envelope::decode(&bytes)?;
    let provider = build_provider(&env.provider_id, "", provider_secrets::DEFAULT_ALLOW)
        .ok_or_else(|| format!("envelope names unknown backend `{}`", env.provider_id))?;
    let seed = provider.unwrap(&env.payload)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    println!("{}", generate(&seed, now, &env.params));
    Ok(())
}

fn cmd_providers() -> Result<(), Box<dyn Error>> {
    for id in auto_order() {
        if let Some(p) = build_provider(id, "totp/default", provider_secrets::DEFAULT_ALLOW) {
            let mark = if p.available() {
                "available"
            } else {
                "unavailable"
            };
            println!("{id:10} {mark}");
        }
    }
    Ok(())
}

fn cmd_enroll(
    store: &PathBuf,
    provider: &str,
    key: &str,
    name: &str,
    allow: &str,
    params: TotpParams,
) -> Result<(), Box<dyn Error>> {
    let seed = decode_setup_key(key)?;

    let chosen = if provider == "auto" {
        auto_order()
            .into_iter()
            .filter_map(|id| build_provider(id, name, allow))
            .find(|p| p.available())
            .ok_or("no backend is available on this host; see `authn providers`")?
    } else {
        let p = build_provider(provider, name, allow)
            .ok_or_else(|| format!("unknown backend `{provider}`"))?;
        if !p.available() {
            return Err(format!("backend `{provider}` is not available on this host").into());
        }
        p
    };

    let payload = chosen.wrap(&seed)?;
    let env = Envelope::new(chosen.id(), params, payload);
    if let Some(parent) = store.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(store, env.encode()?)?;
    harden_perms(store);
    eprintln!(
        "enrolled via `{}` backend -> {}",
        chosen.id(),
        store.display()
    );
    Ok(())
}

/// Construct a backend by id. `name`/`allow` only matter for enrollment with the
/// `secrets` backend; the code path recovers everything it needs from the payload.
fn build_provider(id: &str, name: &str, allow: &str) -> Option<Box<dyn KeyProvider>> {
    match id {
        "secrets" => Some(Box::new(SecretsProvider::new(name).with_allow(allow))),
        "tpm" => Some(Box::new(TpmProvider::new())),
        "aws" => Some(Box::new(AwsProvider::new())),
        #[cfg(target_os = "macos")]
        "enclave" => Some(Box::new(EnclaveProvider::new())),
        _ => None,
    }
}

/// Backend preference order for `auto`, per platform.
fn auto_order() -> Vec<&'static str> {
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

fn parse_algo(s: &str) -> Result<Algo, Box<dyn Error>> {
    match s.to_ascii_lowercase().as_str() {
        "sha1" => Ok(Algo::Sha1),
        "sha256" => Ok(Algo::Sha256),
        "sha512" => Ok(Algo::Sha512),
        other => Err(format!("unknown algo `{other}` (sha1|sha256|sha512)").into()),
    }
}

fn default_store() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("sophos-pin-oracle")
        .join("seed.envelope")
}

fn read_stdin() -> Result<String, Box<dyn Error>> {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;
    Ok(s.trim().to_owned())
}

#[cfg(unix)]
fn harden_perms(path: &PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn harden_perms(_path: &PathBuf) {}
