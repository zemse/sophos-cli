//! `authn` — prints a 6-digit TOTP code from a seed wrapped by a machine-bound
//! backend. With no subcommand it prints the current code (the hot path).

use std::io::Read;
use std::path::{Path, PathBuf};

use authn_cli::{choose_provider, import, write_envelope, Error, DEFAULT_ALLOW};
use clap::{Parser, Subcommand};
use totp_core::{decode_setup_key, Algo, TotpParams};

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
        /// Backend to use: auto, secrets, enclave, tpm, aws, plain.
        #[arg(long, default_value = "auto")]
        provider: String,
        /// Setup key (base32). If omitted, read from stdin.
        #[arg(long)]
        key: Option<String>,
        /// Name for the `secrets` backend entry.
        #[arg(long, default_value = "totp/default")]
        name: String,
        /// `secrets` allow setting (never = no prompt at runtime).
        #[arg(long, default_value = DEFAULT_ALLOW)]
        allow: String,
        #[arg(long, default_value_t = 6)]
        digits: u8,
        #[arg(long, default_value_t = 30)]
        step: u16,
        /// Hash: sha1, sha256, sha512.
        #[arg(long, default_value = "sha1")]
        algo: String,
    },
    /// Import a QR image, otpauth URI or base32 key (`-` reads stdin).
    Import {
        /// PNG/JPEG with one TOTP or Google migration QR, a text file, or `-`.
        image: PathBuf,
        /// Backend to use: auto, secrets, enclave, tpm, aws, plain.
        #[arg(long, default_value = "auto")]
        provider: String,
        /// New `secrets` entry name (existing names are refused).
        #[arg(long, conflicts_with = "list")]
        name: Option<String>,
        /// List account names without storing or displaying seeds.
        #[arg(long, conflicts_with = "account")]
        list: bool,
        /// Account number from --list (required for multi-account exports).
        #[arg(long)]
        account: Option<usize>,
        /// `secrets` allow setting (never = no prompt at runtime).
        #[arg(long, default_value = DEFAULT_ALLOW)]
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

fn run() -> Result<(), Error> {
    let cli = Cli::parse();
    let store = cli.store.clone().unwrap_or_else(authn_cli::default_store);
    match cli.cmd {
        None | Some(Cmd::Code) => cmd_code(&store),
        Some(Cmd::Providers) => cmd_providers(),
        Some(Cmd::Import {
            image,
            provider,
            name,
            list,
            account,
            allow,
        }) => import::run(
            &image,
            &store,
            &import::Options {
                provider: &provider,
                name: name.as_deref(),
                allow: &allow,
                account,
                list,
            },
        ),
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

fn cmd_code(store: &Path) -> Result<(), Error> {
    println!("{}", authn_cli::current_code(store)?);
    Ok(())
}

fn cmd_providers() -> Result<(), Error> {
    for id in authn_cli::all_providers() {
        if let Some(p) = authn_cli::build_provider(id, "totp/default", DEFAULT_ALLOW) {
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
    store: &Path,
    provider: &str,
    key: &str,
    name: &str,
    allow: &str,
    params: TotpParams,
) -> Result<(), Error> {
    let seed = decode_setup_key(key)?;
    let chosen = choose_provider(provider, name, allow)?;
    write_envelope(store, chosen.as_ref(), &seed, params)?;
    eprintln!(
        "enrolled via `{}` backend -> {}",
        chosen.id(),
        store.display()
    );
    Ok(())
}

fn parse_algo(s: &str) -> Result<Algo, Error> {
    match s.to_ascii_lowercase().as_str() {
        "sha1" => Ok(Algo::Sha1),
        "sha256" => Ok(Algo::Sha256),
        "sha512" => Ok(Algo::Sha512),
        other => Err(format!("unknown algo `{other}` (sha1|sha256|sha512)").into()),
    }
}

fn read_stdin() -> Result<String, Error> {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;
    Ok(s.trim().to_owned())
}
