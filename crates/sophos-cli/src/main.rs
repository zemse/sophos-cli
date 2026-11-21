//! Local control for the Sophos SSL VPN supervisor, and onboarding.

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use sophos_cli::config::{self, Config, Secret};
use sophos_cli::ipc::{self, valid_otp, Request};
use sophos_cli::ovpn::{validate_profile, RouteMode};
use sophos_cli::setup::{self, ensure_private_dir, write_private, ConfigFile};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(version, about = "Sophos SSL VPN daemon control")]
struct Args {
    /// Configuration path; also determines the default control socket and onboarding files.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Override the control socket path.
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    /// Use the boot service paths: root-owned system config and /var/run/sophos-cli socket.
    #[arg(long, global = true)]
    system: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write config.json from the profile and TOTP envelope in the config directory.
    Setup(SetupArgs),
    /// Download the OpenVPN profile from the Sophos VPN portal.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Import, test and inspect the machine-bound TOTP seed.
    Totp {
        #[command(subcommand)]
        command: TotpCommand,
    },
    /// Run the privileged foreground supervisor (use systemd or launchd for background operation).
    Daemon,
    /// Connect, prompting for credentials (and a one-time code) absent from the daemon's config.
    Connect,
    /// Give the daemon a one-time code for its next login.
    Otp {
        /// Current authenticator code; prompted for when omitted.
        code: Option<String>,
    },
    /// Print safe connection status as JSON.
    Status,
    /// Restart the VPN using retained credentials.
    Reconnect,
    /// Disconnect, disable reconnection and forget interactive credentials.
    Disconnect,
    /// Stop the supervisor and VPN.
    Stop,
}

#[derive(clap::Args)]
struct SetupArgs {
    /// Existing .ovpn to copy into the config directory (default: client.ovpn already there).
    #[arg(long)]
    profile: Option<PathBuf>,
    /// Firewall IP or hostname; replaces the `remote` host from the profile.
    #[arg(long)]
    gateway: Option<String>,
    /// github (GitHub ranges only), full (all traffic) or pushed (server routes).
    #[arg(long, default_value = "github")]
    route_mode: String,
    /// OpenVPN executable (default: first Homebrew or system install found).
    #[arg(long)]
    openvpn: Option<PathBuf>,
    /// Ignore any TOTP envelope: every login waits for `sophos connect` or `sophos otp`.
    #[arg(long)]
    manual_otp: bool,
    /// Prompt for and store the VPN username and password so the daemon connects on its own.
    #[arg(long)]
    save_login: bool,
    /// UID allowed to control a root daemon (default: the sudo caller).
    #[arg(long)]
    operator_uid: Option<u32>,
    /// Replace an existing config.json (and profile when --profile is given).
    #[arg(long)]
    force: bool,
}

#[derive(Subcommand)]
enum ProfileCommand {
    /// Log in to the Sophos VPN portal and save its OpenVPN profile.
    Fetch {
        /// Firewall IP or hostname serving the VPN portal.
        #[arg(long)]
        gateway: String,
        /// Hostname on the portal's TLS certificate; without it the certificate is not verified.
        #[arg(long)]
        portal_host: Option<String>,
        /// VPN portal HTTPS port.
        #[arg(long, default_value_t = 443)]
        port: u16,
        /// Output path (default: client.ovpn in the config directory).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Replace an existing profile.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum TotpCommand {
    /// Import a QR image, otpauth URI or base32 setup key (`-` reads stdin).
    Import {
        /// PNG/JPEG QR (Google Authenticator export or provisioning QR), text file, or `-`.
        source: PathBuf,
        /// Backend: auto, enclave, secrets, tpm, aws or plain.
        #[arg(long, default_value = DEFAULT_PROVIDER)]
        provider: String,
        /// Entry name for the `secrets` backend.
        #[arg(long, default_value = "sophos-cli/totp")]
        name: String,
        /// List accounts in a migration QR without storing anything.
        #[arg(long, conflicts_with = "account")]
        list: bool,
        /// Account number from --list (required for multi-account exports).
        #[arg(long)]
        account: Option<usize>,
        /// `secrets` allow setting (never = no prompt at runtime).
        #[arg(long, default_value = authn_cli::DEFAULT_ALLOW)]
        allow: String,
    },
    /// Print the current code, to compare with your authenticator app.
    Code,
    /// List TOTP backends and whether each is available on this host.
    Providers,
}

/// The daemon runs as root, where the per-user `secrets` store that `auto` prefers on macOS is not reachable.
#[cfg(target_os = "macos")]
const DEFAULT_PROVIDER: &str = "enclave";
#[cfg(not(target_os = "macos"))]
const DEFAULT_PROVIDER: &str = "auto";

struct RawMode;
impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

fn require_terminal() -> anyhow::Result<()> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        bail!("missing credentials require an interactive terminal");
    }
    Ok(())
}

fn prompt_line(label: &str) -> anyhow::Result<String> {
    require_terminal()?;
    eprint!("{label}: ");
    io::stderr().flush()?;
    let mut value = String::new();
    io::stdin().lock().read_line(&mut value)?;
    Ok(value.trim_end_matches(['\r', '\n']).to_owned())
}

fn prompt_username() -> anyhow::Result<String> {
    prompt_line("VPN username")
}

fn prompt_otp(optional: bool) -> anyhow::Result<Option<Secret>> {
    let label = if optional {
        "One-time code (Enter if MFA is off)"
    } else {
        "One-time code from your authenticator"
    };
    let code = Zeroizing::new(prompt_line(label)?.trim().to_owned());
    if code.is_empty() && optional {
        return Ok(None);
    }
    if !valid_otp(&code) {
        bail!("one-time code must be 6 to 10 digits");
    }
    Ok(Some(Secret::new(code.to_string())))
}

fn prompt_password() -> anyhow::Result<Secret> {
    require_terminal()?;
    eprint!("VPN password (without OTP): ");
    io::stderr().flush()?;
    crossterm::terminal::enable_raw_mode()?;
    let guard = RawMode;
    let mut value = Zeroizing::new(String::new());
    loop {
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Release {
                continue;
            }
            match key.code {
                KeyCode::Enter => break,
                KeyCode::Char('c' | 'd') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    drop(guard);
                    eprintln!();
                    bail!("credential entry cancelled");
                }
                KeyCode::Backspace => {
                    value.pop();
                }
                KeyCode::Char(c)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    if value.len() + c.len_utf8() > 4096 {
                        bail!("password exceeds input limit");
                    }
                    value.push(c);
                }
                _ => {}
            }
        }
    }
    drop(guard);
    eprintln!();
    if value.is_empty() {
        bail!("password cannot be empty");
    }
    Ok(Secret::new(std::mem::take(&mut *value)))
}

fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

fn authn<T>(result: Result<T, authn_cli::Error>) -> anyhow::Result<T> {
    result.map_err(|e| anyhow::anyhow!(e))
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config_path = match (&args.config, args.system) {
        (Some(path), _) => path.clone(),
        (None, true) => config::system_config(),
        (None, false) => config::default_config()?,
    };
    let dir = config_path
        .parent()
        .context("config path needs a parent directory")?
        .to_owned();
    let envelope = dir.join("totp.envelope");
    match args.command {
        Command::Setup(setup_args) => setup(&setup_args, &config_path, &envelope, args.system),
        Command::Totp { command } => totp(command, &dir, &envelope),
        Command::Profile {
            command:
                ProfileCommand::Fetch {
                    gateway,
                    portal_host,
                    port,
                    out,
                    force,
                },
        } => {
            ensure_private_dir(&dir)?;
            let out = out.unwrap_or_else(|| dir.join("client.ovpn"));
            if out.exists() && !force {
                bail!("{} exists; pass --force to replace it", out.display());
            }
            let username = prompt_username()?;
            let password = prompt_password()?;
            let otp = if envelope.exists() {
                eprintln!("using a code from {}", envelope.display());
                Some(Secret::new(authn(authn_cli::current_code(&envelope))?))
            } else {
                prompt_otp(true)?
            };
            let login = Zeroizing::new(format!(
                "{}{}",
                password.expose(),
                otp.as_ref().map(Secret::expose).unwrap_or_default()
            ));
            let fetched = runtime()?.block_on(
                sophos_cli::portal::Portal {
                    gateway: &gateway,
                    host: portal_host.as_deref(),
                    port,
                }
                .fetch_config(&username, &login),
            )?;
            if !fetched.tls_verified {
                eprintln!(
                    "warning: portal certificate not verified; pass --portal-host to verify it"
                );
            }
            if fetched.otp_enrolment {
                eprintln!("warning: the portal asked to enrol an OTP token; finish enrolment in a browser first");
            }
            if let Err(error) = validate_profile(&fetched.ovpn) {
                eprintln!("warning: the daemon will refuse this profile: {error}");
            }
            write_private(&out, fetched.ovpn.as_bytes(), force)?;
            eprintln!("saved profile -> {}", out.display());
            if otp.is_some() {
                eprintln!("note: the portal login used the current code; the VPN login needs the next one");
            }
            Ok(())
        }
        Command::Daemon => {
            let (config, operator) = Config::load(&config_path)?;
            let socket = args
                .socket
                .or_else(|| config.socket.clone())
                .unwrap_or(config::default_socket(&config_path)?);
            runtime()?.block_on(sophos_cli::daemon::run(config, operator, socket))
        }
        command => {
            let socket = match (args.socket, args.system) {
                (Some(socket), _) => socket,
                (None, true) => config::SYSTEM_SOCKET.into(),
                (None, false) => config::default_socket(&config_path)?,
            };
            runtime()?.block_on(control(command, &socket))
        }
    }
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

async fn control(command: Command, socket: &Path) -> anyhow::Result<()> {
    let request = match command {
        Command::Connect => {
            let requirements = ipc::call(socket, Request::Requirements {}).await?;
            if !requirements.ok {
                bail!("daemon rejected requirements request");
            }
            let username = requirements
                .need_username
                .then(prompt_username)
                .transpose()?;
            let password = requirements
                .need_password
                .then(prompt_password)
                .transpose()?;
            // Asked last so the code is as fresh as possible when the daemon uses it.
            let otp = if requirements.need_otp {
                prompt_otp(false)?
            } else {
                None
            };
            Request::Connect {
                username,
                password,
                otp,
            }
        }
        Command::Otp { code } => {
            let otp = match code {
                Some(code) if valid_otp(&code) => Secret::new(code),
                Some(_) => bail!("one-time code must be 6 to 10 digits"),
                None => prompt_otp(false)?.context("one-time code required")?,
            };
            Request::Otp { otp }
        }
        Command::Status => Request::Status {},
        Command::Reconnect => Request::Reconnect {},
        Command::Disconnect => Request::Disconnect {},
        Command::Stop => Request::Stop {},
        Command::Daemon | Command::Setup(_) | Command::Profile { .. } | Command::Totp { .. } => {
            unreachable!()
        }
    };
    let reply = ipc::call(socket, request).await?;
    if !reply.ok {
        bail!(
            "{}",
            reply.error.as_deref().unwrap_or("control request rejected")
        );
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&reply.status).context("encoding status")?
    );
    Ok(())
}

fn totp(command: TotpCommand, dir: &Path, envelope: &Path) -> anyhow::Result<()> {
    match command {
        TotpCommand::Import {
            source,
            provider,
            name,
            list,
            account,
            allow,
        } => {
            if !list {
                ensure_private_dir(dir)?;
            }
            authn(authn_cli::import::run(
                &source,
                envelope,
                &authn_cli::import::Options {
                    provider: &provider,
                    name: Some(&name),
                    allow: &allow,
                    account,
                    list,
                },
            ))?;
            if !list {
                eprintln!("check it: `sophos totp code` should match your authenticator app");
            }
            Ok(())
        }
        TotpCommand::Code => {
            println!("{}", authn(authn_cli::current_code(envelope))?);
            Ok(())
        }
        TotpCommand::Providers => {
            for id in authn_cli::all_providers() {
                if let Some(p) =
                    authn_cli::build_provider(id, "sophos-cli/totp", authn_cli::DEFAULT_ALLOW)
                {
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
    }
}

fn setup(
    args: &SetupArgs,
    config_path: &Path,
    envelope: &Path,
    system: bool,
) -> anyhow::Result<()> {
    if system && euid() != 0 {
        bail!("--system writes root-owned service config; run it with sudo");
    }
    if RouteMode::parse(&args.route_mode).is_none() {
        bail!("route mode must be github, full or pushed");
    }
    let dir = config_path
        .parent()
        .context("config path needs a parent directory")?;
    ensure_private_dir(dir)?;
    let profile = dir.join("client.ovpn");
    if let Some(source) = &args.profile {
        let mut text = Zeroizing::new(String::new());
        std::fs::File::open(source)
            .with_context(|| format!("opening {}", source.display()))?
            .take(2 * 1024 * 1024 + 1)
            .read_to_string(&mut text)?;
        if text.len() > 2 * 1024 * 1024 {
            bail!("profile exceeds 2 MiB");
        }
        write_private(&profile, text.as_bytes(), args.force)?;
    }
    if !profile.exists() {
        bail!(
            "no profile at {}; pass --profile PATH or run `sophos profile fetch --gateway IP` first",
            profile.display()
        );
    }
    let text = config::read_private(&profile, euid(), 2 * 1024 * 1024)?;
    validate_profile(&text).context("the daemon would refuse this profile")?;

    let totp_envelope = if args.manual_otp || !envelope.exists() {
        eprintln!("TOTP: manual; every login waits for `sophos connect` or `sophos otp`");
        None
    } else {
        let decoded = config::load_envelope(envelope, euid())?;
        eprintln!("TOTP: `{}` backend envelope", decoded.provider_id);
        Some(envelope)
    };

    let sudo_uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());
    let operator_uid = args
        .operator_uid
        .or(if euid() == 0 { sudo_uid } else { None });
    if system && operator_uid.is_none() {
        bail!("pass --operator-uid with the UID that will run `sophos connect` (see `id -u`)");
    }
    let openvpn = match &args.openvpn {
        Some(path) => path.clone(),
        None => {
            setup::find_openvpn().context("OpenVPN not found; install it or pass --openvpn PATH")?
        }
    };
    let (username, password) = if args.save_login {
        (Some(prompt_username()?), Some(prompt_password()?))
    } else {
        (None, None)
    };
    let socket = system.then(|| Path::new(config::SYSTEM_SOCKET));
    let rendered = ConfigFile {
        profile: &profile,
        totp_envelope,
        gateway: args.gateway.as_deref(),
        route_mode: &args.route_mode,
        openvpn: &openvpn,
        username: username.as_deref(),
        password: password.as_ref(),
        operator_uid,
        socket,
    }
    .render()?;
    write_private(config_path, rendered.as_bytes(), args.force)?;
    Config::load(config_path).context("written config failed validation")?;
    eprintln!("wrote {}", config_path.display());
    if system {
        eprintln!("next: install the boot service (see README), then `sophos --system connect`");
    } else {
        eprintln!(
            "next: `sudo sophos --config {} daemon` in one terminal, `sophos connect` in another",
            config_path.display()
        );
    }
    Ok(())
}
