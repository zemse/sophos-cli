//! Local control for the Sophos SSL VPN supervisor.

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use sophos_cli::config::{self, Config, Secret};
use sophos_cli::ipc::{self, Request};
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(version, about = "Sophos SSL VPN daemon control")]
struct Args {
    /// Configuration path (daemon only); also determines the default control socket.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Override the control socket path.
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the privileged foreground supervisor (use systemd or launchd for background operation).
    Daemon,
    /// Connect, prompting for credentials absent from the daemon's config.
    Connect,
    /// Print safe connection status as JSON.
    Status,
    /// Restart the VPN using retained credentials.
    Reconnect,
    /// Disconnect, disable reconnection and forget interactive credentials.
    Disconnect,
    /// Stop the supervisor and VPN.
    Stop,
}

struct RawMode;
impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

fn prompt_username() -> anyhow::Result<String> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        bail!("missing credentials require an interactive terminal");
    }
    eprint!("VPN username: ");
    io::stderr().flush()?;
    let mut value = String::new();
    io::stdin().lock().read_line(&mut value)?;
    Ok(value.trim_end_matches(['\r', '\n']).to_owned())
}

fn prompt_password() -> anyhow::Result<Secret> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        bail!("missing password requires an interactive terminal");
    }
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config_path = match args.config {
        Some(path) => path,
        None => config::default_config()?,
    };
    if matches!(args.command, Command::Daemon) {
        let (config, operator) = Config::load(&config_path)?;
        let socket = args
            .socket
            .or_else(|| config.socket.clone())
            .unwrap_or(config::default_socket(&config_path)?);
        return sophos_cli::daemon::run(config, operator, socket).await;
    }
    let socket = args.socket.unwrap_or(config::default_socket(&config_path)?);
    let request = match args.command {
        Command::Connect => {
            let requirements = ipc::call(&socket, Request::Requirements).await?;
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
            Request::Connect { username, password }
        }
        Command::Status => Request::Status,
        Command::Reconnect => Request::Reconnect,
        Command::Disconnect => Request::Disconnect,
        Command::Stop => Request::Stop,
        Command::Daemon => unreachable!(),
    };
    let reply = ipc::call(&socket, request).await?;
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
