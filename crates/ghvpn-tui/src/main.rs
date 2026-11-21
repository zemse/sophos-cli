//! `ghvpn-tui`: connect to a Sophos SSL VPN with the stock `openvpn` binary and check
//! whether a GitHub repository is reachable through it.

mod app;
mod probe;
mod ui;
mod vpn;

use sophos_cli::{ovpn, portal, routes};

use anyhow::Context;
use clap::Parser;
use ratatui::crossterm::event::{self, DisableBracketedPaste, EnableBracketedPaste, Event};
use ratatui::crossterm::execute;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub const USER_AGENT: &str = concat!("ghvpn-tui/", env!("CARGO_PKG_VERSION"));

#[derive(Parser, Debug, Clone)]
#[command(version, about)]
pub struct Args {
    /// Sophos firewall address. Replaces the `remote` host from the .ovpn.
    #[arg(long, env = "GHVPN_GATEWAY")]
    pub gateway: String,
    /// Hostname on the portal's TLS certificate (for example vpn.example.com). Requests still
    /// go to --gateway; without it the portal certificate is not verified.
    #[arg(long, env = "GHVPN_PORTAL_HOST")]
    pub portal_host: Option<String>,
    /// VPN portal HTTPS port.
    #[arg(long, default_value_t = 443)]
    pub portal_port: u16,
    /// Use this .ovpn instead of downloading one from the portal.
    #[arg(long, env = "GHVPN_OVPN")]
    pub ovpn: Option<PathBuf>,
    /// Override the OpenVPN port from the .ovpn.
    #[arg(long)]
    pub vpn_port: Option<u16>,
    /// Override the OpenVPN protocol from the .ovpn (udp, tcp-client).
    #[arg(long)]
    pub vpn_proto: Option<String>,
    /// VPN username (prefills the form).
    #[arg(long, env = "GHVPN_USER")]
    pub user: Option<String>,
    /// github: only GitHub ranges via the VPN. full: all traffic. pushed: server routes.
    #[arg(long, default_value = "github", value_parser = ["github", "full", "pushed"])]
    pub route_mode: String,
    /// Allow legacy TLS (`tls-cipher DEFAULT:@SECLEVEL=0`) for old firewall certificates.
    #[arg(long)]
    pub legacy_tls: bool,
    /// Path to the openvpn binary (default: search PATH and Homebrew locations).
    #[arg(long)]
    pub openvpn: Option<PathBuf>,
    /// Repository to probe.
    #[arg(long, default_value = "https://github.com/example-org/example-repo")]
    pub repo: String,
    /// GitHub username (prefills the form).
    #[arg(long, env = "GHVPN_GITHUB_USER")]
    pub github_user: Option<String>,
    /// Directory for test clones.
    #[arg(long, default_value = "clones")]
    pub clone_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    App,
    Vpn,
    Mgmt,
    OpenVpn,
    Probe,
}

pub enum AppEvent {
    Term(Event),
    Log(Source, String),
    Mgmt(ghvpn_mgmt::Notification),
    VpnStarted(vpn::Started),
    VpnExited(String),
    OvpnFetched(Result<portal::Fetched, String>),
    Probe(&'static str, probe::Outcome),
}

/// What the event loop must do outside the app state (it needs the terminal).
pub enum Action {
    Quit,
    /// Refresh the sudo timestamp interactively, then call [`app::App::connect`].
    SudoThenConnect,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::var_os(probe::ASKPASS_FLAG).is_some() {
        probe::askpass_main();
        return Ok(());
    }
    let args = Args::parse();
    let (tx, mut rx) = mpsc::channel::<AppEvent>(1024);
    let mut app = app::App::new(args, tx.clone());

    let paused = Arc::new(AtomicBool::new(false));
    spawn_input_thread(tx.clone(), paused.clone());

    let mut terminal = ratatui::init();
    let _ = execute!(std::io::stdout(), EnableBracketedPaste);
    let mut quit_deadline: Option<Instant> = None;
    let mut tick = tokio::time::interval(Duration::from_millis(250));

    let result: anyhow::Result<()> = async {
        loop {
            terminal.draw(|f| ui::draw(f, &app))?;
            let action = tokio::select! {
                ev = rx.recv() => match ev {
                    Some(ev) => app.handle(ev),
                    None => Some(Action::Quit),
                },
                _ = tick.tick() => None,
            };
            match action {
                Some(Action::Quit) => {
                    if !app.vpn_running() {
                        break;
                    }
                    if quit_deadline.is_none() {
                        app.disconnect();
                        quit_deadline = Some(Instant::now() + Duration::from_secs(12));
                    }
                }
                Some(Action::SudoThenConnect) => {
                    paused.store(true, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    let _ = execute!(std::io::stdout(), DisableBracketedPaste);
                    ratatui::restore();
                    println!("ghvpn-tui: openvpn needs root. Refreshing the sudo timestamp:");
                    let ok = std::process::Command::new("sudo")
                        .arg("-v")
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false);
                    terminal = ratatui::init();
                    let _ = execute!(std::io::stdout(), EnableBracketedPaste);
                    paused.store(false, Ordering::SeqCst);
                    if ok {
                        app.connect();
                    } else {
                        app.log(Source::App, "sudo -v failed; not connecting".into());
                    }
                }
                None => {}
            }
            if quit_deadline.is_some() && !app.vpn_running() {
                break;
            }
            if quit_deadline.is_some_and(|d| Instant::now() > d) {
                break;
            }
        }
        Ok(())
    }
    .await;

    let _ = execute!(std::io::stdout(), DisableBracketedPaste);
    ratatui::restore();
    if app.vpn_running() {
        eprintln!(
            "ghvpn-tui: openvpn did not confirm exit; check `pgrep -l openvpn` and `netstat -rn`."
        );
    }
    result.context("ui loop")
}

/// Blocking terminal reader. Pauses while the terminal is handed to `sudo`.
fn spawn_input_thread(tx: mpsc::Sender<AppEvent>, paused: Arc<AtomicBool>) {
    std::thread::spawn(move || loop {
        if paused.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        match event::poll(Duration::from_millis(100)) {
            Ok(true) => match event::read() {
                Ok(ev) => {
                    if tx.blocking_send(AppEvent::Term(ev)).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            },
            Ok(false) => {}
            Err(_) => break,
        }
    });
}
