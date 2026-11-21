//! Application state and the VPN authentication state machine.

use crate::ovpn::RouteMode;
use crate::probe::{self, GitCreds, Outcome};
use crate::vpn::{self, StartParams, Started, VpnCmd};
use crate::{portal, Action, AppEvent, Args, Source};
use ghvpn_mgmt::Notification;
use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const LOG_CAP: usize = 3000;
/// A typed OTP is only sent within this window (TOTP codes live 30 s).
const OTP_MAX_AGE: Duration = Duration::from_secs(30);
/// Three failed logins in this window stop further attempts for the same period, so the
/// firewall does not lock the account.
const LOCKOUT_WINDOW: Duration = Duration::from_secs(15 * 60);
const LOCKOUT_FAILURES: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum F {
    Gateway,
    PortalHost,
    OvpnPath,
    VpnUser,
    VpnPassword,
    Otp,
    RouteMode,
    GithubUser,
    GithubToken,
    Repo,
}

pub struct Field {
    pub id: F,
    pub label: &'static str,
    pub value: String,
    pub secret: bool,
    pub hint: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpnState {
    Idle,
    FetchingConfig,
    Starting,
    Connecting(String),
    NeedsCreds,
    Authenticating,
    Connected,
    Reconnecting(String),
    LockedOut(Instant),
    Failed(String),
}

impl VpnState {
    pub fn label(&self) -> String {
        match self {
            VpnState::Idle => "IDLE".into(),
            VpnState::FetchingConfig => "FETCHING CONFIG".into(),
            VpnState::Starting => "STARTING".into(),
            VpnState::Connecting(s) => format!("CONNECTING ({s})"),
            VpnState::NeedsCreds => "NEEDS CREDENTIALS".into(),
            VpnState::Authenticating => "AUTHENTICATING".into(),
            VpnState::Connected => "CONNECTED".into(),
            VpnState::Reconnecting(s) => format!("RECONNECTING ({s})"),
            VpnState::LockedOut(until) => {
                format!(
                    "LOCKED_OUT_GUARD ({} s)",
                    until.saturating_duration_since(Instant::now()).as_secs()
                )
            }
            VpnState::Failed(s) => format!("FAILED ({s})"),
        }
    }
}

pub struct LogLine {
    pub at: Duration,
    pub source: Source,
    pub text: String,
}

pub struct ProbeLine {
    pub at: Duration,
    pub name: &'static str,
    pub outcome: Outcome,
    /// Whether the VPN was connected when the result arrived.
    pub via_vpn: bool,
}

pub struct App {
    pub args: Args,
    pub fields: Vec<Field>,
    pub focus: usize,
    pub state: VpnState,
    pub tunnel_ip: Option<String>,
    pub bytes: (u64, u64),
    pub session_token: bool,
    pub started: Option<Started>,
    pub failures: Vec<Instant>,
    pub log: VecDeque<LogLine>,
    /// Lines scrolled up from the bottom of the log.
    pub log_scroll: usize,
    pub probes: Vec<ProbeLine>,
    pub openvpn: Option<PathBuf>,
    pub use_sudo: bool,
    pub start: Instant,
    pub busy: Vec<&'static str>,
    tx: mpsc::Sender<AppEvent>,
    vpn_tx: Option<mpsc::Sender<VpnCmd>>,
    fetched_ovpn: Option<String>,
    connect_after_fetch: bool,
    portal_used_otp: bool,
    otp_set_at: Option<Instant>,
}

impl App {
    pub fn new(args: Args, tx: mpsc::Sender<AppEvent>) -> Self {
        let f = |id, label, value: String, secret, hint| Field {
            id,
            label,
            value,
            secret,
            hint,
        };
        let fields = vec![
            f(
                F::Gateway,
                "Gateway",
                args.gateway.clone(),
                false,
                "Sophos firewall IP or host",
            ),
            f(
                F::PortalHost,
                "Portal TLS host",
                args.portal_host.clone().unwrap_or_default(),
                false,
                "name on the portal cert; blank = don't verify",
            ),
            f(
                F::OvpnPath,
                ".ovpn file",
                args.ovpn
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
                false,
                "blank = download from portal",
            ),
            f(
                F::VpnUser,
                "VPN username",
                args.user.clone().unwrap_or_default(),
                false,
                "",
            ),
            f(F::VpnPassword, "VPN password", String::new(), true, ""),
            f(
                F::Otp,
                "VPN OTP",
                String::new(),
                false,
                "optional 6 digits, appended to password",
            ),
            f(
                F::RouteMode,
                "Route mode",
                args.route_mode.clone(),
                false,
                "←/→: github | full | pushed",
            ),
            f(
                F::GithubUser,
                "GitHub user",
                args.github_user.clone().unwrap_or_default(),
                false,
                "blank = x-access-token",
            ),
            f(
                F::GithubToken,
                "GitHub token",
                String::new(),
                true,
                "PAT; blank = your normal git credentials",
            ),
            f(F::Repo, "Repo URL", args.repo.clone(), false, ""),
        ];
        let openvpn = args.openvpn.clone().or_else(find_openvpn);
        let use_sudo = unsafe { libc::geteuid() } != 0;
        let mut app = Self {
            args,
            fields,
            focus: 3,
            state: VpnState::Idle,
            tunnel_ip: None,
            bytes: (0, 0),
            session_token: false,
            started: None,
            failures: Vec::new(),
            log: VecDeque::new(),
            log_scroll: 0,
            probes: Vec::new(),
            openvpn,
            use_sudo,
            start: Instant::now(),
            busy: Vec::new(),
            tx,
            vpn_tx: None,
            fetched_ovpn: None,
            connect_after_fetch: false,
            portal_used_otp: false,
            otp_set_at: None,
        };
        match &app.openvpn {
            Some(p) => app.log(Source::App, format!("openvpn: {}", p.display())),
            None => app.log(
                Source::App,
                "openvpn not found. Install it (`brew install openvpn`) or pass --openvpn".into(),
            ),
        }
        if app.args.portal_host.is_none() {
            app.log(
                Source::App,
                "no --portal-host: the portal TLS certificate will NOT be verified".into(),
            );
        }
        app
    }

    pub fn value(&self, id: F) -> &str {
        self.fields
            .iter()
            .find(|f| f.id == id)
            .map(|f| f.value.as_str())
            .unwrap_or("")
    }

    fn set_value(&mut self, id: F, v: String) {
        if let Some(f) = self.fields.iter_mut().find(|f| f.id == id) {
            f.value = v;
        }
    }

    pub fn log(&mut self, source: Source, text: String) {
        if self.log.len() >= LOG_CAP {
            self.log.pop_front();
        }
        self.log.push_back(LogLine {
            at: self.start.elapsed(),
            source,
            text,
        });
    }

    pub fn vpn_running(&self) -> bool {
        self.vpn_tx.is_some()
    }

    pub fn route_mode(&self) -> RouteMode {
        RouteMode::parse(self.value(F::RouteMode)).unwrap_or(RouteMode::Github)
    }

    fn git_creds(&self) -> GitCreds {
        GitCreds {
            user: self.value(F::GithubUser).trim().to_string(),
            token: self.value(F::GithubToken).trim().to_string(),
        }
    }

    pub fn handle(&mut self, ev: AppEvent) -> Option<Action> {
        match ev {
            AppEvent::Term(Event::Key(k)) if k.kind != KeyEventKind::Release => {
                return self.on_key(k)
            }
            AppEvent::Term(Event::Paste(s)) => {
                let s: String = s.chars().filter(|c| !c.is_control()).collect();
                self.fields[self.focus].value.push_str(&s);
                self.after_edit();
            }
            AppEvent::Term(_) => {}
            AppEvent::Log(src, text) => self.log(src, text),
            AppEvent::Mgmt(n) => self.on_mgmt(n),
            AppEvent::VpnStarted(s) => {
                self.log(
                    Source::Vpn,
                    format!(
                        "{}; route mode {}{}; .ovpn reneg-sec {}",
                        s.remote,
                        self.route_mode().name(),
                        if self.route_mode() == RouteMode::Github {
                            format!(
                                " ({} GitHub ranges, {}, egress host pinned to {:?})",
                                s.routes,
                                if s.routes_live {
                                    "live from api.github.com/meta"
                                } else {
                                    "FALLBACK list"
                                },
                                s.egress_pin
                            )
                        } else {
                            String::new()
                        },
                        s.reneg_sec.as_deref().unwrap_or("not set (server decides)"),
                    ),
                );
                self.started = Some(s);
            }
            AppEvent::VpnExited(msg) => {
                self.log(Source::Vpn, msg.clone());
                self.vpn_tx = None;
                self.tunnel_ip = None;
                if !matches!(self.state, VpnState::LockedOut(_) | VpnState::Failed(_)) {
                    self.state = VpnState::Idle;
                }
            }
            AppEvent::OvpnFetched(res) => {
                self.busy.retain(|b| *b != "portal");
                match res {
                    Ok(f) => {
                        self.log(
                            Source::App,
                            format!(
                                "downloaded .ovpn from portal ({} bytes, TLS {})",
                                f.ovpn.len(),
                                if f.tls_verified {
                                    "verified"
                                } else {
                                    "NOT verified"
                                }
                            ),
                        );
                        if f.otp_enrolment {
                            self.log(
                                Source::App,
                                "portal answered 299 (OTP enrolment pending for this user)".into(),
                            );
                        }
                        self.fetched_ovpn = Some(f.ovpn);
                        self.state = VpnState::Idle;
                        let then_connect = std::mem::take(&mut self.connect_after_fetch);
                        if then_connect && std::mem::take(&mut self.portal_used_otp) {
                            self.log(Source::App, "the portal login used the OTP: wait for the next code, type it, press Enter".into());
                        } else if then_connect {
                            return self.request_connect();
                        }
                    }
                    Err(e) => {
                        self.connect_after_fetch = false;
                        self.state = VpnState::Failed("portal".into());
                        self.log(Source::App, format!("portal: {e}"));
                    }
                }
            }
            AppEvent::Probe(name, outcome) => {
                self.busy.retain(|b| *b != name);
                let via_vpn = self.state == VpnState::Connected;
                self.log(
                    Source::Probe,
                    format!(
                        "{name}: {} {}",
                        if outcome.ok { "OK" } else { "FAIL" },
                        outcome.summary
                    ),
                );
                self.probes.push(ProbeLine {
                    at: self.start.elapsed(),
                    name,
                    outcome,
                    via_vpn,
                });
            }
        }
        if let VpnState::LockedOut(until) = self.state {
            if Instant::now() >= until && !self.vpn_running() {
                self.state = VpnState::Idle;
            }
        }
        None
    }

    fn on_key(&mut self, k: KeyEvent) -> Option<Action> {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        match k.code {
            KeyCode::Char('c' | 'q') if ctrl => return Some(Action::Quit),
            KeyCode::Char('f') if ctrl => self.fetch_config(false),
            KeyCode::Char('d') if ctrl => self.disconnect(),
            KeyCode::Char('e') if ctrl => self.run_probe("egress-ip"),
            KeyCode::Char('g') if ctrl => {
                self.run_probe("github-api");
                self.run_probe("git-ls-remote");
            }
            KeyCode::Char('k') if ctrl => self.run_probe("git-clone"),
            KeyCode::Char('l') if ctrl => {
                self.log.clear();
                self.log_scroll = 0;
            }
            KeyCode::Char('u') if ctrl => {
                self.fields[self.focus].value.clear();
                self.after_edit();
            }
            KeyCode::Enter => return self.request_connect(),
            KeyCode::Tab | KeyCode::Down => self.focus = (self.focus + 1) % self.fields.len(),
            KeyCode::BackTab | KeyCode::Up => {
                self.focus = (self.focus + self.fields.len() - 1) % self.fields.len()
            }
            KeyCode::PageUp => self.log_scroll = (self.log_scroll + 10).min(self.log.len()),
            KeyCode::PageDown => self.log_scroll = self.log_scroll.saturating_sub(10),
            KeyCode::End => self.log_scroll = 0,
            KeyCode::Left | KeyCode::Right if self.fields[self.focus].id == F::RouteMode => {
                let all = RouteMode::ALL;
                let i = all
                    .iter()
                    .position(|m| *m == self.route_mode())
                    .unwrap_or(0);
                let n = if k.code == KeyCode::Right {
                    (i + 1) % all.len()
                } else {
                    (i + all.len() - 1) % all.len()
                };
                self.set_value(F::RouteMode, all[n].name().to_string());
            }
            KeyCode::Backspace => {
                self.fields[self.focus].value.pop();
                self.after_edit();
            }
            KeyCode::Char(c) if !ctrl && self.fields[self.focus].id != F::RouteMode => {
                self.fields[self.focus].value.push(c);
                self.after_edit();
            }
            _ => {}
        }
        None
    }

    fn after_edit(&mut self) {
        match self.fields[self.focus].id {
            F::Otp => self.otp_set_at = (!self.value(F::Otp).is_empty()).then(Instant::now),
            // A different source or account invalidates a downloaded config.
            F::Gateway | F::PortalHost | F::VpnUser | F::OvpnPath => self.fetched_ovpn = None,
            _ => {}
        }
    }

    /// Enter: start the VPN, or answer a pending credentials prompt.
    fn request_connect(&mut self) -> Option<Action> {
        if let VpnState::LockedOut(until) = self.state {
            let left = until.saturating_duration_since(Instant::now()).as_secs();
            self.log(
                Source::App,
                format!("lockout guard active for {left} s more (3 failed logins)"),
            );
            return None;
        }
        if self.value(F::VpnUser).is_empty() || self.value(F::VpnPassword).is_empty() {
            self.log(
                Source::App,
                "fill in VPN username and password first".into(),
            );
            return None;
        }
        if self.state == VpnState::NeedsCreds {
            self.send_creds();
            return None;
        }
        if self.vpn_running() || self.state == VpnState::FetchingConfig {
            self.log(
                Source::App,
                "VPN already starting or running (Ctrl-D to disconnect)".into(),
            );
            return None;
        }
        if self.openvpn.is_none() {
            self.log(
                Source::App,
                "openvpn not found; install it or pass --openvpn".into(),
            );
            return None;
        }
        if self.value(F::OvpnPath).trim().is_empty() && self.fetched_ovpn.is_none() {
            self.fetch_config(true);
            return None;
        }
        if self.use_sudo && !sudo_cached() {
            return Some(Action::SudoThenConnect);
        }
        self.connect();
        None
    }

    fn fetch_config(&mut self, then_connect: bool) {
        if self.busy.contains(&"portal") {
            return;
        }
        self.portal_used_otp = !self.value(F::Otp).trim().is_empty();
        let (user, password) = (
            self.value(F::VpnUser).to_string(),
            self.password_with_otp(true),
        );
        if user.is_empty() || password.is_empty() {
            self.log(
                Source::App,
                "fill in VPN username and password first".into(),
            );
            return;
        }
        let gateway = self.value(F::Gateway).trim().to_string();
        let host = self.value(F::PortalHost).trim().to_string();
        let port = self.args.portal_port;
        self.busy.push("portal");
        self.state = VpnState::FetchingConfig;
        self.connect_after_fetch = then_connect;
        self.log(
            Source::App,
            format!("logging in to VPN portal at {gateway}:{port} as {user}"),
        );
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let p = portal::Portal {
                gateway: &gateway,
                host: Some(host.as_str()).filter(|h| !h.is_empty()),
                port,
            };
            let res = p
                .fetch_config(&user, &password)
                .await
                .map_err(|e| format!("{e:#}"));
            let _ = tx.send(AppEvent::OvpnFetched(res)).await;
        });
    }

    /// Spawns the openvpn supervisor. Assumes sudo (if needed) is already cached.
    pub fn connect(&mut self) {
        let ovpn_text = match self.value(F::OvpnPath).trim() {
            "" => match &self.fetched_ovpn {
                Some(t) => t.clone(),
                None => return self.log(Source::App, "no .ovpn loaded".into()),
            },
            path => match std::fs::read_to_string(path) {
                Ok(t) => t,
                Err(e) => return self.log(Source::App, format!("reading {path}: {e}")),
            },
        };
        let Some(openvpn) = self.openvpn.clone() else {
            return;
        };
        let gateway = self.value(F::Gateway).trim().to_string();
        let params = StartParams {
            openvpn,
            use_sudo: self.use_sudo,
            ovpn_text,
            gateway: (!gateway.is_empty()).then_some(gateway),
            port: self.args.vpn_port,
            proto: self.args.vpn_proto.clone(),
            route_mode: self.route_mode(),
            legacy_tls: self.args.legacy_tls,
        };
        let (vtx, vrx) = mpsc::channel(16);
        self.vpn_tx = Some(vtx);
        self.state = VpnState::Starting;
        self.session_token = false;
        self.bytes = (0, 0);
        tokio::spawn(vpn::run(params, vrx, self.tx.clone()));
    }

    pub fn disconnect(&mut self) {
        if let Some(tx) = &self.vpn_tx {
            let _ = tx.try_send(VpnCmd::Disconnect);
            self.log(Source::App, "disconnecting".into());
        }
    }

    /// Password with the OTP appended. `consume` clears the OTP field (codes are single use).
    fn password_with_otp(&mut self, consume: bool) -> String {
        let otp = self.value(F::Otp).trim().to_string();
        let pw = format!("{}{otp}", self.value(F::VpnPassword));
        if consume && !otp.is_empty() {
            self.set_value(F::Otp, String::new());
            self.otp_set_at = None;
            self.log(
                Source::App,
                "OTP consumed; enter a fresh code for the next login".into(),
            );
        }
        pw
    }

    fn send_creds(&mut self) {
        let Some(tx) = self.vpn_tx.clone() else {
            return;
        };
        if self.otp_set_at.is_some_and(|t| t.elapsed() > OTP_MAX_AGE) {
            self.log(
                Source::App,
                "OTP older than 30 s, not sending it. Type the current code and press Enter".into(),
            );
            self.set_value(F::Otp, String::new());
            self.otp_set_at = None;
            return;
        }
        let user = self.value(F::VpnUser).to_string();
        let password = self.password_with_otp(true);
        if tx.try_send(VpnCmd::Creds { user, password }).is_ok() {
            self.state = VpnState::Authenticating;
        }
    }

    fn on_mgmt(&mut self, n: Notification) {
        match n {
            Notification::NeedAuth { static_challenge } => {
                if let Some(sc) = static_challenge {
                    self.log(Source::Mgmt, format!("server uses a static challenge ({:?}); password+OTP is sent concatenated", sc.text));
                }
                if self.state == VpnState::Starting {
                    // First prompt after Enter: credentials were just typed, send them.
                    self.send_creds();
                } else {
                    self.state = VpnState::NeedsCreds;
                    self.log(
                        Source::Mgmt,
                        "server wants credentials again: enter a fresh OTP and press Enter".into(),
                    );
                }
            }
            Notification::AuthFailed { detail } => {
                let now = Instant::now();
                self.failures
                    .retain(|t| now.duration_since(*t) < LOCKOUT_WINDOW);
                self.failures.push(now);
                self.log(
                    Source::Mgmt,
                    format!(
                        "authentication FAILED{} ({} in 15 min)",
                        detail.map(|d| format!(": {d}")).unwrap_or_default(),
                        self.failures.len()
                    ),
                );
                if self.failures.len() >= LOCKOUT_FAILURES {
                    self.state = VpnState::LockedOut(now + LOCKOUT_WINDOW);
                    self.log(
                        Source::App,
                        "3 failures: stopping to avoid a firewall account lockout".into(),
                    );
                    self.disconnect();
                } else {
                    self.state = VpnState::NeedsCreds;
                }
            }
            Notification::NeedPrivateKeyPassword => {
                self.log(
                    Source::Mgmt,
                    "the .ovpn private key is encrypted; not supported by this harness".into(),
                );
                self.disconnect();
            }
            Notification::AuthToken => {
                if !self.session_token {
                    self.log(
                        Source::Mgmt,
                        "server pushed an auth-token: renegotiation won't need a new OTP".into(),
                    );
                }
                self.session_token = true;
            }
            Notification::State {
                name,
                desc,
                local_ip,
                ..
            } => {
                self.log(
                    Source::Mgmt,
                    format!(
                        "STATE {name} {desc} {}",
                        local_ip.clone().unwrap_or_default()
                    ),
                );
                match name.as_str() {
                    "CONNECTED" => {
                        self.tunnel_ip = local_ip;
                        if desc == "SUCCESS" {
                            self.state = VpnState::Connected;
                            self.failures.clear();
                            self.run_probe("egress-ip");
                        } else {
                            self.state = VpnState::Failed(format!("connected with {desc}"));
                        }
                    }
                    "RECONNECTING" => self.state = VpnState::Reconnecting(desc),
                    "EXITING" => {
                        if !matches!(self.state, VpnState::LockedOut(_)) {
                            self.state = VpnState::Reconnecting(format!("exiting: {desc}"));
                        }
                    }
                    // AUTH must not hide a pending prompt or an in-flight answer.
                    "AUTH"
                        if matches!(
                            self.state,
                            VpnState::NeedsCreds | VpnState::Authenticating
                        ) => {}
                    "AUTH" | "GET_CONFIG" | "ASSIGN_IP" | "ADD_ROUTES" | "TCP_CONNECT"
                    | "RESOLVE" | "WAIT" | "CONNECTING" => self.state = VpnState::Connecting(name),
                    _ => {}
                }
            }
            Notification::ByteCount {
                bytes_in,
                bytes_out,
            } => self.bytes = (bytes_in, bytes_out),
            Notification::Fatal(m) => {
                self.log(Source::Mgmt, format!("FATAL: {m}"));
                self.state = VpnState::Failed(m);
            }
            Notification::Hold(m) => self.log(Source::Mgmt, format!("HOLD: {m}")),
            Notification::Info(m) => self.log(Source::Mgmt, format!("INFO: {m}")),
            Notification::Log(m) | Notification::Other(m) => self.log(Source::Mgmt, m),
        }
    }

    fn run_probe(&mut self, name: &'static str) {
        if self.busy.contains(&name) {
            return;
        }
        self.busy.push(name);
        let tx = self.tx.clone();
        let repo = self.value(F::Repo).trim().to_string();
        let creds = self.git_creds();
        let pin: Vec<Ipv4Addr> = match (&self.started, self.state == VpnState::Connected) {
            (Some(s), true) => s.egress_pin.clone(),
            _ => Vec::new(),
        };
        let clone_dir = self.args.clone_dir.clone();
        self.log(
            Source::Probe,
            format!(
                "{name}: running ({})",
                if self.state == VpnState::Connected {
                    "VPN up"
                } else {
                    "VPN down"
                }
            ),
        );
        tokio::spawn(async move {
            let outcome = match name {
                "egress-ip" => probe::egress_ip(&pin).await,
                "github-api" => probe::github_api(&repo, &creds.token).await,
                "git-ls-remote" => probe::git_ls_remote(&repo, &creds).await,
                "git-clone" => probe::git_clone(&repo, &creds, &clone_dir).await,
                _ => unreachable!(),
            };
            let _ = tx.send(AppEvent::Probe(name, outcome)).await;
        });
    }
}

fn find_openvpn() -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .chain(
            [
                "/opt/homebrew/sbin",
                "/usr/local/sbin",
                "/usr/sbin",
                "/sbin",
            ]
            .map(PathBuf::from),
        )
        .map(|d| d.join("openvpn"))
        .find(|p| p.is_file())
}

fn sudo_cached() -> bool {
    std::process::Command::new("sudo")
        .args(["-n", "true"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
