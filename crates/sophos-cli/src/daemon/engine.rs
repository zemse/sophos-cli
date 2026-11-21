use super::{Control, Credentials};
use crate::config::{read_private, Config, Secret};
use crate::ipc::Status;
use crate::ovpn::{self, PatchOpts, RouteMode};
use crate::totp::{self, Totp};
use anyhow::{bail, Context};
use ghvpn_mgmt::{Line, Notification};
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

const AUTH_WINDOW: Duration = Duration::from_secs(15 * 60);
const MAX_AUTH_FAILURES: usize = 3;

#[derive(Default)]
struct Policy {
    attempts: u32,
    failures: VecDeque<Instant>,
    last_counter: Option<u64>,
}
impl Policy {
    fn prune(&mut self, now: Instant) {
        self.failures
            .retain(|at| now.duration_since(*at) < AUTH_WINDOW);
    }
    fn locked(&mut self) -> bool {
        self.prune(Instant::now());
        self.failures.len() >= MAX_AUTH_FAILURES
    }
    fn retry_delay(&mut self) -> Duration {
        let seconds = if self.attempts == 0 {
            0
        } else {
            (1u64 << self.attempts.min(5)).min(30)
        };
        self.attempts = self.attempts.saturating_add(1);
        Duration::from_secs(seconds)
    }
}

struct RunDir(PathBuf);
impl RunDir {
    fn new() -> anyhow::Result<Self> {
        let mut random = [0u8; 16];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| anyhow::anyhow!("OS randomness unavailable"))?;
        let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let path = Path::new("/tmp").join(format!("sophos-{name}"));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_private(path: &Path, content: &str) -> anyhow::Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(content.as_bytes())?;
    Ok(())
}

fn validate_profile(text: &str) -> anyhow::Result<()> {
    let mut block = None;
    let mut identity = false;
    for line in text.lines().map(str::trim) {
        if let Some(tag) = &block {
            if line == format!("</{tag}>") {
                block = None;
            }
            continue;
        }
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if let Some(tag) = line.strip_prefix('<').and_then(|l| l.strip_suffix('>')) {
            if !["ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"].contains(&tag) {
                bail!("unsupported inline block in VPN profile");
            }
            block = Some(tag.to_owned());
            continue;
        }
        let directive = line.split_whitespace().next().unwrap_or_default();
        if ![
            "client",
            "dev",
            "dev-type",
            "proto",
            "remote",
            "remote-random",
            "remote-random-hostname",
            "resolv-retry",
            "nobind",
            "persist-key",
            "persist-tun",
            "cipher",
            "data-ciphers",
            "data-ciphers-fallback",
            "auth",
            "auth-user-pass",
            "auth-retry",
            "auth-nocache",
            "remote-cert-tls",
            "verify-x509-name",
            "tls-version-min",
            "tls-version-max",
            "tls-cipher",
            "tls-ciphersuites",
            "key-direction",
            "reneg-sec",
            "compress",
            "comp-lzo",
            "allow-compression",
            "redirect-gateway",
            "route-nopull",
            "route",
            "route-delay",
            "route-method",
            "route-metric",
            "ca",
            "cert",
            "key",
            "tls-auth",
            "tls-crypt",
            "tls-crypt-v2",
            "verb",
            "mute",
            "tls-client",
            "tls-timeout",
            "float",
            "explicit-exit-notify",
            "sndbuf",
            "rcvbuf",
            "ping",
            "ping-restart",
            "keepalive",
            "connect-retry",
            "connect-timeout",
            "inactive",
        ]
        .contains(&directive)
        {
            bail!("unsupported VPN profile directive; scripts, plugins and extra config are not allowed");
        }
        if directive == "verify-x509-name" || line == "remote-cert-tls server" {
            identity = true;
        }
    }
    if block.is_some() {
        bail!("unterminated VPN profile block");
    }
    if !identity {
        bail!("VPN profile must verify the server identity");
    }
    Ok(())
}

struct Session {
    child: Child,
    lines: tokio::io::Lines<BufReader<OwnedReadHalf>>,
    writer: OwnedWriteHalf,
    _dir: RunDir,
}

enum End {
    Retry,
    Command(Control),
    AuthBlocked,
}

impl Session {
    async fn start(config: &Config, operator: u32) -> anyhow::Result<Self> {
        let profile = read_private(&config.profile, operator, 2 * 1024 * 1024)?;
        validate_profile(&profile)?;
        let dir = RunDir::new()?;
        let mode = RouteMode::parse(&config.route_mode).context("invalid routing mode")?;
        let (mut routes, _) = if mode == RouteMode::Github {
            crate::routes::github_ranges().await
        } else {
            (Vec::new(), false)
        };
        if mode == RouteMode::Github {
            routes.extend(
                crate::routes::egress_host_addrs()
                    .await
                    .into_iter()
                    .map(|ip| (ip, 32)),
            );
        }
        let management = dir.0.join("management.sock");
        let cfg_file = dir.0.join("client.ovpn");
        let (patched, _) = ovpn::patch(
            &profile,
            &PatchOpts {
                gateway: config.gateway.as_deref(),
                port: None,
                proto: None,
                route_mode: mode,
                routes: &routes,
                mgmt_port: 1,
                mgmt_pw_file: &dir.0.join("unused"),
                pid_file: &dir.0.join("openvpn.pid"),
                legacy_tls: false,
            },
        )?;
        let patched = Zeroizing::new(patched);
        let mut output = Zeroizing::new(String::new());
        let mut block = false;
        for line in patched.lines() {
            if line.starts_with('<') && !line.starts_with("</") {
                block = true;
            }
            let name = line.split_whitespace().next().unwrap_or_default();
            if !block && name == "management" {
                output.push_str(&format!("management {} unix\n", management.display()));
            } else if block
                || ![
                    "ping",
                    "ping-restart",
                    "keepalive",
                    "connect-retry",
                    "connect-timeout",
                    "inactive",
                ]
                .contains(&name)
            {
                output.push_str(line);
                output.push('\n');
            }
            if line.starts_with("</") {
                block = false;
            }
        }
        output.push_str("ping 10\nping-restart 30\nconnect-retry 1 10\nconnect-timeout 10\n");
        write_private(&cfg_file, &output)?;
        let mut child = Command::new(&config.openvpn)
            .arg("--config")
            .arg(&cfg_file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("starting OpenVPN; check openvpn path")?;
        let stream = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(status) = child.try_wait()? { bail!("OpenVPN exited before management startup ({status}); check profile compatibility"); }
                if let Ok(stream) = UnixStream::connect(&management).await { return anyhow::Ok(stream); }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }).await.context("OpenVPN management socket startup timed out")??;
        let (reader, writer) = stream.into_split();
        Ok(Self {
            child,
            lines: BufReader::new(reader).lines(),
            writer,
            _dir: dir,
        })
    }

    async fn drive(
        &mut self,
        credentials: &Credentials,
        totp: &Totp,
        policy: &mut Policy,
        rx: &mut mpsc::Receiver<Control>,
        status: &watch::Sender<Status>,
    ) -> anyhow::Result<End> {
        let mut pending_auth = false;
        let mut held_until = None;
        let mut started = false;
        let mut connected_at = None;
        let startup_deadline = Instant::now() + Duration::from_secs(10);
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        loop {
            tokio::select! {
                command = rx.recv() => return Ok(End::Command(command.unwrap_or(Control::Stop))),
                line = self.lines.next_line() => {
                    let Some(line) = line? else { return Ok(End::Retry); };
                    match ghvpn_mgmt::parse_line(&line) {
                        Line::Notification(Notification::Hold(message)) => {
                            started = true;
                            let wait = message.rsplit(':').next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0).min(300);
                            held_until = Some(Instant::now() + Duration::from_secs(wait));
                        }
                        Line::Notification(Notification::NeedAuth { static_challenge }) => {
                            if static_challenge.is_some() { bail!("static-challenge authentication is not supported; use password-plus-TOTP profile"); }
                            pending_auth = true;
                            status.send_modify(|s| s.state = "waiting_for_otp".into());
                        }
                        Line::Notification(Notification::NeedPrivateKeyPassword) => bail!("encrypted profile key needs a separate key-unlock implementation"),
                        Line::Notification(Notification::AuthFailed { .. }) => {
                            policy.prune(Instant::now()); policy.failures.push_back(Instant::now());
                            status.send_modify(|s| { s.auth_failures = policy.failures.len(); s.last_error = Some("VPN authentication rejected".into()); });
                            if policy.locked() { return Ok(End::AuthBlocked); }
                        }
                        Line::Notification(Notification::State { name, desc, local_ip, .. }) => {
                            if name == "CONNECTED" && desc == "SUCCESS" {
                                policy.failures.clear();
                                connected_at = Some(Instant::now());
                                status.send_modify(|s| { s.state = "connected".into(); s.tunnel_ip = local_ip;
                                    s.connected_since = totp::unix_seconds().ok(); s.auth_failures = 0; s.last_error = None; });
                            } else if name == "RECONNECTING" {
                                status.send_modify(|s| { s.state = "reconnecting".into(); s.tunnel_ip = None; s.connected_since = None; s.reconnects = s.reconnects.saturating_add(1); });
                            }
                        }
                        Line::Notification(Notification::Fatal(_)) => bail!("OpenVPN fatal error; check profile, TLS and server policy"),
                        Line::Error(_) => bail!("OpenVPN management command failed"),
                        _ => {}
                    }
                }
                _ = tick.tick() => {
                    if !started && Instant::now() >= startup_deadline { bail!("OpenVPN did not announce startup hold within 10 seconds"); }
                    if let Some(exit) = self.child.try_wait()? { bail!("OpenVPN exited ({exit})"); }
                    if connected_at.is_some_and(|at| at.elapsed() >= Duration::from_secs(60)) { policy.attempts = 0; }
                    if held_until.is_some_and(|at| Instant::now() >= at) {
                        self.writer.write_all(b"state on\nbytecount 2\nhold release\n").await?;
                        held_until = None;
                    }
                    if pending_auth {
                        if let Some(counter) = totp::usable_counter(totp::unix_seconds()?, policy.last_counter) {
                            let code = totp.code(counter);
                            let password = Zeroizing::new(format!("{}{}", credentials.password.expose(), code.as_str()));
                            let username_command = ghvpn_mgmt::username_cmd(&credentials.username)?;
                            let password_command = Zeroizing::new(ghvpn_mgmt::password_cmd(&password)?);
                            let commands = Zeroizing::new(format!("{username_command}\n{}\n", password_command.as_str()));
                            self.writer.write_all(commands.as_bytes()).await?;
                            policy.last_counter = Some(counter);
                            pending_auth = false;
                            status.send_modify(|s| s.state = "authenticating".into());
                        }
                    }
                }
            }
        }
    }

    async fn stop(&mut self) {
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            self.writer.write_all(b"signal SIGTERM\n"),
        )
        .await;
        if !matches!(
            tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await,
            Ok(Ok(_))
        ) {
            let _ = self.child.kill().await;
        }
    }
}

fn apply(
    command: Control,
    credentials: &mut Option<Credentials>,
    desired: &mut bool,
    policy: &mut Policy,
    status: &watch::Sender<Status>,
) -> bool {
    match command {
        Control::Stop => return false,
        Control::Disconnect => {
            *desired = false;
            *credentials = None;
        }
        Control::Connect(value) => {
            *credentials = Some(value);
            *desired = true;
        }
        Control::Reconnect => *desired = credentials.is_some(),
    }
    status.send_modify(|s| {
        s.tunnel_ip = None;
        s.connected_since = None;
    });
    if policy.locked() && *desired {
        *desired = false;
        status.send_modify(|s| {
            s.state = "auth_locked".into();
            s.last_error =
                Some("three authentication failures; wait 15 minutes before reconnecting".into());
        });
    } else if !*desired {
        status.send_modify(|s| {
            s.state = if credentials.is_some() {
                "disconnected"
            } else {
                "needs_credentials"
            }
            .into()
        });
    }
    true
}

pub(super) async fn run(
    config: Arc<Config>,
    operator: u32,
    mut rx: mpsc::Receiver<Control>,
    status: watch::Sender<Status>,
) -> anyhow::Result<()> {
    let totp = Totp::new(config.totp_seed.expose())?;
    let mut credentials = match (&config.username, &config.password) {
        (Some(username), Some(password))
            if !username.is_empty() && !password.expose().is_empty() =>
        {
            Some(Credentials {
                username: username.clone(),
                password: Secret::new(password.expose().to_owned()),
            })
        }
        _ => None,
    };
    let mut desired = credentials.is_some();
    let mut policy = Policy::default();
    loop {
        if !desired {
            let Some(command) = rx.recv().await else {
                break;
            };
            if !apply(
                command,
                &mut credentials,
                &mut desired,
                &mut policy,
                &status,
            ) {
                break;
            }
            continue;
        }
        status.send_modify(|s| {
            s.state = "connecting".into();
            s.tunnel_ip = None;
            s.connected_since = None;
        });
        let result = tokio::select! {
            command = rx.recv() => Ok(End::Command(command.unwrap_or(Control::Stop))),
            session = Session::start(&config, operator) => {
                match session {
                    Ok(mut session) => {
                        let result = session.drive(credentials.as_ref().context("credentials missing")?, &totp, &mut policy, &mut rx, &status).await;
                        session.stop().await;
                        result
                    }
                    Err(error) => Err(error),
                }
            }
        };
        match result {
            Ok(End::Command(command)) => {
                if !apply(
                    command,
                    &mut credentials,
                    &mut desired,
                    &mut policy,
                    &status,
                ) {
                    break;
                }
                continue;
            }
            Ok(End::AuthBlocked) => {
                desired = false;
                status.send_modify(|s| {
                    s.state = "auth_locked".into();
                    s.tunnel_ip = None;
                    s.connected_since = None;
                    s.last_error = Some(
                        "three authentication failures; wait 15 minutes before reconnecting".into(),
                    );
                });
                continue;
            }
            Err(error) => status.send_modify(|s| s.last_error = Some(error.to_string())),
            Ok(End::Retry) => status.send_modify(|s| {
                s.last_error = Some("OpenVPN management connection closed".into())
            }),
        }
        let delay = policy.retry_delay();
        status.send_modify(|s| {
            s.state = "reconnecting".into();
            s.tunnel_ip = None;
            s.connected_since = None;
            s.reconnects = s.reconnects.saturating_add(1);
        });
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            command = rx.recv() => {
                if !apply(command.unwrap_or(Control::Stop), &mut credentials, &mut desired, &mut policy, &status) { break; }
            }
        }
    }
    status.send_modify(|s| {
        s.state = "stopped".into();
        s.tunnel_ip = None;
        s.connected_since = None;
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn session_releases_reconnect_hold_and_stops_after_auth_failures() {
        let (client, server) = UnixStream::pair().unwrap();
        let (reader, writer) = client.into_split();
        let child = Command::new("/bin/sleep")
            .arg("60")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut session = Session {
            child,
            lines: BufReader::new(reader).lines(),
            writer,
            _dir: RunDir::new().unwrap(),
        };
        let (_tx, mut rx) = mpsc::channel(1);
        let (status, mut observed) = watch::channel(Status::default());
        let server = tokio::spawn(async move {
            let (reader, mut writer) = server.into_split();
            let mut lines = BufReader::new(reader).lines();
            for reconnect in [false, true] {
                writer
                    .write_all(b">HOLD:Waiting for hold release:0\n")
                    .await
                    .unwrap();
                for expected in ["state on", "bytecount 2", "hold release"] {
                    assert_eq!(lines.next_line().await.unwrap().as_deref(), Some(expected));
                }
                if !reconnect {
                    writer
                        .write_all(b">STATE:1,CONNECTED,SUCCESS,10.81.0.4,127.0.0.1\n")
                        .await
                        .unwrap();
                    observed.wait_for(|s| s.state == "connected").await.unwrap();
                    writer
                        .write_all(b">STATE:2,RECONNECTING,ping-restart,,,,\n")
                        .await
                        .unwrap();
                    observed
                        .wait_for(|s| s.state == "reconnecting")
                        .await
                        .unwrap();
                }
            }
            writer
                .write_all(b">PASSWORD:Need 'Auth' username/password\n")
                .await
                .unwrap();
            for _ in 0..3 {
                writer
                    .write_all(b">PASSWORD:Verification Failed: 'Auth'\n")
                    .await
                    .unwrap();
            }
        });
        let credentials = Credentials {
            username: "public-test".into(),
            password: Secret::new("public-test".into()),
        };
        let totp = Totp::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        let mut policy = Policy {
            last_counter: Some(u64::MAX),
            ..Policy::default()
        };
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            session.drive(&credentials, &totp, &mut policy, &mut rx, &status),
        )
        .await;
        session.child.kill().await.unwrap();
        assert!(matches!(result.unwrap().unwrap(), End::AuthBlocked));
        assert_eq!(status.borrow().auth_failures, 3);
        assert_eq!(status.borrow().reconnects, 1);
        server.await.unwrap();
    }

    #[test]
    fn backoff_is_immediate_then_bounded() {
        let mut policy = Policy::default();
        assert_eq!(policy.retry_delay(), Duration::ZERO);
        for _ in 0..100 {
            assert!(policy.retry_delay() <= Duration::from_secs(30));
        }
    }

    #[test]
    fn authentication_lock_survives_manual_reconnect() {
        let mut policy = Policy::default();
        policy.failures.extend([Instant::now(); 3]);
        let (tx, _) = watch::channel(Status::default());
        let mut credentials = Some(Credentials {
            username: "public-test".into(),
            password: Secret::new("public-test".into()),
        });
        let mut desired = false;
        assert!(apply(
            Control::Reconnect,
            &mut credentials,
            &mut desired,
            &mut policy,
            &tx
        ));
        assert!(!desired);
        assert_eq!(tx.borrow().state, "auth_locked");
        policy.prune(Instant::now() + AUTH_WINDOW);
        assert!(!policy.locked());
    }

    #[test]
    fn disconnect_forgets_interactive_credentials() {
        let (tx, _) = watch::channel(Status::default());
        let mut credentials = Some(Credentials {
            username: "public-test".into(),
            password: Secret::new("public-test".into()),
        });
        let mut desired = true;
        assert!(apply(
            Control::Disconnect,
            &mut credentials,
            &mut desired,
            &mut Policy::default(),
            &tx
        ));
        assert!(!desired && credentials.is_none());
    }

    #[test]
    fn profile_rejects_executable_directives() {
        assert!(validate_profile("remote-cert-tls server\nclient\n").is_ok());
        for directive in [
            "plugin",
            "config",
            "up",
            "down",
            "script-security",
            "pkcs11-providers",
        ] {
            assert!(
                validate_profile(&format!("remote-cert-tls server\n{directive} anything\n"))
                    .is_err()
            );
        }
        assert!(validate_profile("client\n").is_err());
    }
}
