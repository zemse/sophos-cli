//! Runs `openvpn` (through `sudo -n` unless already root) and drives its management interface.
//!
//! The task owns a private runtime directory holding the patched config (which contains
//! the client private key), the management password and the pid file. The directory is
//! removed when the task ends.

use crate::ovpn::{self, PatchOpts, RouteMode};
use crate::{AppEvent, Source};
use anyhow::{bail, Context};
use ghvpn_mgmt::{Line, Notification};
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

pub enum VpnCmd {
    /// Answer a pending `Need 'Auth'` prompt.
    Creds {
        user: String,
        password: String,
    },
    Disconnect,
}

pub struct StartParams {
    pub openvpn: PathBuf,
    pub use_sudo: bool,
    pub ovpn_text: String,
    pub gateway: Option<String>,
    pub port: Option<u16>,
    pub proto: Option<String>,
    pub route_mode: RouteMode,
    pub legacy_tls: bool,
}

/// Facts about the started tunnel the UI wants to show.
#[derive(Debug, Clone, Default)]
pub struct Started {
    pub routes: usize,
    pub routes_live: bool,
    pub egress_pin: Vec<Ipv4Addr>,
    pub reneg_sec: Option<String>,
    pub remote: String,
}

struct RunDir(PathBuf);

impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub async fn run(p: StartParams, mut cmds: mpsc::Receiver<VpnCmd>, ev: mpsc::Sender<AppEvent>) {
    let log = |s: String| {
        let ev = ev.clone();
        async move {
            let _ = ev.send(AppEvent::Log(Source::Vpn, s)).await;
        }
    };
    let result = run_inner(p, &mut cmds, &ev).await;
    let msg = match result {
        Ok(msg) => msg,
        Err(e) => {
            log(format!("error: {e:#}")).await;
            format!("{e:#}")
        }
    };
    let _ = ev.send(AppEvent::VpnExited(msg)).await;
}

async fn run_inner(
    p: StartParams,
    cmds: &mut mpsc::Receiver<VpnCmd>,
    ev: &mpsc::Sender<AppEvent>,
) -> anyhow::Result<String> {
    let log = |s: String| ev.send(AppEvent::Log(Source::Vpn, s));

    let (routes, routes_live) = match p.route_mode {
        RouteMode::Github => crate::routes::github_ranges().await,
        _ => (Vec::new(), false),
    };
    let egress_pin = match p.route_mode {
        RouteMode::Github => crate::routes::egress_host_addrs().await,
        _ => Vec::new(),
    };
    let mut all_routes = routes.clone();
    all_routes.extend(egress_pin.iter().map(|ip| (*ip, 32u8)));

    let dir = make_run_dir()?;
    let mgmt_pw = random_hex(16)?;
    let mgmt_port = free_port()?;
    let pw_file = dir.0.join("mgmt.pw");
    let pid_file = dir.0.join("openvpn.pid");
    let cfg_file = dir.0.join("client.ovpn");

    let (cfg, info) = ovpn::patch(
        &p.ovpn_text,
        &PatchOpts {
            gateway: p.gateway.as_deref(),
            port: p.port,
            proto: p.proto.as_deref(),
            route_mode: p.route_mode,
            routes: &all_routes,
            mgmt_port,
            mgmt_pw_file: &pw_file,
            pid_file: &pid_file,
            legacy_tls: p.legacy_tls,
        },
    )?;
    write_private(&pw_file, format!("{mgmt_pw}\n").as_bytes())?;
    write_private(&cfg_file, cfg.as_bytes())?;
    if !info.has_cert || !info.has_key {
        log("warning: .ovpn has no inline <cert>/<key>; Sophos configs normally carry both".into())
            .await?;
    }
    let remote = cfg
        .lines()
        .rev()
        .find(|l| l.starts_with("remote "))
        .unwrap_or("")
        .to_string();
    let _ = ev
        .send(AppEvent::VpnStarted(Started {
            routes: routes.len(),
            routes_live,
            egress_pin: egress_pin.clone(),
            reneg_sec: info.reneg_sec.clone(),
            remote: remote.clone(),
        }))
        .await;

    let mut cmd = if p.use_sudo {
        let mut c = Command::new("sudo");
        c.arg("-n").arg(&p.openvpn);
        c
    } else {
        Command::new(&p.openvpn)
    };
    cmd.arg("--config")
        .arg(&cfg_file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning {}", p.openvpn.display()))?;
    log(format!(
        "spawned {} ({}), mgmt on 127.0.0.1:{mgmt_port}",
        p.openvpn.display(),
        remote
    ))
    .await?;
    pipe_lines(child.stdout.take(), ev.clone());
    pipe_lines(child.stderr.take(), ev.clone());

    // Connect to the management interface while openvpn starts up.
    let stream = loop {
        if let Some(status) = child.try_wait()? {
            bail!("openvpn exited before the management interface came up ({status})");
        }
        match TcpStream::connect(("127.0.0.1", mgmt_port)).await {
            Ok(s) => break s,
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    };
    let (rd, mut wr) = stream.into_split();
    let mut lines = BufReader::new(rd).lines();
    // The prompt has no newline; writing the password straight away is fine.
    wr.write_all(format!("{mgmt_pw}\n").as_bytes()).await?;
    log("waiting for OpenVPN startup hold".into()).await?;
    if let Err(e) = release_startup_hold(&mut lines, &mut wr, ev, Duration::from_secs(10)).await {
        shutdown(&mut child, &pid_file, p.use_sudo, ev).await;
        return Err(e);
    }

    let mut disconnecting = false;
    loop {
        tokio::select! {
            line = lines.next_line() => match line {
                Ok(Some(line)) => handle_line(&line, ev).await,
                Ok(None) | Err(_) => {
                    if !disconnecting {
                        log("management interface closed".into()).await?;
                    }
                    let status = shutdown(&mut child, &pid_file, p.use_sudo, ev).await;
                    return Ok(format!("openvpn exited ({status})"));
                }
            },
            cmd = cmds.recv() => match cmd {
                Some(VpnCmd::Creds { user, password }) => {
                    let u = ghvpn_mgmt::username_cmd(&user)?;
                    let pw = ghvpn_mgmt::password_cmd(&password)?;
                    log(format!("> {u}")).await?;
                    log(format!("> {}", ghvpn_mgmt::redacted(&pw))).await?;
                    wr.write_all(format!("{u}\n{pw}\n").as_bytes()).await?;
                }
                Some(VpnCmd::Disconnect) | None => {
                    disconnecting = true;
                    log("> signal SIGTERM".into()).await?;
                    if wr.write_all(b"signal SIGTERM\n").await.is_err() {
                        let status = shutdown(&mut child, &pid_file, p.use_sudo, ev).await;
                        return Ok(format!("openvpn exited ({status})"));
                    }
                }
            },
            status = child.wait() => {
                let status = status.map(|s| s.to_string()).unwrap_or_else(|e| e.to_string());
                return Ok(format!("openvpn exited ({status})"));
            }
        }
    }
}

async fn release_startup_hold<R, W>(
    lines: &mut tokio::io::Lines<R>,
    wr: &mut W,
    ev: &mpsc::Sender<AppEvent>,
    timeout: Duration,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    tokio::time::timeout(timeout, async {
        let mut authenticated = false;
        let mut held = false;
        while let Some(line) = lines.next_line().await? {
            match ghvpn_mgmt::parse_line(&line) {
                Line::Success(s) if s == "password is correct" => authenticated = true,
                Line::Notification(Notification::Hold(_)) => held = true,
                Line::Error(s) | Line::Notification(Notification::Fatal(s)) => {
                    bail!("OpenVPN management startup failed: {s}");
                }
                _ => {}
            }
            handle_line(&line, ev).await;
            if authenticated && held {
                // Releasing before >HOLD can succeed without releasing the later hold.
                wr.write_all(b"state on\nbytecount 2\nhold release\n")
                    .await?;
                return Ok(());
            }
        }
        bail!("OpenVPN management interface closed before startup hold");
    })
    .await
    .context("timed out waiting for OpenVPN management authentication and startup hold")?
}

async fn handle_line(line: &str, ev: &mpsc::Sender<AppEvent>) {
    match ghvpn_mgmt::parse_line(line) {
        Line::Notification(Notification::Log(_)) | Line::Data(_) => {}
        Line::Notification(n) => {
            let _ = ev.send(AppEvent::Mgmt(n)).await;
        }
        Line::Success(s) => {
            let _ = ev
                .send(AppEvent::Log(Source::Mgmt, format!("SUCCESS: {s}")))
                .await;
        }
        Line::Error(s) => {
            let _ = ev
                .send(AppEvent::Log(Source::Mgmt, format!("ERROR: {s}")))
                .await;
        }
    }
}

/// Waits for openvpn to exit after SIGTERM was requested, then falls back to `kill`.
async fn shutdown(
    child: &mut Child,
    pid_file: &Path,
    use_sudo: bool,
    ev: &mpsc::Sender<AppEvent>,
) -> String {
    if let Ok(Ok(s)) = tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
        return s.to_string();
    }
    if let Ok(pid) = std::fs::read_to_string(pid_file) {
        let pid = pid.trim().to_string();
        let _ = ev
            .send(AppEvent::Log(
                Source::Vpn,
                format!("openvpn still running, kill -TERM {pid}"),
            ))
            .await;
        let mut kill = if use_sudo {
            let mut c = Command::new("sudo");
            c.args(["-n", "kill", "-TERM", &pid]);
            c
        } else {
            let mut c = Command::new("kill");
            c.args(["-TERM", &pid]);
            c
        };
        let _ = kill.status().await;
    }
    match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
        Ok(Ok(s)) => s.to_string(),
        _ => "did not exit; check `pgrep openvpn`".into(),
    }
}

fn pipe_lines<R: tokio::io::AsyncRead + Unpin + Send + 'static>(
    r: Option<R>,
    ev: mpsc::Sender<AppEvent>,
) {
    let Some(r) = r else { return };
    tokio::spawn(async move {
        let mut lines = BufReader::new(r).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let line = redact_log(&line);
            if line.contains("auth-token") {
                let _ = ev.send(AppEvent::Mgmt(Notification::AuthToken)).await;
            }
            if ev.send(AppEvent::Log(Source::OpenVpn, line)).await.is_err() {
                break;
            }
        }
    });
}

/// Hides `auth-token <value>` in pushed-option log lines.
fn redact_log(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(i) = rest.find("auth-token ") {
        let start = i + "auth-token ".len();
        out.push_str(&rest[..start]);
        out.push_str("[redacted]");
        let end = rest[start..]
            .find([',', '\'', ' '])
            .map(|e| start + e)
            .unwrap_or(rest.len());
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

fn make_run_dir() -> anyhow::Result<RunDir> {
    let path = std::env::temp_dir().join(format!("ghvpn-tui-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .with_context(|| format!("creating {}", path.display()))?;
    Ok(RunDir(path))
}

fn write_private(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    Ok(())
}

fn random_hex(n: usize) -> anyhow::Result<String> {
    use std::io::Read;
    let mut buf = vec![0u8; n];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

fn free_port() -> anyhow::Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Requires Linux with OpenVPN and ca-certificates; never sends VPN credentials.
    #[tokio::test]
    #[ignore]
    async fn startup_with_real_openvpn() -> anyhow::Result<()> {
        let dir = make_run_dir()?;
        let password = random_hex(16)?;
        let pw_file = dir.0.join("mgmt.pw");
        write_private(&pw_file, format!("{password}\n").as_bytes())?;
        let port = free_port()?;
        let mut child = Command::new("openvpn")
            .args([
                "--client",
                "--dev",
                "null",
                "--proto",
                "tcp-client",
                "--remote",
                "127.0.0.1",
                "9",
                "--ca",
                "/etc/ssl/certs/ISRG_Root_X1.pem",
                "--auth-user-pass",
                "--management",
                "127.0.0.1",
            ])
            .arg(port.to_string())
            .arg(&pw_file)
            .args(["--management-hold", "--management-query-passwords"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let stream = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(status) = child.try_wait()? {
                    bail!("test OpenVPN exited: {status}");
                }
                if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
                    return anyhow::Ok(stream);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await??;
        let (rd, mut wr) = stream.into_split();
        let mut lines = BufReader::new(rd).lines();
        let (ev, _rx) = mpsc::channel(32);
        wr.write_all(format!("{password}\n").as_bytes()).await?;
        release_startup_hold(&mut lines, &mut wr, &ev, Duration::from_secs(5)).await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(line) = lines.next_line().await? {
                if matches!(
                    ghvpn_mgmt::parse_line(&line),
                    Line::Notification(Notification::NeedAuth { .. })
                ) {
                    return anyhow::Ok(());
                }
            }
            bail!("OpenVPN closed without requesting credentials");
        })
        .await??;
        child.kill().await?;
        Ok(())
    }

    #[tokio::test]
    async fn startup_waits_for_hold_before_sending_commands() {
        let (client, server) = tokio::io::duplex(4096);
        let (rd, mut wr) = tokio::io::split(client);
        let mut lines = BufReader::new(rd).lines();
        let (ev, _rx) = mpsc::channel(16);
        let server = tokio::spawn(async move {
            let (rd, mut wr) = tokio::io::split(server);
            let mut lines = BufReader::new(rd).lines();
            wr.write_all(b"ENTER PASSWORD:SUCCESS: password is correct\r\n>INFO:ready\r\n")
                .await
                .unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(20), lines.next_line())
                    .await
                    .is_err()
            );
            wr.write_all(b">HOLD:Waiting for hold release:0\r\n")
                .await
                .unwrap();
            for expected in ["state on", "bytecount 2", "hold release"] {
                assert_eq!(lines.next_line().await.unwrap().as_deref(), Some(expected));
            }
        });
        release_startup_hold(&mut lines, &mut wr, &ev, Duration::from_secs(2))
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn startup_reports_management_errors_and_early_close() {
        for (message, expected) in [
            ("ERROR: bad management password\n", "startup failed"),
            (">FATAL:startup failed\n", "startup failed"),
            ("", "closed before startup hold"),
        ] {
            let (client, mut server) = tokio::io::duplex(4096);
            server.write_all(message.as_bytes()).await.unwrap();
            server.shutdown().await.unwrap();
            let (rd, mut wr) = tokio::io::split(client);
            let mut lines = BufReader::new(rd).lines();
            let (ev, _rx) = mpsc::channel(16);
            let err = release_startup_hold(&mut lines, &mut wr, &ev, Duration::from_secs(2))
                .await
                .unwrap_err();
            assert!(err.to_string().contains(expected), "{err:#}");
        }
    }

    #[tokio::test]
    async fn startup_times_out_if_hold_never_arrives() {
        let (client, mut server) = tokio::io::duplex(4096);
        server
            .write_all(b"SUCCESS: password is correct\n")
            .await
            .unwrap();
        let (rd, mut wr) = tokio::io::split(client);
        let mut lines = BufReader::new(rd).lines();
        let (ev, _rx) = mpsc::channel(16);
        let err = release_startup_hold(&mut lines, &mut wr, &ev, Duration::from_millis(20))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err:#}");
    }

    #[test]
    fn redacts_auth_token() {
        assert_eq!(
            redact_log("PUSH: Received control message: 'PUSH_REPLY,auth-token SESS_abc,ping 10'"),
            "PUSH: Received control message: 'PUSH_REPLY,auth-token [redacted],ping 10'"
        );
        assert_eq!(redact_log("auth-token xyz"), "auth-token [redacted]");
        assert_eq!(redact_log("nothing here"), "nothing here");
    }
}
