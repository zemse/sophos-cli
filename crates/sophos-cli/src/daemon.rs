//! Privileged supervisor and private control socket.

mod engine;

use crate::config::{Config, Secret};
use crate::ipc::{read_frame, Reply, Request, Status};
use anyhow::{bail, Context};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

pub(super) struct Credentials {
    username: String,
    password: Secret,
}

pub(super) enum Control {
    Connect(Credentials),
    Reconnect,
    Disconnect,
    Stop,
}

struct SocketGuard {
    path: PathBuf,
    inode: u64,
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.file_type().is_socket() && m.ino() == self.inode)
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn chown(path: &Path, uid: u32) -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    if unsafe { libc::chown(path.as_ptr(), uid, u32::MAX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

async fn bind(path: &Path, operator: u32) -> anyhow::Result<(UnixListener, SocketGuard)> {
    use std::os::unix::ffi::OsStrExt;
    if !path.is_absolute() || path.as_os_str().as_bytes().len() > 100 {
        bail!("control socket needs a short absolute path");
    }
    let parent = path.parent().context("socket needs a directory")?;
    if !parent.exists() {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        chown(parent, operator)?;
    }
    let meta = fs::symlink_metadata(parent)?;
    if !meta.is_dir() || meta.uid() != operator || meta.mode() & 0o077 != 0 {
        bail!("socket directory must be private (0700) and owned by operator_uid");
    }
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() || (meta.uid() != operator && meta.uid() != 0) {
                bail!("refusing to replace non-socket or foreign control path");
            }
            match UnixStream::connect(path).await {
                Ok(_) => bail!("daemon is already running"),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                    ) =>
                {
                    fs::remove_file(path)?
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let listener = UnixListener::bind(path)?;
    let guard = SocketGuard {
        path: path.to_owned(),
        inode: fs::symlink_metadata(path)?.ino(),
    };
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    chown(path, operator)?;
    Ok((listener, guard))
}

async fn serve(
    mut stream: UnixStream,
    operator: u32,
    config: Arc<Config>,
    tx: mpsc::Sender<Control>,
    status: watch::Receiver<Status>,
) -> anyhow::Result<()> {
    let uid = stream.peer_cred()?.uid();
    if uid != operator && uid != 0 {
        bail!("unauthorised control peer");
    }
    let bytes = read_frame(&mut stream).await?;
    let request: Request =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid control request"))?;
    let mut reply = Reply {
        ok: true,
        status: status.borrow().clone(),
        need_username: config.username.as_ref().is_none_or(|s| s.is_empty()),
        need_password: config
            .password
            .as_ref()
            .is_none_or(|s| s.expose().is_empty()),
        error: None,
    };
    let control = match request {
        Request::Requirements | Request::Status => None,
        Request::Connect { username, password } => {
            let username = username.or_else(|| config.username.clone());
            let password = password.or_else(|| config.password.as_ref().map(Secret::duplicate));
            match (username, password) {
                (Some(username), Some(password))
                    if !username.is_empty() && !password.expose().is_empty() =>
                {
                    if ghvpn_mgmt::quote(&username).is_err()
                        || ghvpn_mgmt::quote(password.expose()).is_err()
                    {
                        reply.ok = false;
                        reply.error =
                            Some("credentials contain unsupported control characters".into());
                        None
                    } else {
                        Some(Control::Connect(Credentials { username, password }))
                    }
                }
                _ => {
                    reply.ok = false;
                    reply.error = Some("missing login credentials".into());
                    None
                }
            }
        }
        Request::Reconnect => Some(Control::Reconnect),
        Request::Disconnect => Some(Control::Disconnect),
        Request::Stop => Some(Control::Stop),
    };
    if let Some(control) = control {
        tx.send(control).await.context("supervisor stopped")?;
    }
    let mut bytes = serde_json::to_vec(&reply)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    Ok(())
}

pub async fn run(config: Config, operator: u32, socket: PathBuf) -> anyhow::Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("daemon requires root for OpenVPN tunnel and routes");
    }
    let (listener, _guard) = bind(&socket, operator).await?;
    let config = Arc::new(config);
    let (tx, rx) = mpsc::channel(16);
    let (status_tx, mut status) = watch::channel(Status {
        state: "needs_credentials".into(),
        ..Status::default()
    });
    let mut engine = tokio::spawn(engine::run(config.clone(), operator, rx, status_tx));
    let mut handlers = JoinSet::new();
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut engine_finished = false;
    loop {
        tokio::select! {
            result = &mut engine => {
                engine_finished = true;
                result??;
                break;
            }
            _ = tokio::signal::ctrl_c() => { let _ = tx.send(Control::Stop).await; break; }
            _ = terminate.recv() => { let _ = tx.send(Control::Stop).await; break; }
            accepted = listener.accept(), if handlers.len() < 16 => {
                let (stream, _) = accepted?;
                let (config, tx, status) = (config.clone(), tx.clone(), status.clone());
                handlers.spawn(async move {
                    // Requests and errors are deliberately not logged: they can contain secrets.
                    let _ = tokio::time::timeout(Duration::from_secs(5), serve(stream, operator, config, tx, status)).await;
                });
            }
            _ = handlers.join_next(), if !handlers.is_empty() => {}
            changed = status.changed() => {
                if changed.is_err() || status.borrow().state == "stopped" { break; }
            }
        }
    }
    drop(listener);
    while handlers.join_next().await.is_some() {}
    let _ = tx.send(Control::Stop).await;
    if !engine_finished {
        engine.await??;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Arc<Config> {
        Arc::new(
            serde_json::from_str(
                r#"{
            "profile":"/public-test/profile.ovpn",
            "totp_seed":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        }"#,
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn private_ipc_reports_missing_fields_and_delivers_credentials() {
        let uid = unsafe { libc::geteuid() };
        for connect in [false, true] {
            let (mut client, server) = UnixStream::pair().unwrap();
            let (tx, mut rx) = mpsc::channel(1);
            let (_status_tx, status) = watch::channel(Status {
                state: "needs_credentials".into(),
                ..Status::default()
            });
            let task = tokio::spawn(serve(server, uid, config(), tx, status));
            let request = if connect {
                Request::Connect {
                    username: Some("public-test-user".into()),
                    password: Some(Secret::new("public-test-password".into())),
                }
            } else {
                Request::Requirements
            };
            let mut bytes = zeroize::Zeroizing::new(serde_json::to_vec(&request).unwrap());
            bytes.push(b'\n');
            client.write_all(&bytes).await.unwrap();
            let frame = read_frame(&mut client).await.unwrap();
            let reply: Reply = serde_json::from_slice(&frame).unwrap();
            assert!(reply.ok && reply.need_username && reply.need_password);
            task.await.unwrap().unwrap();
            if connect {
                let Some(Control::Connect(credentials)) = rx.recv().await else {
                    panic!("connect command missing");
                };
                assert_eq!(credentials.username, "public-test-user");
                assert_eq!(credentials.password.expose(), "public-test-password");
            }
        }
    }

    #[tokio::test]
    async fn private_ipc_rejects_foreign_peers() {
        let uid = unsafe { libc::geteuid() };
        if uid == 0 {
            return;
        }
        let (_client, server) = UnixStream::pair().unwrap();
        let (tx, _) = mpsc::channel(1);
        let (_status_tx, status) = watch::channel(Status::default());
        assert!(serve(server, uid.wrapping_add(1), config(), tx, status)
            .await
            .is_err());
    }
}
