//! One-request-per-connection JSON protocol on a private Unix socket.

use crate::config::Secret;
use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

const MAX_FRAME: u64 = 8192;

#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Requirements,
    Connect {
        username: Option<String>,
        password: Option<Secret>,
    },
    Status,
    Reconnect,
    Disconnect,
    Stop,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Status {
    pub state: String,
    pub tunnel_ip: Option<String>,
    pub connected_since: Option<u64>,
    pub reconnects: u32,
    pub auth_failures: usize,
    pub last_error: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Reply {
    pub ok: bool,
    pub status: Status,
    pub need_username: bool,
    pub need_password: bool,
    pub error: Option<String>,
}

pub async fn read_frame<R: AsyncRead + Unpin>(reader: R) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    BufReader::new(reader.take(MAX_FRAME + 1))
        .read_until(b'\n', &mut bytes)
        .await?;
    if bytes.len() as u64 > MAX_FRAME || bytes.last() != Some(&b'\n') {
        bail!("invalid or oversized IPC frame");
    }
    Ok(bytes)
}

pub async fn call(path: &Path, request: Request) -> anyhow::Result<Reply> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut stream = UnixStream::connect(path)
            .await
            .context("connecting to daemon; start sophos daemon first")?;
        let peer = stream.peer_cred()?.uid();
        if peer != 0 && peer != unsafe { libc::geteuid() } {
            bail!("control socket belongs to another user");
        }
        let mut bytes = Zeroizing::new(serde_json::to_vec(&request)?);
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_FRAME {
            bail!("request exceeds IPC size limit");
        }
        stream.write_all(&bytes).await?;
        let bytes = read_frame(&mut stream).await?;
        serde_json::from_slice(&bytes).context("invalid daemon reply")
    })
    .await
    .context("daemon request timed out")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn framing_requires_newline_and_bounds_size() {
        assert!(read_frame(&b"{}\n"[..]).await.is_ok());
        assert!(read_frame(&b"{}"[..]).await.is_err());
        assert!(read_frame(vec![b'x'; MAX_FRAME as usize + 1].as_slice())
            .await
            .is_err());
    }

    #[test]
    fn status_contains_no_credentials() {
        let status = serde_json::to_string(&Status::default()).unwrap();
        for field in ["password", "seed", "otp", "username"] {
            assert!(!status.contains(field));
        }
        assert!(serde_json::from_str::<Request>(
            "{\"command\":\"status\",\"password\":\"public-test\"}"
        )
        .is_err());
    }
}
