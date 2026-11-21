//! Checks run against the network path: egress IP, GitHub API, `git ls-remote`, `git clone`.

use anyhow::{anyhow, Context};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// Environment variables used by the `GIT_ASKPASS` mode of this binary.
pub const ASKPASS_FLAG: &str = "GHVPN_ASKPASS";
pub const ASKPASS_USER: &str = "GHVPN_GIT_USER";
pub const ASKPASS_TOKEN: &str = "GHVPN_GIT_TOKEN";

#[derive(Debug, Clone)]
pub struct Outcome {
    pub ok: bool,
    pub summary: String,
}

impl Outcome {
    fn ok(s: impl Into<String>) -> Self {
        Self {
            ok: true,
            summary: s.into(),
        }
    }
    fn fail(s: impl Into<String>) -> Self {
        Self {
            ok: false,
            summary: s.into(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct GitCreds {
    pub user: String,
    pub token: String,
}

/// Public IP as seen by api.ipify.org. `pin` forces one of the given addresses, which
/// keeps the request on a host route that goes through the tunnel.
pub async fn egress_ip(pin: &[Ipv4Addr]) -> Outcome {
    let mut b = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(crate::USER_AGENT);
    if let Some(ip) = pin.first() {
        b = b.resolve(
            crate::routes::EGRESS_HOST,
            SocketAddr::new((*ip).into(), 443),
        );
    }
    let res = async {
        let text = b
            .build()?
            .get(format!("https://{}", crate::routes::EGRESS_HOST))
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        anyhow::Ok(text.trim().to_string())
    }
    .await;
    match res {
        Ok(ip) => Outcome::ok(ip),
        Err(e) => Outcome::fail(format!("{e:#}")),
    }
}

/// `https://github.com/<owner>/<repo>(.git)` → `(owner, repo)`.
pub fn parse_repo(url: &str) -> Option<(String, String)> {
    let rest = url
        .trim()
        .trim_end_matches('/')
        .split("github.com")
        .nth(1)?;
    let mut parts = rest.trim_start_matches([':', '/']).split('/');
    let owner = parts.next().filter(|s| !s.is_empty())?;
    let repo = parts.next()?.trim_end_matches(".git");
    (!repo.is_empty()).then(|| (owner.to_string(), repo.to_string()))
}

/// `GET /repos/{owner}/{repo}`. GitHub answers 403 with an "IP allow list" message when
/// the credentials are fine but the source IP is not allowed by the organisation.
pub async fn github_api(repo_url: &str, token: &str) -> Outcome {
    let Some((owner, repo)) = parse_repo(repo_url) else {
        return Outcome::fail(format!("cannot parse a GitHub repo from {repo_url:?}"));
    };
    let res = async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(crate::USER_AGENT)
            .build()?;
        let mut req = client
            .get(format!("https://api.github.com/repos/{owner}/{repo}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        if !token.is_empty() {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let body: serde_json::Value = serde_json::from_str(&resp.text().await?).unwrap_or_default();
        anyhow::Ok((status, body))
    }
    .await;
    let (status, body) = match res {
        Ok(r) => r,
        Err(e) => return Outcome::fail(format!("request failed: {e:#}")),
    };
    let msg = body
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();
    match status {
        200 => Outcome::ok(format!(
            "200 accessible: {} (private={}, default branch {})",
            body.get("full_name")
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
            body.get("private")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            body.get("default_branch")
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
        )),
        403 if msg.contains("IP allow list") => Outcome::fail(
            "403 blocked by the org IP allow list: credentials OK, egress IP not allowed",
        ),
        401 => Outcome::fail(format!("401 bad credentials: {msg}")),
        404 if token.is_empty() => Outcome::fail("404: private repo, no token given"),
        404 => Outcome::fail(
            "404: token cannot see this repo (wrong account, missing scope or SSO not authorised)",
        ),
        _ => Outcome::fail(format!("{status}: {msg}")),
    }
}

fn git_cmd(creds: &GitCreds) -> anyhow::Result<Command> {
    let mut cmd = Command::new("git");
    cmd.env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    if !creds.token.is_empty() {
        let exe = std::env::current_exe().context("locating own binary for GIT_ASKPASS")?;
        // An empty helper resets the list, so a keychain entry for another account can't win.
        cmd.args(["-c", "credential.helper="])
            .env("GIT_ASKPASS", exe)
            .env(ASKPASS_FLAG, "1")
            .env(
                ASKPASS_USER,
                if creds.user.is_empty() {
                    "x-access-token"
                } else {
                    &creds.user
                },
            )
            .env(ASKPASS_TOKEN, &creds.token);
    }
    Ok(cmd)
}

pub async fn git_ls_remote(repo_url: &str, creds: &GitCreds) -> Outcome {
    let run = async {
        let mut cmd = git_cmd(creds)?;
        cmd.args(["ls-remote", "--heads", "--tags", repo_url]);
        let out = tokio::time::timeout(Duration::from_secs(60), cmd.output())
            .await
            .map_err(|_| anyhow!("timed out after 60 s"))??;
        anyhow::Ok(out)
    };
    match run.await {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let refs = stdout.lines().count();
            let first = stdout.lines().next().unwrap_or("").replace('\t', " ");
            Outcome::ok(format!("ok, {refs} refs (first: {first})"))
        }
        Ok(out) => Outcome::fail(last_lines(&String::from_utf8_lossy(&out.stderr), 3)),
        Err(e) => Outcome::fail(format!("{e:#}")),
    }
}

pub async fn git_clone(repo_url: &str, creds: &GitCreds, clone_root: &Path) -> Outcome {
    let name = parse_repo(repo_url)
        .map(|(_, r)| r)
        .unwrap_or_else(|| "repo".into());
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let dest: PathBuf = clone_root.join(format!("{name}-{stamp}"));
    let run = async {
        tokio::fs::create_dir_all(clone_root).await?;
        let mut cmd = git_cmd(creds)?;
        cmd.args(["clone", "--quiet", "--depth", "1", repo_url])
            .arg(&dest);
        let out = tokio::time::timeout(Duration::from_secs(600), cmd.output())
            .await
            .map_err(|_| anyhow!("timed out after 600 s"))??;
        anyhow::Ok(out)
    };
    match run.await {
        Ok(out) if out.status.success() => Outcome::ok(format!("cloned into {}", dest.display())),
        Ok(out) => Outcome::fail(last_lines(&String::from_utf8_lossy(&out.stderr), 3)),
        Err(e) => Outcome::fail(format!("{e:#}")),
    }
}

fn last_lines(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
    let tail = lines[lines.len().saturating_sub(n)..].join(" | ");
    if tail.is_empty() {
        "failed with no output".into()
    } else {
        tail
    }
}

/// Entry point when this binary is invoked by git as `GIT_ASKPASS <prompt>`.
pub fn askpass_main() {
    let prompt = std::env::args().nth(1).unwrap_or_default();
    let var = if prompt.starts_with("Username") {
        ASKPASS_USER
    } else {
        ASKPASS_TOKEN
    };
    println!("{}", std::env::var(var).unwrap_or_default());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_urls() {
        let want = Some(("example-org".to_string(), "example-repo".to_string()));
        assert_eq!(
            parse_repo("https://github.com/example-org/example-repo"),
            want
        );
        assert_eq!(
            parse_repo("https://github.com/example-org/example-repo.git"),
            want
        );
        assert_eq!(
            parse_repo("https://github.com/example-org/example-repo/"),
            want
        );
        assert_eq!(
            parse_repo("git@github.com:example-org/example-repo.git"),
            want
        );
        assert_eq!(parse_repo("https://github.com/example-org"), None);
        assert_eq!(parse_repo("https://gitlab.com/a/b"), None);
    }
}

#[cfg(test)]
mod net_tests {
    use super::*;

    /// Hits the network: `cargo test -p ghvpn-tui -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn direct_baseline() {
        let repo = "https://github.com/example-org/example-repo";
        let ip = egress_ip(&[]).await;
        assert!(ip.ok, "{}", ip.summary);
        let api = github_api(repo, "").await;
        assert!(api.summary.starts_with("404"), "{}", api.summary);
        let public = github_api("https://github.com/rust-lang/rust", "").await;
        assert!(public.ok, "{}", public.summary);
        let ls = git_ls_remote(
            "https://github.com/rust-lang/rustlings",
            &GitCreds::default(),
        )
        .await;
        assert!(ls.ok, "{}", ls.summary);
        let ls = git_ls_remote(
            repo,
            &GitCreds {
                user: String::new(),
                token: "invalid".into(),
            },
        )
        .await;
        assert!(!ls.ok);
        eprintln!(
            "egress {} | private api: {} | bad-token ls-remote: {}",
            ip.summary, api.summary, ls.summary
        );
    }
}
