//! Downloads the OpenVPN client config from the Sophos Firewall VPN portal (SFOS 20+).
//!
//! Same calls the portal's own JavaScript makes:
//! `POST /api/v1/vpnportal/login` then `GET /api/v1/vpnportal/sslvpn/generic-config`.

use anyhow::{bail, Context};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

pub struct Portal<'a> {
    /// IP or hostname of the firewall.
    pub gateway: &'a str,
    /// Hostname on the portal's TLS certificate. When set, the request goes to `gateway`
    /// but the certificate is verified against this name. When unset the certificate is
    /// not verified (it never matches a bare IP).
    pub host: Option<&'a str>,
    pub port: u16,
}

pub struct Fetched {
    pub ovpn: String,
    pub tls_verified: bool,
    /// Login answered 299, which the portal uses to start OTP token enrolment.
    pub otp_enrolment: bool,
}

impl Portal<'_> {
    pub async fn fetch_config(&self, user: &str, password: &str) -> anyhow::Result<Fetched> {
        let mut builder = reqwest::Client::builder()
            .cookie_store(true)
            .timeout(Duration::from_secs(20))
            .user_agent(crate::USER_AGENT);
        let (base, tls_verified) = match self.host.filter(|h| !h.is_empty()) {
            Some(host) => {
                if let Ok(ip) = self.gateway.parse::<IpAddr>() {
                    builder = builder.resolve(host, SocketAddr::new(ip, self.port));
                }
                (format!("https://{host}:{}", self.port), true)
            }
            None => {
                builder = builder.danger_accept_invalid_certs(true);
                (format!("https://{}:{}", self.gateway, self.port), false)
            }
        };
        let client = builder.build()?;

        let body = serde_json::json!({ "username": user, "password": password }).to_string();
        let resp = client
            .post(format!("{base}/api/v1/vpnportal/login"))
            .header("Content-Type", "application/json; charset=utf-8")
            .header("X-Requested-With", "XMLHttpRequest")
            .body(body)
            .send()
            .await
            .with_context(|| format!("portal login request to {base}"))?;
        let status = resp.status().as_u16();
        if status != 200 && status != 299 {
            let text = resp.text().await.unwrap_or_default();
            bail!("portal login failed: HTTP {status} {}", snippet(&text));
        }

        let resp = client
            .get(format!("{base}/api/v1/vpnportal/sslvpn/generic-config"))
            .header("X-Requested-With", "XMLHttpRequest")
            .send()
            .await
            .context("config download request")?;
        let dl_status = resp.status();
        let ovpn = resp.text().await.unwrap_or_default();
        let _ = client
            .post(format!("{base}/api/v1/vpnportal/logout"))
            .send()
            .await;

        if !dl_status.is_success() {
            bail!(
                "config download failed: HTTP {dl_status} {}",
                snippet(&ovpn)
            );
        }
        if !ovpn.lines().any(|l| l.trim_start().starts_with("remote ")) {
            bail!(
                "portal returned something that is not an OpenVPN config: {}",
                snippet(&ovpn)
            );
        }
        Ok(Fetched {
            ovpn,
            tls_verified,
            otp_enrolment: status == 299,
        })
    }
}

fn snippet(s: &str) -> String {
    let s: String = s.chars().filter(|c| !c.is_control()).take(160).collect();
    if s.is_empty() {
        "(empty body)".into()
    } else {
        s
    }
}
