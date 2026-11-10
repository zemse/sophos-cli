//! Destinations routed into the tunnel in `github` route mode.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

/// Host used for the egress-IP check. IPv4-only, so it always matches a v4 host route.
pub const EGRESS_HOST: &str = "api.ipify.org";

/// Core GitHub ranges, used when <https://api.github.com/meta> can't be fetched.
const FALLBACK: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(140, 82, 112, 0), 20),
    (Ipv4Addr::new(143, 55, 64, 0), 20),
    (Ipv4Addr::new(185, 199, 108, 0), 22),
    (Ipv4Addr::new(192, 30, 252, 0), 22),
];

/// Returns the IPv4 ranges for GitHub's `web`, `api` and `git` services, and whether they
/// came from the live meta API (false = fallback list).
pub async fn github_ranges() -> (Vec<(Ipv4Addr, u8)>, bool) {
    match fetch_meta().await {
        Ok(r) if !r.is_empty() => (r, true),
        _ => (FALLBACK.to_vec(), false),
    }
}

async fn fetch_meta() -> anyhow::Result<Vec<(Ipv4Addr, u8)>> {
    let body = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(crate::USER_AGENT)
        .build()?
        .get("https://api.github.com/meta")
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    parse_meta(&body)
}

fn parse_meta(body: &str) -> anyhow::Result<Vec<(Ipv4Addr, u8)>> {
    let meta: serde_json::Value = serde_json::from_str(body)?;
    let mut out: Vec<(Ipv4Addr, u8)> = ["web", "api", "git"]
        .iter()
        .filter_map(|k| meta.get(*k)?.as_array())
        .flatten()
        .filter_map(|v| parse_cidr(v.as_str()?))
        .collect();
    out.sort();
    out.dedup();
    Ok(out)
}

fn parse_cidr(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip, prefix) = s.split_once('/')?;
    let ip: Ipv4Addr = ip.parse().ok()?;
    let prefix: u8 = prefix.parse().ok().filter(|p| *p <= 32)?;
    let mask = u32::from(crate::ovpn::prefix_to_mask(prefix));
    Some((Ipv4Addr::from(u32::from(ip) & mask), prefix))
}

/// IPv4 addresses of [`EGRESS_HOST`], to be host-routed through the tunnel and pinned
/// when probing, so the probe can't drift to an address outside the routes.
pub async fn egress_host_addrs() -> Vec<Ipv4Addr> {
    let Ok(addrs) = tokio::net::lookup_host((EGRESS_HOST, 443)).await else {
        return Vec::new();
    };
    let mut v: Vec<Ipv4Addr> = addrs
        .filter_map(|a| match a.ip() {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_parsing() {
        let body = r#"{"web":["140.82.112.0/20","2a0a:a440::/29","140.82.112.3/32"],
            "api":["140.82.112.0/20","20.201.28.148/32"],"git":["192.30.252.0/22"],"hooks":["1.2.3.0/24"]}"#;
        assert_eq!(
            parse_meta(body).unwrap(),
            vec![
                (Ipv4Addr::new(20, 201, 28, 148), 32),
                (Ipv4Addr::new(140, 82, 112, 0), 20),
                (Ipv4Addr::new(140, 82, 112, 3), 32),
                (Ipv4Addr::new(192, 30, 252, 0), 22),
            ]
        );
    }

    #[test]
    fn cidr_normalises_host_bits() {
        assert_eq!(
            parse_cidr("10.1.2.3/8"),
            Some((Ipv4Addr::new(10, 0, 0, 0), 8))
        );
        assert_eq!(parse_cidr("10.1.2.3/33"), None);
        assert_eq!(parse_cidr("::1/128"), None);
    }
}
