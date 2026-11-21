//! Rewrites a Sophos `.ovpn` so credentials only flow through the management interface
//! and routing follows the selected [`RouteMode`].

use anyhow::bail;
use std::net::Ipv4Addr;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMode {
    /// `route-nopull` plus routes for GitHub's published IPv4 ranges only.
    Github,
    /// `redirect-gateway def1`: everything goes through the tunnel.
    Full,
    /// Whatever the server pushes, untouched.
    Pushed,
}

impl RouteMode {
    pub const ALL: [RouteMode; 3] = [RouteMode::Github, RouteMode::Full, RouteMode::Pushed];

    pub fn name(self) -> &'static str {
        match self {
            RouteMode::Github => "github",
            RouteMode::Full => "full",
            RouteMode::Pushed => "pushed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.name() == s)
    }
}

pub struct PatchOpts<'a> {
    pub gateway: Option<&'a str>,
    pub port: Option<u16>,
    pub proto: Option<&'a str>,
    pub route_mode: RouteMode,
    /// (network, prefix length)
    pub routes: &'a [(Ipv4Addr, u8)],
    pub mgmt_port: u16,
    pub mgmt_pw_file: &'a Path,
    pub pid_file: &'a Path,
    pub legacy_tls: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OvpnInfo {
    /// `host port proto` of the remotes in the original file.
    pub remotes: Vec<String>,
    pub cipher: Option<String>,
    pub reneg_sec: Option<String>,
    pub has_cert: bool,
    pub has_key: bool,
}

/// Directives dropped from the original because the harness sets them (or they would
/// bypass the management interface).
const DROPPED: &[&str] = &[
    "auth-user-pass",
    "auth-retry",
    "auth-nocache",
    "management",
    "management-query-passwords",
    "management-hold",
    "management-client-user",
    "script-security",
    "up",
    "down",
    "daemon",
    "log",
    "log-append",
    "writepid",
    "verb",
    "reneg-sec",
    "data-ciphers",
    "data-ciphers-fallback",
];

/// Directives dropped only when the harness controls routing.
const ROUTING: &[&str] = &["redirect-gateway", "route-nopull"];

pub fn patch(input: &str, opts: &PatchOpts) -> anyhow::Result<(String, OvpnInfo)> {
    let mut info = OvpnInfo::default();
    let mut out = String::with_capacity(input.len() + 4096);
    let mut inline: Option<String> = None;
    let mut first_remote: Option<(String, Option<String>)> = None;

    for raw in input.lines() {
        let line = raw.trim();
        if let Some(tag) = &inline {
            if line == format!("</{tag}>") {
                inline = None;
            }
            out.push_str(raw);
            out.push('\n');
            continue;
        }
        if let Some(tag) = line.strip_prefix('<').and_then(|l| l.strip_suffix('>')) {
            if !tag.starts_with('/') {
                match tag {
                    "cert" => info.has_cert = true,
                    "key" => info.has_key = true,
                    _ => {}
                }
                inline = Some(tag.to_string());
                out.push_str(raw);
                out.push('\n');
                continue;
            }
        }
        let mut words = line.split_whitespace();
        let Some(directive) = words
            .next()
            .filter(|d| !d.starts_with('#') && !d.starts_with(';'))
        else {
            out.push_str(raw);
            out.push('\n');
            continue;
        };
        let args: Vec<&str> = words.collect();
        match directive {
            "remote" => {
                info.remotes.push(args.join(" "));
                if first_remote.is_none() {
                    first_remote = Some((
                        args.get(1).unwrap_or(&"").to_string(),
                        args.get(2).map(|p| p.to_string()),
                    ));
                }
                if opts.gateway.is_some() {
                    continue;
                }
            }
            "cipher" => info.cipher = args.first().map(|c| c.to_string()),
            "reneg-sec" => info.reneg_sec = args.first().map(|c| c.to_string()),
            _ => {}
        }
        if DROPPED.contains(&directive)
            || (opts.route_mode != RouteMode::Pushed && ROUTING.contains(&directive))
        {
            out.push_str("# [ghvpn-tui removed] ");
            out.push_str(if directive == "auth-user-pass" && !args.is_empty() {
                "auth-user-pass <file>"
            } else {
                line
            });
            out.push('\n');
            continue;
        }
        out.push_str(raw);
        out.push('\n');
    }
    if inline.is_some() {
        anyhow::bail!("unterminated inline block in .ovpn");
    }
    if info.remotes.is_empty() && opts.gateway.is_none() {
        anyhow::bail!("no `remote` in .ovpn and no gateway given");
    }

    out.push_str("\n# --- ghvpn-tui overrides ---\n");
    if let Some(gw) = opts.gateway {
        let (port, proto) = first_remote.unwrap_or_default();
        let port = opts
            .port
            .map(|p| p.to_string())
            .unwrap_or(if port.is_empty() { "8443".into() } else { port });
        let proto = opts.proto.map(str::to_string).or(proto);
        out.push_str(&format!(
            "remote {gw} {port}{}\n",
            proto.map(|p| format!(" {p}")).unwrap_or_default()
        ));
    }
    out.push_str("auth-user-pass\nauth-retry interact\nauth-nocache\n");
    out.push_str(&format!(
        "management 127.0.0.1 {} {}\n",
        opts.mgmt_port,
        opts.mgmt_pw_file.display()
    ));
    out.push_str("management-query-passwords\nmanagement-hold\n");
    out.push_str("script-security 1\n");
    out.push_str(&format!("writepid {}\n", opts.pid_file.display()));
    out.push_str("pull-filter ignore \"dhcp-option DOMAIN-SEARCH\"\n");
    let mut ciphers = String::from("AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305");
    if let Some(c) = &info.cipher {
        if !ciphers.split(':').any(|x| x.eq_ignore_ascii_case(c)) {
            ciphers.push(':');
            ciphers.push_str(c);
        }
        out.push_str(&format!(
            "data-ciphers {ciphers}\ndata-ciphers-fallback {c}\n"
        ));
    } else {
        out.push_str(&format!("data-ciphers {ciphers}\n"));
    }
    out.push_str("reneg-sec 0\nverb 3\n");
    if opts.legacy_tls {
        out.push_str("tls-cipher \"DEFAULT:@SECLEVEL=0\"\n");
    }
    match opts.route_mode {
        RouteMode::Pushed => {}
        RouteMode::Full => out.push_str("redirect-gateway def1\n"),
        RouteMode::Github => {
            out.push_str("route-nopull\npull-filter ignore \"redirect-gateway\"\n");
            for (net, prefix) in opts.routes {
                out.push_str(&format!("route {net} {}\n", prefix_to_mask(*prefix)));
            }
        }
    }
    Ok((out, info))
}

/// Accept only plain client directives, so a profile cannot run scripts or plugins as root.
pub fn validate_profile(text: &str) -> anyhow::Result<()> {
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

pub fn prefix_to_mask(prefix: u8) -> Ipv4Addr {
    let bits = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32) as u32)
    };
    Ipv4Addr::from(bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "client
dev tun
proto tcp
remote vpn.example.com 8443
remote 10.0.0.1 8443
cipher AES-128-CBC
auth-user-pass /etc/creds.txt
redirect-gateway def1
reneg-sec 3600
<ca>
-----BEGIN CERTIFICATE-----
auth-user-pass inside-a-block-is-data
-----END CERTIFICATE-----
</ca>
<cert>
x
</cert>
<key>
y
</key>
route remote_host 255.255.255.255 net_gateway
";

    fn opts<'a>(routes: &'a [(Ipv4Addr, u8)], mode: RouteMode) -> PatchOpts<'a> {
        PatchOpts {
            gateway: Some("203.0.113.10"),
            port: None,
            proto: None,
            route_mode: mode,
            routes,
            mgmt_port: 7505,
            mgmt_pw_file: Path::new("/tmp/x/mgmt.pw"),
            pid_file: Path::new("/tmp/x/openvpn.pid"),
            legacy_tls: false,
        }
    }

    #[test]
    fn patch_github_mode() {
        let routes = [(Ipv4Addr::new(140, 82, 112, 0), 20)];
        let (out, info) = patch(SAMPLE, &opts(&routes, RouteMode::Github)).unwrap();
        assert_eq!(info.remotes, vec!["vpn.example.com 8443", "10.0.0.1 8443"]);
        assert_eq!(info.cipher.as_deref(), Some("AES-128-CBC"));
        assert_eq!(info.reneg_sec.as_deref(), Some("3600"));
        assert!(info.has_cert && info.has_key);
        assert!(!out.contains("/etc/creds.txt"));
        assert!(out.contains("auth-user-pass inside-a-block-is-data"));
        assert!(out.contains("remote 203.0.113.10 8443\n"));
        assert!(!out.contains("\nremote vpn.example.com"));
        assert!(out.contains("# [ghvpn-tui removed] redirect-gateway def1"));
        assert!(out.contains("management 127.0.0.1 7505 /tmp/x/mgmt.pw\n"));
        assert!(out.contains("data-ciphers-fallback AES-128-CBC\n"));
        assert!(
            out.contains("data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC\n")
        );
        assert!(out.contains("route-nopull\n"));
        assert!(out.contains("route 140.82.112.0 255.255.240.0\n"));
        assert!(out.contains("route remote_host 255.255.255.255 net_gateway\n"));
    }

    #[test]
    fn patch_pushed_mode_keeps_routing() {
        let (out, _) = patch(SAMPLE, &opts(&[], RouteMode::Pushed)).unwrap();
        assert!(out.contains("\nredirect-gateway def1\n"));
        assert!(!out.contains("route-nopull"));
    }

    #[test]
    fn port_and_proto_override() {
        let mut o = opts(&[], RouteMode::Full);
        o.port = Some(1194);
        o.proto = Some("udp");
        let (out, _) = patch(SAMPLE, &o).unwrap();
        assert!(out.contains("remote 203.0.113.10 1194 udp\n"));
        assert!(out.ends_with("redirect-gateway def1\n"));
    }

    #[test]
    fn unterminated_block_is_rejected() {
        assert!(patch(
            "client\nremote a 1\n<ca>\nxx\n",
            &opts(&[], RouteMode::Full)
        )
        .is_err());
    }

    #[test]
    fn masks() {
        assert_eq!(prefix_to_mask(0), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(prefix_to_mask(20), Ipv4Addr::new(255, 255, 240, 0));
        assert_eq!(prefix_to_mask(32), Ipv4Addr::new(255, 255, 255, 255));
    }
}
