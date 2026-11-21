# SPEC: `ghvpn` — GitHub-over-Sophos-VPN gateway for an EC2 instance

Version: 0.1 (draft)
Language: Rust (stable, edition 2021)
Target host: Linux EC2 instance (Ubuntu 24.04 LTS or Amazon Linux 2023, x86_64 or arm64)

---

## 1. Goal

Let a headless EC2 instance run `git clone / fetch / pull / push` (HTTPS and SSH) and GitHub API calls against an
organisation that only accepts traffic from the company's Sophos firewall egress IP (most likely a GitHub
Enterprise Cloud **IP allow list**). Only GitHub traffic goes through the company's Sophos SSL VPN (OpenVPN).
All other traffic from the instance keeps using the normal EC2 network path.

The VPN requires **username + password + 6-digit MFA code (TOTP)**. The code is entered in the same field as the
password, with no separator: `<password><otp>`.

### Non-goals
- Re-implementing the OpenVPN protocol. We drive the stock `openvpn` 2.6 binary.
- Supporting Sophos Connect IPsec (IKEv1/XAUTH) or Entra ID SSO login. Both are out of scope (see §11).
- Routing any non-GitHub traffic through the VPN.

---

## 2. Prerequisites (must be verified before writing code)

| # | Check | How | If it fails |
|---|---|---|---|
| P1 | The user has an **SSL VPN** policy and can download a personal `.ovpn` | Sign in to the Sophos VPN portal (`https://<fw>` on SFOS 20+, or the user portal on older firmware) → VPN → download "OpenVPN Connect v3" config | Ask IT to add the user to an SSL VPN policy. Stop. |
| P2 | Portal and VPN login use password + OTP, **not Entra ID SSO only** | The portal shows username/password/OTP fields, not just an SSO button | Out of scope. Stop. |
| P3 | No "Block clients with no heartbeat" rule applies to VPN users | Ask IT | The tunnel will come up but pass no traffic. Stop. |
| P4 | The firewall allows **VPN zone → WAN** with SNAT (so GitHub sees the company IP) | After a manual `openvpn` connect with `redirect-gateway def1`: `curl --interface tun0 https://ifconfig.me` returns the company IP | Ask IT for a VPN→WAN rule (it can be scoped to GitHub ranges). Stop. |
| P5 | The EC2 security group allows outbound traffic to the firewall's `remote` host/port/proto from the `.ovpn` | Read the `remote` and `proto` lines | Open the egress rule. |
| P6 | **IT has approved using this account and VPN profile from a cloud server** | Written confirmation | Do not deploy. A cloud instance is a new endpoint holding company credentials and a client private key. |

Manual smoke test (P1 + P4):
```bash
sudo openvpn --config sophos.ovpn --redirect-gateway def1 --data-ciphers-fallback AES-256-CBC
# username: <user>   password: <password><otp>
```

---

## 3. Architecture

```
┌──────────────────────────── EC2 instance ────────────────────────────────┐
│                                                                          │
│  git / gh / curl ──► 127.0.0.1:1080 (SOCKS5)   ──┐                       │
│  ssh (ProxyCommand: ghvpn ssh-proxy) ────────────┤                       │
│  ghvpn CLI ──► /run/ghvpn/ctl.sock (control API) ┤                       │
│                                                  │                       │
│  ┌──────────── network namespace "ghvpn" ────────▼────────────────────┐  │
│  │  ghvpnd (daemon, Rust)                                             │  │
│  │   ├─ supervises `openvpn` child (management iface on unix socket)  │  │
│  │   ├─ SOCKS5 + HTTP CONNECT proxy, GitHub-host allowlist            │  │
│  │   └─ health checker (egress IP, git ls-remote)                     │  │
│  │  tun0 ── default route (full tunnel, inside the namespace only)    │  │
│  │  veth-gh1 10.200.0.2/30 ── underlay route to the Sophos gateway    │  │
│  └──────────────┬─────────────────────────────────────────────────────┘  │
│        veth-gh0 10.200.0.1/30  (host side, MASQUERADE to ens5)           │
└──────────────────────────────────────────────────────────────────────────┘
```

Why a network namespace:
- Inside the namespace the VPN can be a **full tunnel**, so all of GitHub's changing IP ranges and CDNs are
  covered without maintaining route lists.
- The host routing table, DNS and SSH access to the instance are never touched. A broken VPN cannot lock you
  out of the box.
- No Docker dependency. (A Docker variant is allowed as an alternative build target. See §12.)

### Processes
| Binary | Runs as | Purpose |
|---|---|---|
| `ghvpnd` | root (systemd), needs `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` for netns | Namespace setup, openvpn supervision, proxy, control API |
| `ghvpn` | any user in the `ghvpn` group | CLI: `up`, `otp`, `down`, `status`, `ssh-proxy`, `doctor`, `git-setup` |
| `openvpn` | spawned by `ghvpnd` inside the netns | The actual tunnel |

---

## 4. Network setup (performed by `ghvpnd` at start, torn down at stop)

Implement these steps with the `rtnetlink` / `nix` crates, or by shelling out to `ip` and `nft`/`iptables` behind
a `NetOps` trait so they can be tested.

1. `ip netns add ghvpn`
2. `ip link add veth-gh0 type veth peer name veth-gh1`; move `veth-gh1` into `ghvpn`.
3. Host: `veth-gh0` = `10.200.0.1/30`, up. Netns: `veth-gh1` = `10.200.0.2/30`, `lo` up, default route via `10.200.0.1`.
4. Host: `sysctl net.ipv4.ip_forward=1`; NAT rule `10.200.0.0/30 → MASQUERADE` on the primary interface.
   Only allow forwarding from `veth-gh0` to the Sophos gateway `remote` IP(s) and port (resolved from the `.ovpn`).
5. Netns DNS: write `/etc/netns/ghvpn/resolv.conf`. Before the tunnel is up, use the VPC resolver (`169.254.169.253`).
   Once the tunnel is up, use VPN-pushed DNS if present, otherwise `1.1.1.1`. DNS for proxied requests is resolved
   **by the proxy inside the namespace** (clients use `socks5h`).
6. Expose the proxy to the host. The daemon's proxy socket is created **inside** the netns, bound to
   `10.200.0.2:1080`. The host-side `ghvpnd` thread (still in the host netns) runs a tiny TCP forwarder
   `127.0.0.1:1080 → 10.200.0.2:1080`.
   Simplest implementation: the daemon opens the listening socket while in the host netns, then calls
   `setns()` for the worker threads that dial upstream. Either approach is acceptable. Document the one chosen.
7. Teardown is idempotent: delete the netns, veth and NAT rules, even after a crash (run teardown at start too).

---

## 5. OpenVPN supervision

### 5.1 Config handling
- Load the `.ovpn` (contains the CA, client certificate and **private key**). Store it in AWS Secrets Manager
  (see §7). Materialise it only to a `0600` file under `/run/ghvpn/` (tmpfs) and delete it on stop.
- Append these overrides (later directives win in OpenVPN):
  ```
  redirect-gateway def1          # full tunnel, inside netns only
  pull-filter ignore "dhcp-option DOMAIN-SEARCH"
  auth-retry interact            # ask the management interface again on auth failure
  auth-nocache
  management /run/ghvpn/mgmt.sock unix
  management-query-passwords
  management-hold
  management-client-user root
  script-security 1
  data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC
  data-ciphers-fallback AES-256-CBC   # only if the .ovpn's `cipher` line names it; use the .ovpn's value
  verb 3
  ```
- Remove any `auth-user-pass <file>` argument so credentials come **only** through the management interface.
- Spawn `ip netns exec ghvpn openvpn --config /run/ghvpn/client.ovpn`. Capture stdout/stderr into `tracing` logs.

### 5.2 Management-interface client
Connect to `/run/ghvpn/mgmt.sock`. The protocol is line-based. Lines starting with `>` are asynchronous notifications.

On connect, send:
```
state on
bytecount 30
hold release
```

Handle:
| Notification | Action |
|---|---|
| `>PASSWORD:Need 'Auth' username/password` | If a **fresh OTP** is available (see §6), send `username "Auth" <user>` and then `password "Auth" <password><otp>`. Mark that OTP as consumed. Otherwise move to state `NEEDS_OTP` and wait. |
| `>PASSWORD:Verification Failed: 'Auth'` | Increment `auth_failures`. Move to `NEEDS_OTP`. **Never retry with the same OTP.** If `auth_failures >= 3` within 15 min, move to `LOCKED_OUT_GUARD` and refuse automatic attempts for 15 min (to avoid an account lockout on the firewall). |
| `>STATE:<ts>,CONNECTED,SUCCESS,<ip>,...` | State `CONNECTED`. Run the post-connect health check (§8). |
| `>STATE:...,RECONNECTING,...` / `EXITING` | State `RECONNECTING`. Expect a password prompt. |
| `>BYTECOUNT:in,out` | Update metrics. |
| `>FATAL:` | State `FAILED`. Restart openvpn with backoff (5 s → 5 min). |

Quoting: in `username`/`password` commands, escape `\` as `\\` and `"` as `\"`. Redact both from all logs.

### 5.3 Renegotiation and MFA
OpenVPN renegotiates the TLS session every `reneg-sec` seconds (default 3600; the server value usually wins). With
`auth-user-pass` the client re-sends credentials on renegotiation, and a used OTP will be rejected. Requirements:
- At startup, read `reneg-sec` from the `.ovpn` and log it. Set the client to `reneg-sec 0` (the server may override).
- If the server pushes `auth-token`, OpenVPN reuses the token instead of the password. Detect it (a log line
  containing `auth-token`) and report `session_token: yes|no` in `status`.
- If no token is pushed, every renegotiation and reconnect triggers `NEEDS_OTP`. The daemon must keep the existing
  tunnel state, notify the user (§9), and wait for `ghvpn otp <code>`.

---

## 6. MFA code sources

Implement a `OtpSource` trait with these implementations, chosen by config:

1. **`manual` (default)**: the code arrives through `ghvpn up --otp 123456` or `ghvpn otp 123456` over the control
   socket. It is valid for **30 s** after receipt and used **at most once**.
2. **`stdin`**: `ghvpn up` prompts on the TTY (no echo).
3. **`totp-secret` (off by default; needs explicit IT approval)**: generate RFC 6238 codes from a Base32 seed stored
   in Secrets Manager (`totp-rs` crate, SHA1, 6 digits, 30 s step).
   - The config must set `i_have_it_approval = true` or the daemon refuses to start in this mode.
     Storing the seed next to the password on the same server turns 2FA into a single factor.
   - Never send the same time-step code twice. If the current step was already used, wait for the next step.

The OTP value is never written to disk or logs.

---

## 7. Secrets and configuration

### 7.1 Config file `/etc/ghvpn/config.toml`
```toml
[vpn]
ovpn_secret_id     = "ghvpn/sophos-ovpn"        # Secrets Manager: full .ovpn text
username_secret_id = "ghvpn/sophos-username"
password_secret_id = "ghvpn/sophos-password"
otp_mode           = "manual"                   # manual | stdin | totp-secret
# totp_secret_id   = "ghvpn/sophos-totp-seed"
# i_have_it_approval = false

[proxy]
socks_listen = "127.0.0.1:1080"
http_listen  = "127.0.0.1:3128"
allow_hosts  = ["github.com", "*.github.com", "*.githubusercontent.com",
                "github.githubassets.com", "*.githubassets.com", "ghcr.io", "*.ghcr.io"]
allow_ports  = [443, 22]

[health]
expected_egress_ips = ["203.0.113.10"]          # company firewall public IP(s)
probe_repo          = "https://github.com/<org>/<private-repo>.git"
interval_secs       = 120

[notify]
sns_topic_arn = ""                              # optional: "needs OTP" alerts
```

### 7.2 Secrets
- Load from **AWS Secrets Manager** through the instance's IAM role (`aws-config`, `aws-sdk-secretsmanager`).
  Minimal IAM policy: `secretsmanager:GetSecretValue` on `arn:...:secret:ghvpn/*` only.
- Fallback for non-AWS testing: `GHVPN_*` environment variables (development only; print a warning).
- Hold secrets in memory in `secrecy::SecretString` (or zeroize on drop).
- Require IMDSv2 on the instance.

---

## 8. Proxy and health checks

### 8.1 Proxy (runs inside the netns)
- **SOCKS5** (RFC 1928, CONNECT only, no auth, domain-name address type required) and **HTTP CONNECT**.
  Implement both directly on `tokio`; they are about 200 lines each. Don't add a heavy dependency.
- **Allowlist enforcement**: reject any destination whose hostname doesn't match `allow_hosts`, or whose port isn't
  in `allow_ports`. Reject raw IP destinations. This stops the box becoming an open relay into the company network.
- Resolve DNS inside the netns (so `socks5h://` works).
- Listen only on loopback on the host side. Never bind `0.0.0.0`.
- Optional: per-connection logs (host, port, bytes, duration). No payload logging.

### 8.2 Health checks (after CONNECTED and every `interval_secs`)
1. **Egress IP**: from inside the netns, `GET https://api.ipify.org`, and the result must be in `expected_egress_ips`.
   If not → state `DEGRADED(egress_mismatch)`. This usually means VPN→WAN is not allowed (P4).
2. **GitHub reachability**: `git ls-remote <probe_repo>` through the proxy using the configured credentials.
   A 403 that mentions "IP allow list" means the egress IP is wrong.
3. **Tunnel liveness**: `>BYTECOUNT` increasing, or a TCP connect to `github.com:443` succeeds within 5 s.

---

## 9. Control API and CLI

### 9.1 Control socket
A Unix socket at `/run/ghvpn/ctl.sock`, mode `0660`, group `ghvpn`. JSON lines, one request per connection.

| Request | Response |
|---|---|
| `{"cmd":"up","otp":"123456"}` | `{"ok":true,"state":"CONNECTING"}` |
| `{"cmd":"otp","otp":"123456"}` | supplies a code for a pending `NEEDS_OTP` |
| `{"cmd":"down"}` | sends `signal SIGTERM` to openvpn, keeps the netns |
| `{"cmd":"status"}` | `{"state":"CONNECTED","since":"…","tunnel_ip":"…","egress_ip":"…","egress_ok":true,"session_token":false,"bytes_in":…,"bytes_out":…,"auth_failures":0}` |

States: `IDLE → CONNECTING → NEEDS_OTP → AUTHENTICATING → CONNECTED ⇄ RECONNECTING`, plus `DEGRADED`, `FAILED`,
`LOCKED_OUT_GUARD`.

### 9.2 CLI (`clap`)
```
ghvpn up [--otp <code>]       # prompts if omitted and a TTY is present
ghvpn otp <code>
ghvpn down
ghvpn status [--json]
ghvpn doctor                  # runs the P1–P5 checks that can be automated, prints a pass/fail table
ghvpn git-setup [--ssh]       # writes the git and ssh config from §10
ghvpn ssh-proxy <host> <port> # used as an SSH ProxyCommand: connects via the SOCKS5 proxy, pipes stdin/stdout
ghvpn exec -- <cmd...>        # runs a command with HTTPS_PROXY/ALL_PROXY set for that one process
```

### 9.3 Notifications
When entering `NEEDS_OTP` or `FAILED`: log at WARN, write the state to `/run/ghvpn/state`, and publish to SNS if
`sns_topic_arn` is set. The message must contain no secrets.

---

## 10. Git integration (`ghvpn git-setup`)

HTTPS (scoped to GitHub only):
```bash
git config --global http.https://github.com/.proxy socks5h://127.0.0.1:1080
git config --global credential.helper store   # or a PAT from Secrets Manager via a custom helper
```

SSH (`~/.ssh/config`):
```sshconfig
Host github.com
  HostName ssh.github.com
  Port 443
  User git
  IdentityFile ~/.ssh/id_ed25519_github
  ProxyCommand /usr/local/bin/ghvpn ssh-proxy %h %p
```

GitHub authentication itself (PAT or deploy key/SSH key) is separate from VPN authentication and is the user's
responsibility. Recommend a **fine-grained PAT** or an **SSH key used only on this instance**.

`gh` CLI and other tools: `ghvpn exec -- gh pr list`.

---

## 11. Out of scope / known blockers

- **Entra ID SSO for SSL VPN**: no browser flow on a headless box → unsupported.
- **Security Heartbeat enforcement**: requires Sophos Endpoint → unsupported.
- **IPsec-only users**: would need strongSwan IKEv1 + XAUTH. Possible later as a separate backend behind the same
  control API (drive strongSwan through VICI using the `rsvici` crate). Not in v0.1.
- **Fully unattended operation without a TOTP seed**: impossible if the server doesn't issue session tokens. Every
  reconnect needs a human to supply a code.

---

## 12. Alternative packaging (optional build target)

A Docker image (`debian:stable-slim` + `openvpn` + `ghvpnd`) run with `--cap-add=NET_ADMIN --device=/dev/net/tun`
and `-p 127.0.0.1:1080:1080 -p 127.0.0.1:3128:3128`. In this mode, skip §4 (the container is the isolation
boundary) and serve the control socket from a bind-mounted `/run/ghvpn`. Same code; enable it with a
`--no-netns` flag.

---

## 13. Project layout

```
ghvpn/
├─ Cargo.toml                 # workspace
├─ crates/
│  ├─ ghvpn-core/             # config, secrets, state machine, OtpSource, types
│  ├─ ghvpn-mgmt/             # OpenVPN management-interface client + parser
│  ├─ ghvpn-net/              # netns/veth/NAT setup + teardown (NetOps trait)
│  ├─ ghvpn-proxy/            # SOCKS5 + HTTP CONNECT + allowlist
│  ├─ ghvpnd/                 # daemon binary
│  └─ ghvpn/                  # CLI binary
├─ packaging/
│  ├─ ghvpnd.service
│  ├─ config.example.toml
│  └─ Dockerfile
└─ tests/
   ├─ mgmt_fixtures/          # recorded management-interface transcripts
   └─ e2e/                    # docker-compose with a test OpenVPN server
```

Suggested crates: `tokio`, `clap`, `serde`, `toml`, `serde_json`, `tracing`, `tracing-subscriber`, `anyhow`,
`thiserror`, `nix`, `rtnetlink`, `reqwest` (rustls), `aws-config`, `aws-sdk-secretsmanager`, `aws-sdk-sns`,
`secrecy`, `zeroize`, `totp-rs` (behind the `totp` feature), `globset`.

### systemd unit (`packaging/ghvpnd.service`)
```ini
[Unit]
Description=GitHub over Sophos VPN gateway
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/ghvpnd --config /etc/ghvpn/config.toml
Restart=on-failure
RestartSec=5
RuntimeDirectory=ghvpn
RuntimeDirectoryMode=0750
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/run/ghvpn /etc/netns
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```
Note: `ghvpnd` does **not** auto-connect on boot unless `otp_mode = "totp-secret"`. Otherwise it starts in `IDLE`
and waits for `ghvpn up --otp …`.

---

## 14. Testing

1. **Unit**
   - Management-line parser: all notifications in §5.2, including malformed lines.
   - Credential quoting/escaping (`"`, `\`, unicode).
   - Allowlist matching (wildcards, case, trailing dots, IP literals rejected).
   - State machine transitions, including "OTP reuse is impossible" and the lockout guard.
   - TOTP: RFC 6238 test vectors; one code per time step.
2. **Integration** (no Sophos needed): docker-compose with an OpenVPN 2.6 server using `auth-user-pass-verify` and a
   script that accepts `password` + a TOTP from a test seed. Exercise connect, wrong OTP, renegotiation with
   `reneg-sec 60`, server restart, and proxy allowlist denial.
3. **Live acceptance** (on the real EC2 instance, with IT approval):
   - `ghvpn doctor` passes P1–P5.
   - `ghvpn up --otp <code>` → `CONNECTED` within 30 s, `egress_ok: true`.
   - `git clone`, commit, `git push` to a private org repo over HTTPS **and** SSH succeed.
   - With the VPN down, the same push fails with an IP allow list error (proves the route is actually used).
   - `curl https://example.com` from the host still uses the EC2 IP (proves only GitHub is tunnelled).
   - `curl -x socks5h://127.0.0.1:1080 https://intranet.example.local` is rejected by the allowlist.
   - SSH into the instance still works while the VPN flaps.

## 15. Acceptance criteria (v0.1)
- [ ] All §14 unit and integration tests pass in CI.
- [ ] No secret (password, OTP, TOTP seed, private key) appears in logs, the state file, `status` output, or on
      persistent disk.
- [ ] Host routing table and `/etc/resolv.conf` are byte-identical before and after `up`/`down`.
- [ ] Teardown after `kill -9 ghvpnd` + restart leaves no stale netns, veth or NAT rules.
- [ ] Live acceptance checks in §14.3 pass.
