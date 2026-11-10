# ghvpn

Harness for reaching an IP-allow-listed GitHub org through a Sophos SSL VPN. See [SPEC.md](SPEC.md) for the full EC2 design; this repo currently has the interactive TUI harness.

## ghvpn-tui

Ratatui app that downloads the `.ovpn` from the Sophos VPN portal, runs the stock `openvpn` binary through its management interface, and probes a GitHub repo before and after the tunnel is up.

Requirements: `openvpn` 2.6 (`brew install openvpn`), `git`, sudo rights (openvpn needs root for the tun device; the TUI runs `sudo -v` when needed).

```bash
cargo run -p ghvpn-tui -- --gateway 203.0.113.10 --portal-host <name-on-portal-cert>
```

Flow:
1. Fill VPN username, password (and OTP if MFA is on), GitHub user and PAT.
2. `^E` / `^G` with the VPN down: baseline egress IP and repo access (expect an IP allow list 403 or a 404).
3. `Enter`: logs in to the portal, downloads the config, starts openvpn, answers the credential prompt.
4. On `CONNECTED` the egress IP is checked automatically. `^G` again: GitHub API + `git ls-remote`. `^K`: shallow clone into `./clones`.

Route modes (`←/→` on the field or `--route-mode`):
- `github` (default): `route-nopull` plus routes for GitHub's `web`/`api`/`git` IPv4 ranges from `api.github.com/meta`, plus host routes for `api.ipify.org` so the egress check goes through the tunnel.
- `full`: `redirect-gateway def1`, all traffic through the VPN.
- `pushed`: whatever the firewall pushes.

Notes:
- Without `--portal-host` the portal certificate is not verified (the cert never matches a bare IP).
- The OTP is appended to the password with no separator and cleared after one use. If MFA is on, the portal login consumes one code and the VPN login needs the next one.
- Three failed VPN logins in 15 minutes stop further attempts for 15 minutes, to avoid a firewall account lockout.
- The patched config (with the client private key) lives in a `0700` temp dir and is deleted when openvpn exits.

Options: `cargo run -p ghvpn-tui -- --help`.
