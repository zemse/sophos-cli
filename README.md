# ghvpn

Harness for reaching an IP-allow-listed GitHub org through a Sophos SSL VPN. Includes an interactive TUI and a draft headless CLI. See [SPEC.md](SPEC.md) for the full EC2 design.

## sophos-cli

Headless OpenVPN supervisor with local Unix-socket control, TOTP generation and automatic reconnect.

**Development status:** the daemon is a source draft, not a verified release. Its workspace lockfile update is still pending, so the locked build below currently fails. Compilation, tests and live macOS service deployment are not yet verified. The instructions describe the implemented interface, not a tested installation. There is no `setup`, `install-service` or `connect --profile` command yet.

### Local macOS setup

You need Rust, Homebrew, administrator access, a Sophos SSL VPN `.ovpn` profile, your VPN username/password and the Base32 TOTP seed. A current six-digit OTP is not the seed. The backend expects password followed by TOTP with no separator. Confirm your organization permits automated MFA.

1. Install OpenVPN (not the Sophos GUI):

   ```bash
   brew install openvpn
   "$(brew --prefix)/sbin/openvpn" --version
   ```

2. From the cloned repository, build/install the CLI:

   ```bash
   cargo install --path crates/sophos-cli --locked
   "$HOME/.cargo/bin/sophos" --help
   ```

   Resolve the pending workspace lockfile update before this step can succeed. The installed binary is `sophos`, not `sophos-cli`.

3. Prepare private config files. Replace the source profile path with your own:

   ```bash
   mkdir -p "$HOME/.config/sophos-cli"
   chmod 700 "$HOME/.config/sophos-cli"
   install -m 600 /absolute/path/to/client.ovpn "$HOME/.config/sophos-cli/client.ovpn"
   touch "$HOME/.config/sophos-cli/config.json"
   chmod 600 "$HOME/.config/sophos-cli/config.json"
   id -u
   brew --prefix
   ```

   Open `~/.config/sophos-cli/config.json` in a local editor and enter:

   ```json
   {
     "profile": "/Users/YOUR_LOGIN/.config/sophos-cli/client.ovpn",
     "totp_seed": "YOUR_BASE32_TOTP_SEED",
     "openvpn": "/opt/homebrew/sbin/openvpn",
     "route_mode": "github"
   }
   ```

   Replace `YOUR_LOGIN` and the seed locally. Paths must be absolute; JSON does not expand `~` or `$HOME`. Use the OpenVPN path from your Homebrew prefix (usually `/usr/local/sbin/openvpn` on Intel). Never put real secrets in shell arguments, commits or chat.

4. Start the privileged supervisor in one terminal:

   ```bash
   sudo "$HOME/.cargo/bin/sophos" --config "$HOME/.config/sophos-cli/config.json" daemon
   ```

5. In a second terminal, connect and enter your username and base password when prompted. Password entry is hidden:

   ```bash
   "$HOME/.cargo/bin/sophos" --config "$HOME/.config/sophos-cli/config.json" connect
   "$HOME/.cargo/bin/sophos" --config "$HOME/.config/sophos-cli/config.json" status
   ```

   `connect` queues the request. Check `status` for the resulting connection or error. The foreground daemon must stay running; closing its terminal is not a persistent installation.

6. Control the connection using the same config path:

   ```bash
   sophos --config "$HOME/.config/sophos-cli/config.json" reconnect
   sophos --config "$HOME/.config/sophos-cli/config.json" disconnect
   sophos --config "$HOME/.config/sophos-cli/config.json" stop
   ```

   These examples assume `~/.cargo/bin` is on `PATH`; otherwise use the full binary path as above. `disconnect` disables retries and forgets prompted credentials. `stop` exits the supervisor. Do not run a second VPN client managing the same tunnel/routes.

### Start at boot on macOS

For operation without an open terminal, use the supplied system LaunchDaemon. This is manual installation and requires administrator access. Stop the foreground daemon before switching to the service.

From the repository root:

```bash
sudo install -o root -g wheel -m 755 "$HOME/.cargo/bin/sophos" /usr/local/bin/sophos
sudo install -d -o root -g wheel -m 700 "/Library/Application Support/sophos-cli"
sudo install -o root -g wheel -m 600 "$HOME/.config/sophos-cli/client.ovpn" "/Library/Application Support/sophos-cli/client.ovpn"
sudo install -o root -g wheel -m 600 "$HOME/.config/sophos-cli/config.json" "/Library/Application Support/sophos-cli/config.json"
id -u
```

If `/usr/local/bin` does not exist, create it as a root-owned directory first. Use a local privileged editor, for example `sudo nano "/Library/Application Support/sophos-cli/config.json"`, to replace the service config with:

```json
{
  "profile": "/Library/Application Support/sophos-cli/client.ovpn",
  "totp_seed": "YOUR_BASE32_TOTP_SEED",
  "username": "YOUR_VPN_USERNAME",
  "password": "YOUR_BASE_PASSWORD_WITHOUT_OTP",
  "openvpn": "/opt/homebrew/sbin/openvpn",
  "route_mode": "github",
  "operator_uid": 501,
  "socket": "/var/run/sophos-cli/control.sock"
}
```

Use your own `id -u` value instead of `501`, the correct Homebrew executable path, and your actual credentials entered only in the local editor. Escape quotes/backslashes in JSON strings. Config and profile must remain root-owned `0600`, in the root-owned `0700` directory. Storing password and seed together weakens MFA factor separation; file permissions do not protect against root compromise.

Install and load the service:

```bash
sudo install -o root -g wheel -m 644 crates/sophos-cli/examples/in.soham.sophos.plist /Library/LaunchDaemons/in.soham.sophos.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/in.soham.sophos.plist
sophos --socket /var/run/sophos-cli/control.sock status
```

The template starts the daemon at boot and restarts it if it exits. With both login fields stored, the daemon attempts connection on startup. If you omit either login field, run `sophos --socket /var/run/sophos-cli/control.sock connect` and answer the prompts after each daemon restart.

Use `--socket /var/run/sophos-cli/control.sock` for all service control commands. The CLI does not read a custom socket value from the secret config. `disconnect` disables reconnection until `connect`, but a service restart can reconnect using stored credentials. `stop` is not a persistent service shutdown because launchd can restart the daemon. To stop and unload it:

```bash
sudo launchctl bootout system /Library/LaunchDaemons/in.soham.sophos.plist
```

To remove the service registration, run `bootout` first, then remove `/Library/LaunchDaemons/in.soham.sophos.plist`. Remove the protected config/profile separately if no longer needed. Loading the plist again uses the same `bootstrap` command.

### Reconnection, routing and troubleshooting

- OpenVPN handles transport reconnects; the daemon supplies fresh TOTP credentials and restarts OpenVPN if it exits. Default keepalive is 10 seconds with restart after 30 seconds of silence, unless overridden by the server. This is not instantaneous or a guarantee of uninterrupted connectivity.
- Three rejected logins within 15 minutes pause retries. Check credentials, wait for the window to expire, then run `connect`. Do not bypass the limit by repeatedly restarting.
- Sleep/wake and network changes rely on OpenVPN reconnect behavior and still need live macOS testing. An asleep Mac cannot maintain an active tunnel.
- `github` routes GitHub IPv4 destinations through the VPN, not all traffic. Use `full` or `pushed` only if appropriate for your network. No kill switch, IPv6 isolation or corporate DNS helper is provided. Traffic can fall back to the ordinary connection during an outage.
- If OpenVPN is not found, run `brew install openvpn` and verify the absolute `openvpn` config path. The CLI does not install it automatically.
- Socket connection errors: check the daemon is running and that your command uses the correct config-derived socket or the service's explicit `--socket` path.
- Permission errors: check config/profile ownership and modes, the config directory mode, and the service's `operator_uid`.
- Service startup errors: inspect `sudo launchctl print system/in.soham.sophos` and `/var/log/sophos-cli.log` locally. Do not publish logs or profiles containing secrets.

For Linux systemd setup, configuration details and limitations, see [crates/sophos-cli/README.md](crates/sophos-cli/README.md). GitHub authentication remains separate from VPN authentication; the VPN only supplies network access.

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
