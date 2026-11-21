# sophos-cli

Headless Sophos SSL VPN supervisor and local `sophos` CLI. Uses OpenVPN 2.6 and the existing `.ovpn` profile, not a replacement VPN protocol. Linux and macOS only.

Source draft: the workspace lockfile update is pending, so locked builds currently fail. Compilation, tests and live service deployment are not yet verified. See the [root README](../../README.md#local-macos-setup) for step-by-step local macOS setup and manual boot-service installation. No automatic setup or service installer is implemented.

## Configuration

Default: `$XDG_CONFIG_HOME/sophos-cli/config.json`, or `~/.config/sophos-cli/config.json`. Directory must be private (`0700`), config and profile files `0600`. Final-component symlinks are rejected. Use absolute paths; `~` is not expanded inside JSON.

```json
{
  "profile": "/absolute/path/client.ovpn",
  "totp_seed": "REPLACE_WITH_YOUR_BASE32_SEED",
  "gateway": "203.0.113.10",
  "route_mode": "github"
}
```

Enter the seed in a local editor, not a shell argument or chat. The seed is required; a current six-digit code is not a seed. TOTP uses SHA1, six digits and 30-second steps. Synchronize the server clock. Confirm organization approval before automating MFA.

Optional fields:

- `username`, `password`: stored login credentials. Password is the base password, without OTP. Omit either to prompt for it through `sophos connect`.
- `openvpn`: absolute executable path. Default `/usr/sbin/openvpn` on Linux, `/opt/homebrew/sbin/openvpn` on Apple silicon macOS. Set `/usr/local/sbin/openvpn` where appropriate for Intel Homebrew.
- `socket`: custom control socket path; pass the same path to CLI commands with `--socket`.
- `operator_uid`: UID allowed to control a root daemon. Defaults to config file owner. For root-owned service config, set this explicitly to your login UID.

The control socket is `0600` in a private operator-owned `0700` directory. Requests authenticate the peer UID. The operator is trusted to control the VPN. Use root-owned config and profile paths under a root-owned directory for a persistent privileged service. A root daemon must not load an executable or config from an untrusted user's writable directory.

## Run

Install OpenVPN separately with your platform package manager. Build/install this crate only after reviewing its dependency changes.

```bash
cargo install --path crates/sophos-cli --locked
```

Start the supervisor in one terminal:

```bash
sudo /absolute/path/to/sophos --config /absolute/path/config.json daemon
```

In another terminal:

```bash
sophos connect
sophos status
sophos reconnect
sophos disconnect
sophos stop
```

Use `--config /absolute/path/config.json` if not using the default config location. Control commands do not read the secret config: `connect` asks the daemon which credentials are missing, then prompts locally. Password input is hidden. There are no password or seed flags. Commands acknowledge queueing; use `status` to observe the resulting connection state.

Interactive credentials remain in daemon memory across reconnects. `disconnect` forgets them and disables reconnection. A daemon restart loses interactive credentials; run `connect` again. With both login fields stored, the daemon attempts connection automatically after starting. `stop` ends the foreground process, but a service manager configured to keep it alive may restart it. Stop/unload the service itself for a persistent shutdown.

## Reconnect

- OpenVPN keepalive defaults: ping every 10 seconds, restart after 30 seconds without packets. Server-pushed settings may override these. This detects silent failures; it is not an instantaneous guarantee.
- OpenVPN handles transport reconnects internally. The supervisor releases each announced management hold and supplies fresh credentials when requested.
- If OpenVPN exits, the supervisor restarts it. First retry has no delay; repeated failures use backoff capped at 30 seconds.
- OTPs are generated when credentials are requested. Already-used counters and the last three seconds of a step are skipped. A reconnect can wait for the next code window. Codes used by another client or before daemon restart cannot be tracked locally.
- Three rejected authentications in 15 minutes pause reconnects. Wait for the window to expire, correct credentials and run `connect` again. This limit is process-local; restarting the daemon resets it.
- Static challenges and encrypted client private keys are not supported. This backend sends base password plus TOTP, without a separator.

`status` contains state, tunnel IP, connection time, reconnect count, authentication-failure count and last error. It never contains credentials, seed or OTP. Raw OpenVPN logs are not forwarded because they can contain session tokens. Unsupported profiles fail with a generic compatibility error; inspect a profile locally without exposing key material.

## Routing

- `github` (default): published GitHub web/API/Git IPv4 ranges and the egress-check host through the VPN. Server-pushed routes are suppressed. Existing explicit profile routes are retained.
- `full`: general IPv4 default traffic through the VPN. Can break remote SSH unless the operator provisions a return route.
- `pushed`: accept server routing.

This is destination-based routing, not per-process routing. It is not an IPv6 isolation solution or a kill switch. On VPN failure, traffic can fall back to the host route. Do not use a second client managing the same VPN/routes simultaneously.

## Linux service

See `examples/sophos.service`. Install the binary at `/usr/local/bin/sophos`. Place config/profile under `/etc/sophos-cli` (root-owned, directory `0700`, files `0600`). Set `operator_uid` to your login UID and `socket` to `/run/sophos-cli/control.sock` in config. The daemon creates the private runtime directory.

Install the unit under `/etc/systemd/system/sophos.service`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sophos.service
sophos --socket /run/sophos-cli/control.sock connect
sophos --socket /run/sophos-cli/control.sock status
```

Only fully stored credentials permit unattended startup. `systemctl stop sophos.service` disconnects the VPN and stops the supervisor. No proxy, cloud secret manager or AWS permissions are needed for this local setup.

## macOS service

See `examples/in.soham.sophos.plist`. It is a system LaunchDaemon, not a login LaunchAgent: OpenVPN needs privileges to create utun interfaces and routes. OpenVPN uses macOS's native utun support; no third-party kernel extension is installed by this crate.

Install the binary at `/usr/local/bin/sophos`, config/profile under `/Library/Application Support/sophos-cli` with root ownership, directory `0700` and files `0600`. Set the config's `operator_uid` to your login UID and `socket` to `/var/run/sophos-cli/control.sock`. Install the plist as root-owned `0644` at `/Library/LaunchDaemons/in.soham.sophos.plist`.

```bash
sudo launchctl bootstrap system /Library/LaunchDaemons/in.soham.sophos.plist
sophos --socket /var/run/sophos-cli/control.sock connect
sophos --socket /var/run/sophos-cli/control.sock status
```

To stop: `sudo launchctl bootout system /Library/LaunchDaemons/in.soham.sophos.plist`. No DNS helper scripts are installed. Public GitHub DNS can use the host resolver; internal corporate DNS may require separate administrator configuration. Network changes and wake from sleep rely on OpenVPN reconnect behavior and keepalive detection.

Service templates are examples, not automatically installed or enabled. Live launchd deployment must be verified on the target Mac; schema/build checks alone do not establish working tunnel or sleep/wake behavior.

## Security

Storing password and TOTP seed together collapses factor separation for a compromised machine. File permissions do not protect against root compromise. Secret buffers are zeroized where practical, but no guarantee is made that the OS, allocator, terminal or OpenVPN holds no additional copies. Do not use swap/core dumps as secret storage. Prefer an organization-approved unattended identity where available.

## References

- [OpenVPN management protocol](https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt)
- [TOTP, RFC 6238](https://www.rfc-editor.org/rfc/rfc6238)
- [systemd services](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
- [Apple launchd guidance](https://support.apple.com/guide/terminal/apdc6c1077b-5d5d-4d35-9c19-60f2397b2369/mac)
