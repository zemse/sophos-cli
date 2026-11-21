# sophos-cli

Headless Sophos SSL VPN supervisor and local `sophos` CLI. Uses OpenVPN 2.6 and the existing `.ovpn` profile, not a replacement VPN protocol. Linux and macOS only.

Onboarding, service installation and manual codes are in the [root README](../../README.md). This page is the config reference.

## config.json

`sophos setup` writes this file. Default location `$XDG_CONFIG_HOME/sophos-cli/config.json` or `~/.config/sophos-cli/config.json`; with `--system`, `/etc/sophos-cli/config.json` (Linux) or `/Library/Application Support/sophos-cli/config.json` (macOS). The directory must be `0700`, the config, profile and envelope `0600`, owned by the operator or root. Final-component symlinks are rejected. Paths must be absolute.

```json
{
  "profile": "/etc/sophos-cli/client.ovpn",
  "totp_envelope": "/etc/sophos-cli/totp.envelope",
  "gateway": "203.0.113.10",
  "route_mode": "github",
  "openvpn": "/usr/sbin/openvpn",
  "operator_uid": 1000,
  "socket": "/var/run/sophos-cli/control.sock"
}
```

- `profile`: OpenVPN profile. Only plain client directives are accepted, and it must verify the server identity (`remote-cert-tls server` or `verify-x509-name`).
- `totp_envelope`: envelope from `sophos totp import`, unwrapped by its backend at every login.
- `totp_seed`: plaintext Base32 seed (SHA1, 6 digits, 30 seconds) instead of an envelope. Set at most one of the two.
- With neither, logins wait for `sophos connect` or `sophos otp` to supply a code.
- `gateway`: replaces the `remote` host from the profile.
- `route_mode`: `github` (default), `full` or `pushed`.
- `openvpn`: executable path. Default `/opt/homebrew/sbin/openvpn` on macOS, `/usr/sbin/openvpn` elsewhere.
- `username`, `password`: stored login. The password is the base password, without the code. Omit either to be prompted by `sophos connect`.
- `operator_uid`: UID allowed to control a root daemon. Defaults to the config file owner.
- `socket`: control socket. Defaults to `run/control.sock` next to the config. Client commands do not read the config, so pass the same path with `--socket`, or use `--system` for `/var/run/sophos-cli/control.sock`.

## Control protocol

One JSON request per connection on a `0600` Unix socket in a `0700` operator-owned directory. The daemon checks the peer UID. Requests: `requirements`, `connect` (optional `username`, `password`, `otp`), `otp`, `status`, `reconnect`, `disconnect`, `stop`. Unknown fields are rejected. Replies carry `status` plus `need_username`, `need_password` and `need_otp`.

`status.state` is one of `needs_credentials`, `needs_otp`, `connecting`, `waiting_for_otp`, `authenticating`, `connected`, `reconnecting`, `disconnected`, `auth_locked` or `stopped`.

- `waiting_for_otp`: OpenVPN asked for credentials and a code is being prepared.
- `needs_otp`: a code must be supplied.

## Limits

- Static-challenge prompts and encrypted client private keys are not supported. The login is the base password followed by the code, with no separator.
- The three-failure lockout counter lives in the daemon process, so a restart resets it.
- Codes used by another client, or before a daemon restart, cannot be tracked.
- Secret buffers are zeroized where practical. No guarantee is made that the OS, allocator, terminal or OpenVPN keeps no other copy.
