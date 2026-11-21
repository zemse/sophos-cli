# sophos-cli

Headless client for a Sophos SSL VPN whose login is password plus a 6-digit TOTP code. The `sophos` binary runs the stock OpenVPN 2.6 client through its management interface, logs in by itself, reconnects, and routes only GitHub traffic through the tunnel by default. It was built to reach a GitHub org that only accepts the company's egress IP.

The TOTP seed can stay out of plaintext. `sophos totp import` reads your Google Authenticator QR and wraps the seed with this machine's Secure Enclave, TPM or AWS KMS, so a copied disk cannot produce codes. If you do not want the seed on the machine at all, skip the import and type codes from your phone when the VPN asks.

**Status:** unit and integration tests pass on macOS, and TOTP import plus code generation through the Secure Enclave are verified on a real Mac. A live connection to a Sophos firewall, the TPM and AWS backends, and the boot services have not been verified yet. See [TASKS.md](TASKS.md).

## What you need

- VPN username and password.
- The firewall's IP or hostname (the VPN portal and gateway).
- Your TOTP key, in any of these forms:
  - A Google Authenticator export QR (Transfer accounts, Export accounts), as a screenshot or photo (PNG or JPEG).
  - The original setup QR, or its `otpauth://totp/...` URI.
  - The base32 setup key (for example `JBSW Y3DP EHPK 3PXP`).
  - A current 6-digit code is not a key. With only that, use [manual codes](#connect-without-storing-the-totp-key).
- Linux or macOS with root access, Rust, and OpenVPN 2.6.
- Your organisation's approval to automate MFA from this machine.

## Install

```bash
# macOS
brew install openvpn
# Debian / Ubuntu
sudo apt install openvpn

git clone https://github.com/zemse/sophos-cli && cd sophos-cli
cargo install --path crates/sophos-cli --locked   # installs `sophos`
cargo install --path crates/authn-cli --locked    # optional: standalone `authn`
```

The Secure Enclave backend compiles a small Swift shim, so macOS builds need the Xcode command line tools.

## Onboarding

Everything lives in one private directory: `~/.config/sophos-cli/` for a foreground daemon, or with `--system` the root-owned service directory (`/etc/sophos-cli/` on Linux, `/Library/Application Support/sophos-cli/` on macOS). Pick one mode and use it for every step. For a server that must connect at boot, use `--system` and run each step with `sudo`.

| File | Written by | Contents |
| --- | --- | --- |
| `client.ovpn` | `sophos profile fetch` or `setup --profile` | OpenVPN profile, including your client private key |
| `totp.envelope` | `sophos totp import` | TOTP parameters and the wrapped seed, never the seed itself (except `plain`) |
| `config.json` | `sophos setup` | Paths, gateway, routing, optionally the stored login |

All are mode `0600` in a `0700` directory. The daemon refuses anything looser.

### 1. Get the OpenVPN profile

Download it from the Sophos VPN portal (SFOS 20+). You are prompted for username, password and a one-time code:

```bash
sophos profile fetch --gateway 203.0.113.10
# or, for the boot service:
sudo sophos --system profile fetch --gateway 203.0.113.10
```

Add `--portal-host vpn.example.com` (the name on the portal certificate) to verify TLS; without it the certificate is not checked, because it never matches a bare IP. If you already imported the TOTP key, the code is generated for you. If you already have an `.ovpn` file, skip this and pass it to `setup --profile` in step 3.

### 2. Load the TOTP key (optional)

Skip this step to [connect with manual codes](#connect-without-storing-the-totp-key).

```bash
# Image on this machine
sophos totp import ~/Downloads/authenticator.png

# Google Authenticator export with several accounts: list, then pick one
sophos totp import export.png --list
sophos totp import export.png --account 2

# otpauth URI or base32 key, read from stdin so it stays out of shell history
pbpaste | sophos totp import -
```

Load a QR that is on your laptop onto a remote server without the image ever touching the server's disk:

```bash
ssh server 'sudo sophos --system totp import -' < authenticator.png
```

Import must run on the machine that will connect, because the envelope only unwraps there. Check that it worked:

```bash
sophos totp code      # must match your authenticator app right now
```

Then delete the image or URI: it still contains the seed.

Backends, chosen with `--provider`:

| id | Where | How the seed is kept |
| --- | --- | --- |
| `enclave` | macOS (default there) | Encrypted to a non-exportable Secure Enclave key of this Mac |
| `tpm` | Linux with TPM 2.0 or AWS NitroTPM | Sealed with `systemd-creds` (tpm2-tools fallback) |
| `aws` | EC2 with an instance role | KMS envelope encryption or Secrets Manager, chosen by environment (see below) |
| `secrets` | macOS, per user | The `secrets` CLI store; not reachable by the root daemon |
| `plain` | anywhere | Unencrypted in the envelope; file permissions only |

The `aws` backend reads its settings from the environment on every use, at import and at each login. Set `SPO_AWS_KMS_KEY_ID` (or `SPO_AWS_MODE=secretsmanager` and `SPO_AWS_SECRET_NAME`) plus `AWS_REGION`. Pass them through `sudo` (`sudo env AWS_REGION=... SPO_AWS_KMS_KEY_ID=... sophos --system totp import ...`). Add the same values as `Environment=` lines in the systemd unit.

`auto` (the default on Linux) picks `tpm`, then `aws`. `sophos totp providers` shows what this host supports. Only the QR's one selected account is stored. SHA1, SHA256 and SHA512, 6 or 8 digits and any period are supported.

### 3. Write the config

```bash
sophos setup --gateway 203.0.113.10
# boot service: also store the login so it can connect unattended
sudo sophos --system setup --gateway 203.0.113.10 --save-login
```

`setup` checks the profile, finds OpenVPN, and records `totp.envelope` if step 2 created one; otherwise it configures manual codes. Useful flags:

- `--profile PATH` copies an existing `.ovpn` in.
- `--save-login` prompts for username and password and stores them, so the daemon connects without you.
- `--route-mode github|full|pushed` (default `github`).
- `--manual-otp` ignores the envelope.
- `--operator-uid` sets who may control the root daemon (default: the `sudo` caller).
- `--force` replaces an existing config.

It validates the written config with the same loader the daemon uses.

### 4. Run it

Foreground, in two terminals:

```bash
sudo sophos daemon         # terminal 1, keeps running
sophos connect             # terminal 2: prompts for whatever the config lacks
sophos status              # JSON: state, tunnel IP, reconnects, last error
```

As a boot service on Linux:

```bash
sudo install -m 755 ~/.cargo/bin/sophos /usr/local/bin/sophos
sudo install -m 644 crates/sophos-cli/examples/sophos.service /etc/systemd/system/sophos.service
sudo systemctl daemon-reload && sudo systemctl enable --now sophos.service
sophos --system status
```

As a boot service on macOS:

```bash
sudo install -o root -g wheel -m 755 ~/.cargo/bin/sophos /usr/local/bin/sophos
sudo install -o root -g wheel -m 644 crates/sophos-cli/examples/in.soham.sophos.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/in.soham.sophos.plist
sophos --system status
```

With the login stored and a TOTP envelope, the service connects at boot and after every drop with no input. Otherwise run `sophos --system connect`. Logs: `journalctl -u sophos` or `/var/log/sophos-cli.log`.

Control commands: `connect`, `otp`, `status`, `reconnect`, `disconnect` (stop and forget prompted credentials), `stop` (exit the daemon; a service manager restarts it). Use `--system` with each when talking to the service.

## Connect without storing the TOTP key

Leave out step 2 (or pass `setup --manual-otp`). The daemon then holds no seed, and each login waits for a code from you:

```bash
sophos connect             # prompts for missing username/password, then the current code
sophos status              # "state": "needs_otp" whenever the VPN wants a new code
sophos otp 123456          # supply it; works over ssh from anywhere
```

- A code is used for one login and expires after 60 seconds, so type it right before connecting.
- In manual mode the daemon does not start OpenVPN until it has a code.
- Each new VPN login needs a new code: the first connect, a reconnect after the tunnel drops, and a daemon restart.
- The client never renegotiates TLS (`reneg-sec 0`). If the firewall renegotiates on its own schedule (OpenVPN servers default to hourly), the VPN asks again and manual mode needs a code within about a minute, unless the firewall issues an OpenVPN auth token. This has not been observed against a real Sophos firewall yet.
- With `--save-login` you only ever type the code.
- Watch for `needs_otp` from a cron job or monitor and notify yourself.

`sophos otp` also works with an envelope configured. A supplied code is used first, and if the backend fails to unwrap (for example a locked Mac at boot) the daemon waits in `needs_otp` for one.

## Behaviour

- OpenVPN pings every 10 seconds and restarts after 30 seconds of silence. If OpenVPN exits, the daemon restarts it with backoff capped at 30 seconds.
- Codes are made when OpenVPN asks for credentials. An already-used time step and the last 3 seconds of a step are skipped.
- The portal and the VPN each consume a code, so after `profile fetch` the first VPN login may wait for the next step.
- Three rejected logins in 15 minutes stop retries until the window passes and you run `connect`. This avoids locking the firewall account.
- `github` routing sends GitHub's published web, API and git IPv4 ranges through the tunnel and leaves everything else alone.
  - `full` sends all IPv4 traffic, which can cut off a remote SSH session.
  - `pushed` takes the firewall's routes.
- There is no kill switch and no IPv6 isolation: during an outage, traffic can fall back to the normal route.
- Profiles may contain only plain client directives. Scripts, plugins and extra config files are refused, because OpenVPN runs as root.
- `status` never contains credentials, seeds or codes.

## Security model

| Threat | Covered? |
| --- | --- |
| Disk, snapshot or backup copied to another machine | Yes with `enclave`, `tpm` or `aws`: the envelope cannot be unwrapped elsewhere. Not with `plain` or `totp_seed`. |
| Reading the seed from files at rest | Yes, except `plain`. |
| Someone with root on the running machine | No. Root can run `sophos totp code` or read daemon memory. Use manual codes if that matters. |

`--save-login` stores the password next to the profile's private key, so a copied disk then holds two of the three factors. The TOTP backend keeps the third. Manual mode keeps the TOTP factor on your phone.

## Other tools in this repo

- `authn` is a standalone TOTP printer using the same envelopes and backends: `authn import qr.png --store seed.envelope`, then `authn --store seed.envelope`. See [crates/authn-cli](crates/authn-cli).
- `ghvpn-tui` is an interactive harness that fetches the profile, connects, and probes a GitHub repo before and after the tunnel. Run it with `cargo run -p ghvpn-tui -- --gateway 203.0.113.10 --repo https://github.com/<org>/<repo>`.
- [SPEC.md](SPEC.md) describes a planned EC2 variant using a network namespace and a SOCKS proxy.

## Layout

- `crates/sophos-cli`: the `sophos` daemon and CLI.
- `crates/totp-core`: RFC 6238 codes, the `KeyProvider` trait, the envelope format.
- `crates/provider-{enclave,tpm,aws,secrets}`: TOTP backends.
- `crates/authn-cli`: QR/URI/key import and backend selection (library), and the `authn` binary.
- `crates/ghvpn-mgmt`: OpenVPN management-interface parser.
- `crates/ghvpn-tui`: the TUI harness.

## References

- [OpenVPN management interface](https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt)
- [TOTP, RFC 6238](https://www.rfc-editor.org/rfc/rfc6238)
- [Google Authenticator key URI format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
- [Reconstructed Google Authenticator export schema](https://github.com/qistoph/otp_export/blob/master/OtpMigration.proto)
- [rqrr QR decoder](https://github.com/WanzenBug/rqrr)
