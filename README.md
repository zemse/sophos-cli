# sophos-pin-oracle

A small binary that prints a 6-digit TOTP (RFC 6238) authenticator code to
stdout. The seed is never embedded in the binary. It is wrapped at rest by a
hardware- or cloud-bound backend, so a copied binary is inert on any other
machine.

```
$ authn
492871
```

## What this does and does not protect

Be clear about the limit. If a binary can print the code with no human step,
then the seed must be reachable by the process at runtime, so anyone who can run
the binary on the enrolled machine can obtain codes. Embedding the seed and
obfuscating the binary does not change this (a copied, obfuscated binary is just
run as-is: code-lifting).

What the backends buy you is machine binding:

| Threat | Covered? |
| --- | --- |
| Binary or disk image copied and run on another machine | Yes. The wrapped seed cannot be unwrapped without this machine's Secure Enclave / TPM / IAM role, so the copy is inert. |
| Reading the raw seed out of the binary or envelope file at rest | Yes. Neither contains the seed. |
| Attacker with full access to the live enrolled machine who can run the binary | No, not without a per-use human step. This is out of scope by design (zero-interaction runtime). Obfuscation only raises their cost. |

This repo targets the first two. To also cover the third, enroll with a backend
mode that requires user presence (for example the `secrets` backend with
`--allow ask`), which trades away the zero-interaction property.

## Backends

Selected automatically (`--provider auto`) or forced by name.

| id | Platform | Mechanism |
| --- | --- | --- |
| `secrets` | macOS | Seed stored in the hardware-backed `secrets` store (zemse/macos-secrets) with `--allow never`; envelope holds only the secret name. |
| `enclave` | macOS | Seed ECIES-encrypted to a non-exportable Secure Enclave P-256 key. |
| `tpm` | Linux | Seed sealed to a TPM 2.0 (including AWS NitroTPM) via `systemd-creds`. |
| `aws` | EC2 without a TPM | Seed wrapped with KMS (or stored in Secrets Manager) and bound to the instance IAM role via IMDS. |

## Usage

```
# Enroll a setup key once (reads the base32 key from stdin if --key is omitted)
authn enroll --provider auto --key JBSWY3DPEHPK3PXP

# Print the current code (default subcommand)
authn

# See which backends are compiled and available on this host
authn providers
```

## Import an authenticator QR

```
# Use a new secret name and envelope path for each account
authn import /path/to/qr.png --name totp/sophos --store /path/to/sophos.envelope
authn --store /path/to/sophos.envelope
```

Import reads one QR from a PNG or JPEG locally and stores the decoded seed in
`secrets`. It never prints the setup key or passes it as a process argument.
The image must contain a single `otpauth://totp/...` QR, not an HOTP or Google
Authenticator migration QR. SHA1, SHA256 and SHA512, 6 or 8 digits, and periods
from 1 to 65535 seconds are supported. Omitted parameters default to SHA1,
6 digits and 30 seconds. Duplicate TOTP parameters and invalid values are refused.
Images are limited to 32 MiB, 8192 pixels per side and a 64 MiB decoder budget.

Existing envelope paths and existing secret names are refused. The name check is
not atomic with `secrets set`, so do not import or write the same name concurrently.
A failed import removes its new envelope, but may leave a secret entry behind;
check that name before retrying. The source image is unchanged and still contains
the seed, so protect it like the original setup key. Import defaults to
`--allow never` for prompt-free code generation; use `--allow ask` to require
approval when reading codes. Enrollment may require a one-time approval.

The URI parser follows the [Google Authenticator key URI format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format),
and image decoding uses [rqrr](https://github.com/WanzenBug/rqrr).

The enrolled state lives in a self-describing envelope at
`$XDG_CONFIG_HOME/sophos-pin-oracle/seed.envelope` (override with `--store`).
It records the backend id and the TOTP parameters, never the seed.

## Build

```
cargo build --release   # stripped, LTO, panic=abort binary at target/release/authn
```

## Layout

- `crates/totp-core` — RFC 6238 code generation, the `KeyProvider` trait, the envelope.
- `crates/provider-secrets` — macOS `secrets` backend.
- `crates/provider-enclave` — macOS Secure Enclave backend.
- `crates/provider-tpm` — Linux TPM backend.
- `crates/provider-aws` — EC2 KMS / Secrets Manager backend.
- `crates/authn-cli` — the `authn` binary.
