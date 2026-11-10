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
