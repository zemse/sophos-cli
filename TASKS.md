# Tasks

## VPN
- [ ] First live run against 203.0.113.10 with real VPN + GitHub credentials (portal login status codes, OpenVPN port/proto, P4 VPN→WAN SNAT)
- [ ] Find the portal hostname on the `*.example.com` cert and make it the `--portal-host` default
- [ ] SPEC §4: Linux netns/veth isolation (`ghvpn-net`) for the EC2 daemon
- [ ] SPEC §8.1: SOCKS5 + HTTP CONNECT proxy with GitHub allowlist (`ghvpn-proxy`)
- [ ] SPEC §9: `ghvpnd` daemon + control socket + `ghvpn` CLI, reusing `ghvpn-mgmt`
- [ ] SPEC §7.2: AWS Secrets Manager loading, `secrecy`/zeroize for in-memory secrets
- [ ] SPEC §14.2: docker-compose OpenVPN test server with `auth-user-pass-verify` + TOTP

## Backends
- [x] TOTP core (RFC 6238, SHA1/256/512) verified against RFC test vectors
- [x] `secrets` backend (macOS, hardware-backed store)
- [x] `enclave` backend (macOS Secure Enclave) — live roundtrip + full enroll/code verified on this Mac (TOTP cross-checked against an independent computation)
- [ ] `tpm` backend (Linux) — written on macOS, needs live seal/unseal on an EC2 Linux + TPM box
- [ ] `aws` backend (KMS / Secrets Manager) — written without creds, needs live verify on EC2 with an instance profile

## Live verification
- [x] End-to-end enroll + code through the `enclave` backend on this Mac (zero interaction)
- [x] Enroll + generate through `secrets` end to end on this Mac (QR import with public seed, SHA256/8 digits/60s cross-checked independently)
- [x] Import a PNG/JPEG TOTP QR into `secrets` (parser + CLI tests, live roundtrip verified)
- [x] Import Google Authenticator migration QRs with account listing and selection (parser + CLI tests, live selected-account roundtrip verified)
- [ ] TPM: verify `systemd-creds` seal/unseal on EC2 (enable NitroTPM at launch, UEFI boot); confirm the stdin `--name` match behaviour and the tpm2-tools primary-recreation assumption
- [ ] AWS: verify KMS Encrypt/Decrypt via instance role on EC2 (export AWS_REGION); confirm a copied binary off-instance fails to unwrap

## Defense in depth (optional, runtime can be slow)
- [ ] Argon2id machine-key second wrap over stable host identifiers (adds latency that frustrates automated lifting)
- [ ] `obfstr` for string constants; release profile already strips symbols + LTO + panic=abort
- [ ] Optional anti-debug self-check (PT_DENY_ATTACH on macOS, ptrace on Linux) — marginal value, document as such
- [ ] zeroize + mlock the in-memory seed buffer end to end
- [ ] Optional `--tpm2-pcrs=` binding for tamper resistance (breaks on firmware/kernel updates)

## Packaging
- [ ] Decide envelope location + docs for multi-account use (multiple `--store` / `--name`)
- [ ] CI matrix (macOS + Linux) building each backend
- [ ] Codesign + keychain entitlement path if a SecKey-based enclave design is wanted later
