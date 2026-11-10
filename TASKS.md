# Tasks

## Backends
- [x] TOTP core (RFC 6238, SHA1/256/512) verified against RFC test vectors
- [x] `secrets` backend (macOS, hardware-backed store)
- [ ] `enclave` backend (macOS Secure Enclave) — in progress, live roundtrip to verify
- [ ] `tpm` backend (Linux) — written on macOS, needs live seal/unseal on an EC2 Linux + TPM box
- [ ] `aws` backend (KMS / Secrets Manager) — written without creds, needs live verify on EC2 with an instance profile

## Live verification
- [ ] Enroll + generate through `secrets` end to end on this Mac (one-time Touch ID at enroll if `--allow never` loosening prompts)
- [ ] TPM: verify `systemd-creds` seal/unseal on EC2 (enable NitroTPM at launch, UEFI boot)
- [ ] AWS: verify KMS Encrypt/Decrypt via instance role on EC2; confirm a copied binary off-instance fails to unwrap

## Defense in depth (optional, runtime can be slow)
- [ ] Argon2id machine-key second wrap over stable host identifiers (adds latency that frustrates automated lifting)
- [ ] `obfstr` for string constants; confirm release profile strips symbols
- [ ] Optional anti-debug self-check (PT_DENY_ATTACH on macOS, ptrace on Linux) — marginal value, document as such
- [ ] zeroize + mlock the in-memory seed buffer end to end

## Packaging
- [ ] Decide envelope location + docs for multi-account use (multiple `--store` / `--name`)
- [ ] CI matrix (macOS + Linux) building each backend
