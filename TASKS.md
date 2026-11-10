# Tasks

## Backends
- [x] TOTP core (RFC 6238, SHA1/256/512) verified against RFC test vectors
- [x] `secrets` backend (macOS, hardware-backed store)
- [x] `enclave` backend (macOS Secure Enclave) — live roundtrip + full enroll/code verified on this Mac (TOTP cross-checked against an independent computation)
- [ ] `tpm` backend (Linux) — written on macOS, needs live seal/unseal on an EC2 Linux + TPM box
- [ ] `aws` backend (KMS / Secrets Manager) — written without creds, needs live verify on EC2 with an instance profile

## Live verification
- [x] End-to-end enroll + code through the `enclave` backend on this Mac (zero interaction)
- [ ] Enroll + generate through `secrets` end to end on this Mac (one-time Touch ID at enroll if `--allow never` loosening prompts)
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
