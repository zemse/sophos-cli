# QR fixtures

All seeds are public examples, not real credentials.

- `totp.png`: Google example seed, SHA256, 8 digits, 60-second period.
- `migration-single`: Alice, RFC 6238 SHA1 seed, 6 digits.
- `migration-multiple`: Alice plus Bob, RFC 6238 SHA256 seed, 8 digits.
- `migration-hotp`: counter-based account, unsupported by this TOTP CLI.
- `migration-batch`: first QR of a two-QR export, incomplete on its own.

Migration fixtures include PNG images and their URI text. They use version 1,
batch index 0 and batch ID 42. Migration data has no period field; TOTP uses
30 seconds.

Regenerate with `python3 generate_migration.py` from this directory. Requires
the existing `qrrs` binary. The generator checks each PNG by decoding it back
to the original URI.

Field numbers and enum values follow the [reconstructed migration schema](https://github.com/qistoph/otp_export/blob/master/OtpMigration.proto).
