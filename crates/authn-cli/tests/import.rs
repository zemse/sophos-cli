#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use totp_core::{Algo, Envelope};

static NEXT: AtomicU64 = AtomicU64::new(0);
// Public Google example seed, SHA256, 8 digits, 60-second period.
const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/totp.png");
const NAME: &str = "totp/import-test";
const MIGRATION_SINGLE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/migration-single.png"
);
const MIGRATION_V2: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/migration-v2.png"
);
const MIGRATION_MULTIPLE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/migration-multiple.png"
);
const MIGRATION_HOTP: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/migration-hotp.png"
);
const MIGRATION_BATCH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/migration-batch.png"
);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "authn-import-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let bin = path.join("secrets");
        fs::write(
            &bin,
            r#"#!/bin/sh
printf '%s\n' "$1" >> "$TEST_DIR/calls"
case "$1" in
    --version|status) exit 0 ;;
    list) if [ "$EXISTING" = yes ]; then printf '%s\n' 'totp/import-test'; fi ;;
    set)
        printf '%s\n' "$*" > "$TEST_DIR/args"
        if [ "$FAIL_SET" = yes ]; then printf '%s\n' '48656c6c6f21deadbeef' >&2; exit 1; fi
        cat > "$TEST_DIR/seed"
        ;;
    get) cat "$TEST_DIR/seed" ;;
    *) exit 1 ;;
esac
"#,
        )
        .unwrap();
        fs::set_permissions(bin, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_authn"));
        cmd.env("PATH", format!("{}:/usr/bin:/bin", self.0.display()))
            .env("TEST_DIR", &self.0)
            .env_remove("EXISTING")
            .env_remove("FAIL_SET")
            .arg("--store")
            .arg(self.0.join("seed.envelope"));
        cmd
    }

    fn import(&self, image: &Path) -> Command {
        let mut cmd = self.command();
        cmd.arg("import")
            .arg(image)
            .args(["--provider", "secrets", "--name", NAME]);
        cmd
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn assert_private_failure(output: Output) {
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("JBSWY3DPEHPK3PXP"));
    assert!(!stderr.contains("48656c6c6f21deadbeef"));
    assert!(!stderr.contains("12345678901234567890"));
}

#[test]
fn image_import_and_code_through_secrets_protocol() {
    let dir = TestDir::new();
    let result = dir.import(Path::new(FIXTURE)).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty());
    let store = dir.0.join("seed.envelope");
    let envelope = Envelope::decode(&fs::read(&store).unwrap()).unwrap();
    assert_eq!(envelope.provider_id, "secrets");
    assert_eq!(envelope.payload, NAME.as_bytes());
    assert_eq!(envelope.params.algo, Algo::Sha256);
    assert_eq!(envelope.params.digits, 8);
    assert_eq!(envelope.params.step, 60);
    assert_eq!(
        fs::metadata(store).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::read_to_string(dir.0.join("args")).unwrap(),
        "set totp/import-test --allow never\n"
    );
    assert_eq!(
        fs::read_to_string(dir.0.join("seed")).unwrap(),
        "48656c6c6f21deadbeef"
    );
    let code = dir.command().arg("code").output().unwrap();
    assert!(code.status.success());
    let code = String::from_utf8(code.stdout).unwrap();
    assert_eq!(code.trim().len(), 8);
    assert!(code.trim().bytes().all(|b| b.is_ascii_digit()));
}

#[test]
fn migration_listing_is_read_only_and_excludes_seeds() {
    let dir = TestDir::new();
    let result = dir
        .command()
        .args(["import", MIGRATION_MULTIPLE, "--list"])
        .output()
        .unwrap();
    assert!(result.status.success());
    assert_eq!(
        String::from_utf8(result.stdout).unwrap(),
        "1\tExample\tExample:alice\tTOTP\n2\tExample\tExample:bob\tTOTP\n"
    );
    assert!(result.stderr.is_empty());
    assert!(!dir.0.join("calls").exists());
    assert!(!dir.0.join("seed.envelope").exists());
}

#[test]
fn migration_import_selects_exact_account_and_preserves_parameters() {
    for (fixture, selection, seed, algo, digits) in [
        (
            MIGRATION_SINGLE,
            None,
            &b"12345678901234567890"[..],
            Algo::Sha1,
            6,
        ),
        (
            MIGRATION_V2,
            None,
            &b"12345678901234567890"[..],
            Algo::Sha1,
            6,
        ),
        (
            MIGRATION_MULTIPLE,
            Some("2"),
            &b"12345678901234567890123456789012"[..],
            Algo::Sha256,
            8,
        ),
    ] {
        let dir = TestDir::new();
        let mut cmd = dir.import(Path::new(fixture));
        if let Some(number) = selection {
            cmd.args(["--account", number]);
        }
        let result = cmd.output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(result.stdout.is_empty());
        let expected_hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            fs::read_to_string(dir.0.join("seed")).unwrap(),
            expected_hex
        );
        assert_eq!(
            fs::read_to_string(dir.0.join("args")).unwrap(),
            "set totp/import-test --allow never\n"
        );
        let envelope = Envelope::decode(&fs::read(dir.0.join("seed.envelope")).unwrap()).unwrap();
        assert_eq!(envelope.provider_id, "secrets");
        assert_eq!(envelope.payload, NAME.as_bytes());
        assert_eq!(envelope.params.algo, algo);
        assert_eq!(envelope.params.digits, digits);
        assert_eq!(envelope.params.step, 30);
        let code = dir.command().arg("code").output().unwrap();
        assert!(code.status.success());
        assert_eq!(
            String::from_utf8(code.stdout).unwrap().trim().len(),
            usize::from(digits)
        );
    }
}

#[test]
fn migration_rejects_ambiguous_unsupported_or_invalid_selection_before_storage() {
    for (fixture, selection) in [
        (MIGRATION_MULTIPLE, None),
        (MIGRATION_MULTIPLE, Some("0")),
        (MIGRATION_MULTIPLE, Some("3")),
        (MIGRATION_HOTP, None),
        (MIGRATION_BATCH, None),
    ] {
        let dir = TestDir::new();
        let mut cmd = dir.import(Path::new(fixture));
        if let Some(number) = selection {
            cmd.args(["--account", number]);
        }
        assert_private_failure(cmd.output().unwrap());
        assert!(!dir.0.join("calls").exists());
        assert!(!dir.0.join("seed.envelope").exists());
    }
}

#[test]
fn migration_keeps_overwrite_guards() {
    let dir = TestDir::new();
    assert_private_failure(
        dir.import(Path::new(MIGRATION_SINGLE))
            .env("EXISTING", "yes")
            .output()
            .unwrap(),
    );
    assert!(!dir.0.join("args").exists());
    fs::write(dir.0.join("seed.envelope"), b"existing enrollment").unwrap();
    assert_private_failure(dir.import(Path::new(MIGRATION_SINGLE)).output().unwrap());
    assert_eq!(
        fs::read(dir.0.join("seed.envelope")).unwrap(),
        b"existing enrollment"
    );
    assert!(!dir.0.join("args").exists());
}

#[test]
fn jpeg_import_preserves_allow_setting() {
    let dir = TestDir::new();
    let jpeg = dir.0.join("qr.jpg");
    image::open(FIXTURE)
        .unwrap()
        .into_rgb8()
        .save(&jpeg)
        .unwrap();
    let result = dir.import(&jpeg).args(["--allow", "ask"]).output().unwrap();
    assert!(result.status.success());
    assert!(result.stdout.is_empty());
    assert_eq!(
        fs::read_to_string(dir.0.join("args")).unwrap(),
        "set totp/import-test --allow ask\n"
    );
}

#[test]
fn image_limits_are_enforced_before_enrollment() {
    let dir = TestDir::new();
    let huge = dir.0.join("huge.png");
    fs::File::create(&huge)
        .unwrap()
        .set_len(32 * 1024 * 1024 + 1)
        .unwrap();
    assert_private_failure(dir.import(&huge).output().unwrap());
    image::GrayImage::from_pixel(8193, 1, image::Luma([255]))
        .save(&huge)
        .unwrap();
    assert_private_failure(dir.import(&huge).output().unwrap());
    assert!(!dir.0.join("args").exists());
}

#[test]
fn existing_secret_or_envelope_is_not_overwritten() {
    let dir = TestDir::new();
    assert_private_failure(
        dir.import(Path::new(FIXTURE))
            .env("EXISTING", "yes")
            .output()
            .unwrap(),
    );
    assert!(!dir.0.join("args").exists());
    let store = dir.0.join("seed.envelope");
    fs::write(&store, b"existing enrollment").unwrap();
    assert_private_failure(dir.import(Path::new(FIXTURE)).output().unwrap());
    assert_eq!(fs::read(store).unwrap(), b"existing enrollment");
    assert!(!dir.0.join("args").exists());
}

#[test]
fn backend_failure_removes_reserved_envelope() {
    let dir = TestDir::new();
    assert_private_failure(
        dir.import(Path::new(FIXTURE))
            .env("FAIL_SET", "yes")
            .output()
            .unwrap(),
    );
    assert!(!dir.0.join("seed.envelope").exists());
}

#[test]
fn rejects_missing_corrupt_blank_and_multiple_qr_images() {
    let dir = TestDir::new();
    let missing = dir.0.join("missing.png");
    assert_private_failure(dir.import(&missing).output().unwrap());
    let corrupt = dir.0.join("corrupt.png");
    fs::write(&corrupt, b"not an image").unwrap();
    assert_private_failure(dir.import(&corrupt).output().unwrap());
    let blank = dir.0.join("blank.png");
    image::GrayImage::from_pixel(400, 400, image::Luma([255]))
        .save(&blank)
        .unwrap();
    assert_private_failure(dir.import(&blank).output().unwrap());
    let fixture = image::open(FIXTURE).unwrap().into_luma8();
    let mut multiple =
        image::GrayImage::from_pixel(fixture.width() * 2, fixture.height(), image::Luma([255]));
    image::imageops::replace(&mut multiple, &fixture, 0, 0);
    image::imageops::replace(&mut multiple, &fixture, i64::from(fixture.width()), 0);
    let path = dir.0.join("multiple.png");
    multiple.save(&path).unwrap();
    assert_private_failure(dir.import(&path).output().unwrap());
    assert!(!dir.0.join("args").exists());
    assert!(!dir.0.join("seed.envelope").exists());
}

#[test]
fn stdin_uri_import_into_plain_backend_generates_codes() {
    use std::io::Write;
    use std::process::Stdio;
    let dir = TestDir::new();
    let mut child = dir
        .command()
        .args(["import", "-", "--provider", "plain"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&digits=8\n")
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let store = dir.0.join("seed.envelope");
    let envelope = Envelope::decode(&fs::read(&store).unwrap()).unwrap();
    assert_eq!(envelope.provider_id, "plain");
    assert_eq!(envelope.params.digits, 8);
    assert!(!dir.0.join("args").exists());
    let code = dir.command().arg("code").output().unwrap();
    assert!(code.status.success());
    assert_eq!(String::from_utf8(code.stdout).unwrap().trim().len(), 8);
    let again = dir
        .command()
        .args(["import", FIXTURE, "--provider", "plain"])
        .output()
        .unwrap();
    assert_private_failure(again);
}
