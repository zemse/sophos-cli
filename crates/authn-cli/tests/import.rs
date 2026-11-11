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
        cmd.arg("import").arg(image).args(["--name", NAME]);
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
