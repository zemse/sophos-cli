//! Import TOTP provisioning and migration QRs without displaying seeds.

mod migration;

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use image::{ImageFormat, ImageReader, Limits};
use provider_secrets::SecretsProvider;
use totp_core::{decode_setup_key, Algo, Envelope, KeyProvider, TotpParams};
use url::Url;
use zeroize::Zeroizing;

struct Provisioning {
    seed: Zeroizing<Vec<u8>>,
    params: TotpParams,
}

struct Account {
    label: String,
    issuer: String,
    provisioning: Result<Provisioning, &'static str>,
}

pub fn run(
    image: &Path,
    store: &Path,
    name: Option<&str>,
    allow: &str,
    account: Option<usize>,
    list: bool,
) -> Result<(), Box<dyn Error>> {
    let content = read_qr(image)?;
    let accounts = parse_accounts(&content)?;
    if list {
        for (index, account) in accounts.iter().enumerate() {
            let status = match &account.provisioning {
                Ok(_) => "TOTP",
                Err(reason) => reason,
            };
            println!(
                "{}\t{}\t{}\t{}",
                index + 1,
                account.issuer.escape_debug(),
                account.label.escape_debug(),
                status
            );
        }
        return Ok(());
    }
    let provisioning = select_account(accounts, account)?;
    let name = name.ok_or("--name is required for import")?;
    if name.is_empty() || name.starts_with('-') || name.chars().any(char::is_control) {
        return Err(
            "secret name must be nonempty, not start with '-' and contain no control characters"
                .into(),
        );
    }
    let provider = SecretsProvider::new(name).with_allow(allow);
    if !provider.available() {
        return Err("secrets backend is not available on this host".into());
    }
    if provider.exists()? {
        return Err("secret name already exists; choose a new --name".into());
    }
    if let Some(parent) = store.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(store).map_err(|_| {
        "cannot create envelope; choose a new --store path and check directory permissions"
    })?;
    let result = (|| -> Result<(), Box<dyn Error>> {
        let payload = provider
            .wrap(&provisioning.seed)
            .map_err(|_| "secrets enrollment failed")?;
        let envelope = Envelope::new(provider.id(), provisioning.params, payload);
        file.write_all(&envelope.encode()?)?;
        file.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        drop(file);
        let _ = fs::remove_file(store);
        eprintln!("import failed; a secret entry may remain under the requested name");
    }
    result?;
    eprintln!("imported via `secrets` backend -> {}", store.display());
    Ok(())
}

fn select_account(
    accounts: Vec<Account>,
    number: Option<usize>,
) -> Result<Provisioning, Box<dyn Error>> {
    let number = match number {
        Some(number) => number,
        None if accounts.len() == 1 => 1,
        None => {
            return Err(
                "multiple accounts in QR; use --list, then select with --account NUMBER".into(),
            )
        }
    };
    let index = number.checked_sub(1).ok_or("account numbers start at 1")?;
    let account = accounts
        .into_iter()
        .nth(index)
        .ok_or("account number is out of range")?;
    account.provisioning.map_err(Into::into)
}

fn parse_accounts(content: &str) -> Result<Vec<Account>, Box<dyn Error>> {
    if content.len() > 16384 || content.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("invalid authenticator URI".into());
    }
    let uri = Url::parse(content).map_err(|_| "invalid authenticator URI")?;
    if uri.scheme() == "otpauth-migration" {
        return migration::parse(&uri);
    }
    let provisioning = parse_uri(content)?;
    Ok(vec![Account {
        label: uri.path().trim_start_matches('/').to_owned(),
        issuer: String::new(),
        provisioning: Ok(provisioning),
    }])
}

fn read_qr(path: &Path) -> Result<Zeroizing<String>, Box<dyn Error>> {
    if fs::metadata(path)?.len() > 32 * 1024 * 1024 {
        return Err("QR image exceeds the 32 MiB file limit".into());
    }
    let mut reader = ImageReader::open(path)?.with_guessed_format()?;
    if !matches!(reader.format(), Some(ImageFormat::Png | ImageFormat::Jpeg)) {
        return Err("QR image must be PNG or JPEG".into());
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(8192);
    limits.max_image_height = Some(8192);
    limits.max_alloc = Some(64 * 1024 * 1024);
    reader.limits(limits);
    let image = reader
        .decode()
        .map_err(|_| "cannot decode QR image within image limits")?
        .into_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(image);
    let grids = prepared.detect_grids();
    if grids.len() != 1 {
        return Err("expected exactly one QR code in the image".into());
    }
    let (_, content) = grids[0].decode().map_err(|_| "cannot decode QR code")?;
    Ok(Zeroizing::new(content))
}

fn parse_uri(content: &str) -> Result<Provisioning, Box<dyn Error>> {
    if content.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("invalid authenticator URI".into());
    }
    let uri = Url::parse(content).map_err(|_| "invalid authenticator URI")?;
    if uri.scheme() != "otpauth"
        || uri.host_str() != Some("totp")
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.port().is_some()
        || uri.fragment().is_some()
        || uri.path().trim_matches('/').is_empty()
    {
        return Err(
            "expected an otpauth TOTP or Google Authenticator migration URI (HOTP is unsupported)"
                .into(),
        );
    }
    let mut secret = None;
    let mut algorithm = None;
    let mut digits = None;
    let mut period = None;
    for (key, value) in uri.query_pairs() {
        let slot = match key.as_ref() {
            "secret" => &mut secret,
            "algorithm" => &mut algorithm,
            "digits" => &mut digits,
            "period" => &mut period,
            "counter" => return Err("HOTP counter is unsupported for TOTP import".into()),
            _ => continue,
        };
        if slot.is_some() {
            return Err("duplicate authenticator parameter".into());
        }
        *slot = Some(Zeroizing::new(value.into_owned()));
    }
    let secret = secret.ok_or("authenticator URI is missing its secret")?;
    let seed = decode_setup_key(&secret)?;
    if seed.is_empty() {
        return Err("authenticator seed is empty".into());
    }
    let algo = match algorithm
        .as_deref()
        .map(|s| s.as_str())
        .unwrap_or("SHA1")
        .to_ascii_uppercase()
        .as_str()
    {
        "SHA1" => Algo::Sha1,
        "SHA256" => Algo::Sha256,
        "SHA512" => Algo::Sha512,
        _ => return Err("unsupported authenticator algorithm".into()),
    };
    let digits = digits
        .map(|s| s.parse::<u8>())
        .transpose()
        .map_err(|_| "invalid authenticator digits")?
        .unwrap_or(6);
    if !matches!(digits, 6 | 8) {
        return Err("authenticator digits must be 6 or 8".into());
    }
    let step = period
        .map(|s| s.parse::<u16>())
        .transpose()
        .map_err(|_| "invalid authenticator period")?
        .unwrap_or(30);
    if step == 0 {
        return Err("authenticator period must be between 1 and 65535 seconds".into());
    }
    Ok(Provisioning {
        seed,
        params: TotpParams { digits, step, algo },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const URI: &str = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example";

    #[test]
    fn defaults() {
        let p = parse_uri(URI).unwrap();
        assert_eq!(&*p.seed, b"Hello!\xde\xad\xbe\xef");
        assert_eq!(p.params.algo, Algo::Sha1);
        assert_eq!(p.params.digits, 6);
        assert_eq!(p.params.step, 30);
    }

    #[test]
    fn preserves_parameters_and_percent_decoding() {
        for (algorithm, expected) in [
            ("sha1", Algo::Sha1),
            ("SHA256", Algo::Sha256),
            ("SHA512", Algo::Sha512),
        ] {
            let uri = format!("otpauth://totp/Example%3Aalice?secret=%4ABSwy3DPEHPK3PXP&algorithm={algorithm}&digits=8&period=60");
            let p = parse_uri(&uri).unwrap();
            assert_eq!(&*p.seed, b"Hello!\xde\xad\xbe\xef");
            assert_eq!(p.params.algo, expected);
            assert_eq!(p.params.digits, 8);
            assert_eq!(p.params.step, 60);
        }
    }

    #[test]
    fn rejects_unsupported_and_malformed_uris() {
        for uri in [
            "not a uri",
            "https://example.com",
            "otpauth-migration://offline?data=test",
            "otpauth://hotp/alice?secret=ABC&counter=1",
            "otpauth://totp/?secret=ABC",
            "otpauth://user@totp/alice?secret=ABC",
            "otpauth://totp/alice",
            "otpauth://totp/alice?secret=",
            "otpauth://totp/alice?secret=!!!",
        ] {
            assert!(parse_uri(uri).is_err(), "accepted malformed fixture");
        }
        for suffix in [
            "&digits=0",
            "&digits=7",
            "&digits=10",
            "&digits=x",
            "&period=0",
            "&period=-1",
            "&period=65536",
            "&algorithm=MD5",
            "&secret=ABC",
            "&counter=1",
            "#fragment",
            "&digits=6&digits=8",
            "&algorithm=SHA1&algorithm=SHA256",
            "&period=30&period=60",
        ] {
            assert!(
                parse_uri(&format!("{URI}{suffix}")).is_err(),
                "accepted malformed fixture"
            );
        }
    }

    #[test]
    fn errors_do_not_echo_uri_or_secret() {
        let uri = format!("{URI}&algorithm=PRIVATE_MARKER");
        let error = parse_uri(&uri).err().unwrap().to_string();
        assert!(!error.contains("JBSWY"));
        assert!(!error.contains("PRIVATE_MARKER"));
        assert!(!error.contains("otpauth"));
    }
}
