//! Import TOTP provisioning and migration QRs, otpauth URIs and base32 setup
//! keys without displaying seeds.

mod migration;

use std::fs::{self, File};
use std::io::{Cursor, Read};
use std::path::Path;

use image::{ImageFormat, ImageReader, Limits};
use provider_secrets::SecretsProvider;
use totp_core::{decode_setup_key, Algo, TotpParams};
use url::Url;
use zeroize::Zeroizing;

use crate::Error;

const INPUT_LIMIT: u64 = 32 * 1024 * 1024;

struct Provisioning {
    seed: Zeroizing<Vec<u8>>,
    params: TotpParams,
}

struct Account {
    label: String,
    issuer: String,
    provisioning: Result<Provisioning, &'static str>,
}

pub struct Options<'a> {
    /// Backend id or `auto`.
    pub provider: &'a str,
    /// Entry name, required by the `secrets` backend only.
    pub name: Option<&'a str>,
    pub allow: &'a str,
    pub account: Option<usize>,
    pub list: bool,
}

/// Import from `source`: a PNG/JPEG QR, an otpauth URI or a base32 key, read
/// from a file or from stdin when `source` is `-`.
pub fn run(source: &Path, store: &Path, options: &Options) -> Result<(), Error> {
    let content = read_source(source)?;
    let accounts = parse_accounts(&content)?;
    if options.list {
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
    let provisioning = select_account(accounts, options.account)?;
    if let Some(name) = options.name {
        if name.is_empty() || name.starts_with('-') || name.chars().any(char::is_control) {
            return Err(
                "secret name must be nonempty, not start with '-' and contain no control characters"
                    .into(),
            );
        }
    }
    let provider = crate::choose_provider(
        options.provider,
        options.name.unwrap_or_default(),
        options.allow,
    )?;
    let secrets = provider.id() == "secrets";
    if secrets {
        let name = options
            .name
            .ok_or("--name is required for the secrets backend")?;
        if SecretsProvider::new(name).exists()? {
            return Err("secret name already exists; choose a new --name".into());
        }
    }
    let result = crate::write_envelope(
        store,
        provider.as_ref(),
        &provisioning.seed,
        provisioning.params,
    );
    if result.is_err() && secrets {
        eprintln!("import failed; a secret entry may remain under the requested name");
    }
    result?;
    eprintln!(
        "imported via `{}` backend -> {}",
        provider.id(),
        store.display()
    );
    Ok(())
}

fn select_account(accounts: Vec<Account>, number: Option<usize>) -> Result<Provisioning, Error> {
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

fn parse_accounts(content: &str) -> Result<Vec<Account>, Error> {
    if !content.contains(':') {
        let key: String = content.chars().filter(|c| !c.is_whitespace()).collect();
        if !key
            .bytes()
            .all(|b| b.is_ascii_alphabetic() || (b'2'..=b'7').contains(&b) || b == b'=')
        {
            return Err("input is not a QR image, otpauth URI or base32 setup key".into());
        }
        let seed = decode_setup_key(&key)?;
        if seed.len() < 10 {
            return Err("setup key must contain at least 80 bits (16 base32 characters)".into());
        }
        return Ok(vec![Account {
            label: "setup key".into(),
            issuer: String::new(),
            provisioning: Ok(Provisioning {
                seed,
                params: TotpParams::default(),
            }),
        }]);
    }
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

fn read_source(path: &Path) -> Result<Zeroizing<String>, Error> {
    let mut bytes = Zeroizing::new(Vec::new());
    if path == Path::new("-") {
        std::io::stdin()
            .lock()
            .take(INPUT_LIMIT + 1)
            .read_to_end(&mut bytes)?;
    } else {
        if fs::metadata(path)?.len() > INPUT_LIMIT {
            return Err("input exceeds the 32 MiB limit".into());
        }
        File::open(path)?
            .take(INPUT_LIMIT + 1)
            .read_to_end(&mut bytes)?;
    }
    if bytes.len() as u64 > INPUT_LIMIT {
        return Err("input exceeds the 32 MiB limit".into());
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") || bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        return read_qr(&bytes);
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "input must be a PNG or JPEG QR, an otpauth URI or a base32 setup key")?;
    let text = text.trim();
    if text.is_empty() {
        return Err("input is empty".into());
    }
    Ok(Zeroizing::new(text.to_owned()))
}

fn read_qr(bytes: &[u8]) -> Result<Zeroizing<String>, Error> {
    let mut reader = ImageReader::new(Cursor::new(bytes)).with_guessed_format()?;
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

fn parse_uri(content: &str) -> Result<Provisioning, Error> {
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
    fn accepts_base32_setup_keys_and_rejects_short_or_arbitrary_text() {
        let accounts = parse_accounts("jbsw y3dp ehpk 3pxp").unwrap();
        let p = accounts.into_iter().next().unwrap().provisioning.unwrap();
        assert_eq!(&*p.seed, b"Hello!\xde\xad\xbe\xef");
        assert_eq!(p.params.digits, 6);
        for text in ["not an image", "JBSWY3DP", "JBSWY3DPEHPK3PX1"] {
            assert!(parse_accounts(text).is_err());
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
