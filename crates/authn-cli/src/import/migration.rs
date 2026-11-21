//! Google Authenticator's version 1 and 2 migration protobuf format.

use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine as _,
};
use prost::Message;
use totp_core::{Algo, TotpParams};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use super::{Account, Provisioning};

// Field numbers follow qistoph/otp_export's reconstructed OtpMigration.proto.
#[derive(Clone, PartialEq, Message)]
struct MigrationPayload {
    #[prost(message, repeated, tag = "1")]
    accounts: Vec<OtpParameters>,
    #[prost(int32, optional, tag = "2")]
    version: Option<i32>,
    #[prost(int32, optional, tag = "3")]
    batch_size: Option<i32>,
    #[prost(int32, optional, tag = "4")]
    batch_index: Option<i32>,
    #[prost(int32, optional, tag = "5")]
    batch_id: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
struct OtpParameters {
    #[prost(bytes = "vec", optional, tag = "1")]
    secret: Option<Vec<u8>>,
    #[prost(string, optional, tag = "2")]
    name: Option<String>,
    #[prost(string, optional, tag = "3")]
    issuer: Option<String>,
    #[prost(int32, optional, tag = "4")]
    algorithm: Option<i32>,
    #[prost(int32, optional, tag = "5")]
    digits: Option<i32>,
    #[prost(int32, optional, tag = "6")]
    kind: Option<i32>,
    #[prost(int64, optional, tag = "7")]
    counter: Option<i64>,
}

impl Drop for OtpParameters {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

pub(super) fn parse(uri: &Url) -> Result<Vec<Account>, crate::Error> {
    if uri.host_str() != Some("offline")
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.port().is_some()
        || uri.fragment().is_some()
        || !matches!(uri.path(), "" | "/")
    {
        return Err("invalid Google Authenticator migration URI".into());
    }
    // A raw '+' is a Base64 symbol here, not a form-encoded space.
    let query = Zeroizing::new(uri.query().unwrap_or("").replace('+', "%2B"));
    let mut data = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if key == "data" {
            if data.is_some() {
                return Err("duplicate migration data parameter".into());
            }
            data = Some(Zeroizing::new(value.into_owned()));
        }
    }
    let data = data.ok_or("migration URI is missing its data")?;
    let bytes = STANDARD
        .decode(data.as_bytes())
        .or_else(|_| STANDARD_NO_PAD.decode(data.as_bytes()))
        .map_err(|_| "invalid migration Base64 data")?;
    let bytes = Zeroizing::new(bytes);
    let payload = MigrationPayload::decode(bytes.as_slice())
        .map_err(|_| "invalid migration protobuf data")?;
    if !matches!(payload.version, Some(1 | 2)) {
        return Err("unsupported migration version (expected version 1 or 2)".into());
    }
    if payload.batch_size != Some(1) || payload.batch_index.unwrap_or(0) != 0 {
        return Err("multi-QR or incomplete exports are unsupported; export only the desired account in Google Authenticator".into());
    }
    if payload.accounts.is_empty() || payload.accounts.len() > 100 {
        return Err("migration QR must contain between 1 and 100 accounts".into());
    }
    Ok(payload
        .accounts
        .into_iter()
        .map(|mut otp| {
            let provisioning = provisioning(&mut otp);
            Account {
                label: otp.name.take().unwrap_or_default(),
                issuer: otp.issuer.take().unwrap_or_default(),
                provisioning,
            }
        })
        .collect())
}

fn provisioning(otp: &mut OtpParameters) -> Result<Provisioning, &'static str> {
    match otp.kind {
        Some(2) => {}
        Some(1) => return Err("HOTP is unsupported"),
        _ => return Err("unsupported migration OTP type"),
    }
    if otp.counter.unwrap_or(0) != 0 {
        return Err("unexpected counter for migration TOTP account");
    }
    let algo = match otp.algorithm {
        Some(1) => Algo::Sha1,
        Some(2) => Algo::Sha256,
        Some(3) => Algo::Sha512,
        _ => return Err("unsupported migration algorithm"),
    };
    let digits = match otp.digits {
        Some(1) => 6,
        Some(2) => 8,
        _ => return Err("unsupported migration digit count"),
    };
    let seed = Zeroizing::new(otp.secret.take().unwrap_or_default());
    if seed.is_empty() {
        return Err("migration account has an empty seed");
    }
    Ok(Provisioning {
        seed,
        params: TotpParams {
            algo,
            digits,
            step: 30,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::{parse_accounts, select_account};

    const SINGLE: &str = include_str!("../../tests/fixtures/migration-single.txt");
    const MULTIPLE: &str = include_str!("../../tests/fixtures/migration-multiple.txt");
    const HOTP: &str = include_str!("../../tests/fixtures/migration-hotp.txt");
    const BATCH: &str = include_str!("../../tests/fixtures/migration-batch.txt");

    fn fixture_payload() -> MigrationPayload {
        let uri = Url::parse(SINGLE.trim()).unwrap();
        let (_, data) = uri.query_pairs().next().unwrap();
        MigrationPayload::decode(STANDARD.decode(data.as_bytes()).unwrap().as_slice()).unwrap()
    }

    fn uri(payload: &MigrationPayload) -> String {
        let mut uri = Url::parse("otpauth-migration://offline").unwrap();
        uri.query_pairs_mut()
            .append_pair("data", &STANDARD.encode(payload.encode_to_vec()));
        uri.into()
    }

    #[test]
    fn single_account_preserves_seed_and_parameters() {
        let accounts = parse_accounts(SINGLE.trim()).unwrap();
        assert_eq!(accounts[0].label, "Example:alice");
        assert_eq!(accounts[0].issuer, "Example");
        let p = select_account(accounts, None).unwrap();
        assert_eq!(&*p.seed, b"12345678901234567890");
        assert_eq!(p.params.algo, Algo::Sha1);
        assert_eq!(p.params.digits, 6);
        assert_eq!(p.params.step, 30);
    }

    #[test]
    fn version_two_preserves_seed_and_parameters() {
        let content = include_str!("../../tests/fixtures/migration-v2.txt");
        let p = select_account(parse_accounts(content.trim()).unwrap(), None).unwrap();
        assert_eq!(&*p.seed, b"12345678901234567890");
        assert_eq!(p.params.algo, Algo::Sha1);
        assert_eq!(p.params.digits, 6);
        assert_eq!(p.params.step, 30);
    }

    #[test]
    fn multi_account_requires_selection_and_preserves_second_account() {
        assert!(select_account(parse_accounts(MULTIPLE.trim()).unwrap(), None).is_err());
        for invalid in [0, 3, usize::MAX] {
            assert!(
                select_account(parse_accounts(MULTIPLE.trim()).unwrap(), Some(invalid)).is_err()
            );
        }
        let p = select_account(parse_accounts(MULTIPLE.trim()).unwrap(), Some(2)).unwrap();
        assert_eq!(&*p.seed, b"12345678901234567890123456789012");
        assert_eq!(p.params.algo, Algo::Sha256);
        assert_eq!(p.params.digits, 8);
        assert_eq!(p.params.step, 30);
    }

    #[test]
    fn rejects_hotp_batches_and_bad_metadata() {
        assert!(select_account(parse_accounts(HOTP.trim()).unwrap(), None).is_err());
        assert!(parse_accounts(BATCH.trim()).is_err());
        let mut payload = fixture_payload();
        payload.version = Some(3);
        assert!(parse_accounts(&uri(&payload)).is_err());
        payload.version = None;
        assert!(parse_accounts(&uri(&payload)).is_err());
        payload.version = Some(1);
        for size in [None, Some(0), Some(-1), Some(2)] {
            payload.batch_size = size;
            assert!(parse_accounts(&uri(&payload)).is_err());
        }
        payload.batch_size = Some(1);
        payload.batch_index = Some(1);
        assert!(parse_accounts(&uri(&payload)).is_err());
        payload.batch_index = Some(0);
        payload.accounts.clear();
        assert!(parse_accounts(&uri(&payload)).is_err());
    }

    #[test]
    fn rejects_unsupported_account_parameters() {
        for (field, value) in [
            ("algorithm", 0),
            ("algorithm", 4),
            ("algorithm", 99),
            ("digits", 0),
            ("digits", 99),
            ("kind", 0),
            ("kind", 99),
        ] {
            let mut payload = fixture_payload();
            let otp = &mut payload.accounts[0];
            match field {
                "algorithm" => otp.algorithm = Some(value),
                "digits" => otp.digits = Some(value),
                _ => otp.kind = Some(value),
            }
            assert!(select_account(parse_accounts(&uri(&payload)).unwrap(), None).is_err());
        }
        let mut payload = fixture_payload();
        payload.accounts[0].secret = Some(Vec::new());
        assert!(select_account(parse_accounts(&uri(&payload)).unwrap(), None).is_err());
        let mut payload = fixture_payload();
        payload.accounts[0].counter = Some(1);
        assert!(select_account(parse_accounts(&uri(&payload)).unwrap(), None).is_err());
    }

    #[test]
    fn accepts_sha512_and_standard_base64_forms() {
        let mut payload = fixture_payload();
        payload.accounts[0].algorithm = Some(3);
        payload.accounts[0].digits = Some(2);
        payload.accounts[0].secret = Some(vec![255; 20]);
        let encoded = STANDARD.encode(payload.encode_to_vec());
        for data in [encoded.clone(), encoded.trim_end_matches('=').to_owned()] {
            let raw = format!("otpauth-migration://offline?data={data}");
            let p = select_account(parse_accounts(&raw).unwrap(), None).unwrap();
            assert_eq!(p.params.algo, Algo::Sha512);
            assert_eq!(p.params.digits, 8);
            assert_eq!(&*p.seed, &[255; 20]);
        }
    }

    #[test]
    fn malformed_inputs_do_not_echo_payload() {
        for content in [
            "otpauth-migration://wrong?data=PRIVATE_MARKER",
            "otpauth-migration://offline",
            "otpauth-migration://offline?data=PRIVATE_MARKER",
            "otpauth-migration://offline?data=AA==",
            "otpauth-migration://offline?data=CA==",
            "otpauth-migration://offline?data=AA==&data=AA==",
            "otpauth-migration://offline?data=AA==#PRIVATE_MARKER",
            "otpauth-migration://user@offline?data=AA==",
        ] {
            let error = parse_accounts(content).err().unwrap().to_string();
            assert!(!error.contains("PRIVATE_MARKER"));
            assert!(!error.contains("AA=="));
        }
    }
}
