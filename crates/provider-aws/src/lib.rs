//! Seed backend for cloud Linux hosts without a TPM (e.g. plain EC2).
//!
//! The root of trust is the instance IAM role, reached via IMDS through the
//! default AWS credential chain, not local hardware. A binary + envelope copied
//! off the instance has no IAM role, so the payload is inert (threat model:
//! stolen binary). Enforce IMDSv2 on the instance. Runtime needs no user input.
//!
//! Two modes, chosen by `SPO_AWS_MODE` (`kms` default, or `secretsmanager`):
//!   * KMS: `wrap` = `kms:Encrypt` the seed under `SPO_AWS_KMS_KEY_ID`; the
//!     payload is the raw ciphertext blob. `unwrap` = `kms:Decrypt`. An
//!     EncryptionContext `{app: SPO_AWS_CONTEXT or "sophos-pin-oracle"}` is
//!     bound at both ends.
//!   * Secrets Manager: `wrap` = create (or put a new version of) the secret
//!     `SPO_AWS_SECRET_NAME` holding the seed; the payload is the secret name
//!     as UTF-8. `unwrap` = `GetSecretValue`.
//!
//! The trait is sync, so each call builds a current-thread tokio runtime.
//! TLS is rustls (the SDK default), so no OpenSSL is needed.
//!
//! IAM: KMS needs `kms:Encrypt` (enroll) and `kms:Decrypt` (runtime) on the key.
//! Secrets Manager needs `secretsmanager:CreateSecret` + `PutSecretValue`
//! (enroll) and `secretsmanager:GetSecretValue` (runtime).
//! Not live-tested: verify on EC2 with an instance profile granting these.

use std::future::Future;

use totp_core::{KeyProvider, ProviderError};
use zeroize::Zeroizing;

pub const ENV_MODE: &str = "SPO_AWS_MODE";
pub const ENV_KMS_KEY_ID: &str = "SPO_AWS_KMS_KEY_ID";
pub const ENV_SECRET_NAME: &str = "SPO_AWS_SECRET_NAME";
pub const ENV_CONTEXT: &str = "SPO_AWS_CONTEXT";
/// Default EncryptionContext value when `SPO_AWS_CONTEXT` is unset.
pub const DEFAULT_CONTEXT: &str = "sophos-pin-oracle";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Kms { key_id: String, context: String },
    SecretsManager { name: String },
}

impl Mode {
    /// Parse config from an env lookup. `None` when the mode's required
    /// setting is missing; `Err` for an unknown mode string.
    fn parse(get: impl Fn(&str) -> Option<String>) -> Result<Option<Mode>, ProviderError> {
        let non_empty = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        let mode = non_empty(ENV_MODE).unwrap_or_else(|| "kms".into());
        match mode.trim().to_ascii_lowercase().as_str() {
            "kms" => Ok(non_empty(ENV_KMS_KEY_ID).map(|key_id| Mode::Kms {
                key_id,
                context: non_empty(ENV_CONTEXT).unwrap_or_else(|| DEFAULT_CONTEXT.into()),
            })),
            "secretsmanager" => {
                Ok(non_empty(ENV_SECRET_NAME).map(|name| Mode::SecretsManager { name }))
            }
            other => Err(ProviderError::Backend(format!(
                "unknown {ENV_MODE} {other:?} (expected kms or secretsmanager)"
            ))),
        }
    }

    fn from_env() -> Result<Mode, ProviderError> {
        Self::parse(|k| std::env::var(k).ok())?.ok_or(ProviderError::Unavailable)
    }
}

/// Region is resolvable cheaply from env only (no IMDS call). On EC2 without
/// these vars, set `AWS_REGION`; enrollment/runtime still honour the full chain.
fn region_in_env(get: impl Fn(&str) -> Option<String>) -> bool {
    ["AWS_REGION", "AWS_DEFAULT_REGION"]
        .iter()
        .any(|k| get(k).is_some_and(|v| !v.trim().is_empty()))
}

pub struct AwsProvider {
    _private: (),
}

impl AwsProvider {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for AwsProvider {
    fn default() -> Self {
        Self::new()
    }
}

fn block_on<F: Future>(f: F) -> Result<F::Output, ProviderError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    Ok(rt.block_on(f))
}

fn backend<E: std::error::Error>(what: &str, e: E) -> ProviderError {
    // Walk the source chain; the SDK's top-level Display is just "service error".
    let mut msg = format!("{what}: {e}");
    let mut src = e.source();
    while let Some(s) = src {
        msg.push_str(&format!(": {s}"));
        src = s.source();
    }
    ProviderError::Backend(msg)
}

async fn sdk_config() -> aws_config::SdkConfig {
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await
}

async fn kms_wrap(key_id: &str, ctx: &str, seed: &[u8]) -> Result<Vec<u8>, ProviderError> {
    use aws_sdk_kms::primitives::Blob;
    let client = aws_sdk_kms::Client::new(&sdk_config().await);
    let out = client
        .encrypt()
        .key_id(key_id)
        .plaintext(Blob::new(seed))
        .encryption_context("app", ctx)
        .send()
        .await
        .map_err(|e| backend("kms:Encrypt", e))?;
    out.ciphertext_blob()
        .map(|b| b.as_ref().to_vec())
        .ok_or_else(|| ProviderError::Backend("kms:Encrypt returned no ciphertext".into()))
}

async fn kms_unwrap(ctx: &str, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
    use aws_sdk_kms::primitives::Blob;
    let client = aws_sdk_kms::Client::new(&sdk_config().await);
    let out = client
        .decrypt()
        .ciphertext_blob(Blob::new(payload))
        .encryption_context("app", ctx)
        .send()
        .await
        .map_err(|e| backend("kms:Decrypt", e))?;
    out.plaintext()
        .map(|b| Zeroizing::new(b.as_ref().to_vec()))
        .ok_or_else(|| ProviderError::Backend("kms:Decrypt returned no plaintext".into()))
}

async fn sm_wrap(name: &str, seed: &[u8]) -> Result<Vec<u8>, ProviderError> {
    use aws_sdk_secretsmanager::primitives::Blob;
    let client = aws_sdk_secretsmanager::Client::new(&sdk_config().await);
    let created = client
        .create_secret()
        .name(name)
        .secret_binary(Blob::new(seed))
        .send()
        .await;
    match created {
        Ok(_) => {}
        Err(e)
            if e.as_service_error()
                .is_some_and(|s| s.is_resource_exists_exception()) =>
        {
            client
                .put_secret_value()
                .secret_id(name)
                .secret_binary(Blob::new(seed))
                .send()
                .await
                .map_err(|e| backend("secretsmanager:PutSecretValue", e))?;
        }
        Err(e) => return Err(backend("secretsmanager:CreateSecret", e)),
    }
    Ok(name.as_bytes().to_vec())
}

async fn sm_unwrap(payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
    let id = std::str::from_utf8(payload)
        .map_err(|_| ProviderError::Backend("payload is not a UTF-8 secret name".into()))?;
    let client = aws_sdk_secretsmanager::Client::new(&sdk_config().await);
    let out = client
        .get_secret_value()
        .secret_id(id)
        .send()
        .await
        .map_err(|e| backend("secretsmanager:GetSecretValue", e))?;
    if let Some(b) = out.secret_binary() {
        Ok(Zeroizing::new(b.as_ref().to_vec()))
    } else if let Some(s) = out.secret_string() {
        Ok(Zeroizing::new(s.as_bytes().to_vec()))
    } else {
        Err(ProviderError::Backend("secret has no value".into()))
    }
}

impl KeyProvider for AwsProvider {
    fn id(&self) -> &'static str {
        "aws"
    }

    /// Env-only check: required setting for the mode plus a region in env. No
    /// network calls.
    fn available(&self) -> bool {
        let get = |k: &str| std::env::var(k).ok();
        matches!(Mode::parse(get), Ok(Some(_))) && region_in_env(get)
    }

    fn wrap(&self, seed: &[u8]) -> Result<Vec<u8>, ProviderError> {
        match Mode::from_env()? {
            Mode::Kms { key_id, context } => block_on(kms_wrap(&key_id, &context, seed))?,
            Mode::SecretsManager { name } => block_on(sm_wrap(&name, seed))?,
        }
    }

    fn unwrap(&self, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        match Mode::from_env()? {
            Mode::Kms { context, .. } => block_on(kms_unwrap(&context, payload))?,
            Mode::SecretsManager { .. } => block_on(sm_unwrap(payload))?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn default_mode_is_kms() {
        let m = Mode::parse(env(&[(ENV_KMS_KEY_ID, "alias/x")])).unwrap();
        assert_eq!(
            m,
            Some(Mode::Kms {
                key_id: "alias/x".into(),
                context: DEFAULT_CONTEXT.into()
            })
        );
    }

    #[test]
    fn kms_custom_context() {
        let m = Mode::parse(env(&[(ENV_KMS_KEY_ID, "k"), (ENV_CONTEXT, "i-123")])).unwrap();
        assert_eq!(
            m,
            Some(Mode::Kms {
                key_id: "k".into(),
                context: "i-123".into()
            })
        );
    }

    #[test]
    fn secrets_manager_mode() {
        let m = Mode::parse(env(&[(ENV_MODE, "SecretsManager"), (ENV_SECRET_NAME, "s")])).unwrap();
        assert_eq!(m, Some(Mode::SecretsManager { name: "s".into() }));
    }

    #[test]
    fn missing_config_is_none() {
        assert_eq!(Mode::parse(env(&[])).unwrap(), None);
        assert_eq!(
            Mode::parse(env(&[(ENV_MODE, "secretsmanager"), (ENV_KMS_KEY_ID, "k")])).unwrap(),
            None
        );
        assert_eq!(Mode::parse(env(&[(ENV_KMS_KEY_ID, "  ")])).unwrap(), None);
    }

    #[test]
    fn unknown_mode_errors() {
        assert!(Mode::parse(env(&[(ENV_MODE, "bogus")])).is_err());
    }

    #[test]
    fn region_detection() {
        assert!(!region_in_env(env(&[])));
        assert!(region_in_env(env(&[("AWS_REGION", "us-east-1")])));
        assert!(region_in_env(env(&[("AWS_DEFAULT_REGION", "eu-west-1")])));
    }

    #[test]
    fn unconfigured_is_unavailable_and_errors() {
        // Test env has no SPO_AWS_* set.
        if std::env::var(ENV_KMS_KEY_ID).is_err() && std::env::var(ENV_MODE).is_err() {
            let p = AwsProvider::new();
            assert!(!p.available());
            assert!(matches!(p.wrap(b"x"), Err(ProviderError::Unavailable)));
        }
        assert_eq!(AwsProvider::new().id(), "aws");
    }
}
