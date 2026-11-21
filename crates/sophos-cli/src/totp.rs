//! RFC 6238 TOTP. A plain `totp_seed` uses SHA1, six digits and 30-second
//! steps; an envelope carries its own parameters.

use anyhow::{bail, Context};
use totp_core::TotpParams;
use zeroize::Zeroizing;

pub struct Totp {
    seed: Zeroizing<Vec<u8>>,
    params: TotpParams,
}

impl Totp {
    pub fn from_seed(seed: Zeroizing<Vec<u8>>, params: TotpParams) -> Self {
        Self { seed, params }
    }

    pub fn step(&self) -> u64 {
        u64::from(self.params.step.max(1))
    }

    pub fn new(base32: &str) -> anyhow::Result<Self> {
        let mut seed = Zeroizing::new(Vec::new());
        let mut bits = 0u32;
        let mut count = 0;
        let mut padding = false;
        let mut symbols = 0;
        let mut pads = 0;
        for ch in base32.bytes().filter(|b| !b.is_ascii_whitespace()) {
            if ch == b'=' {
                padding = true;
                pads += 1;
                continue;
            }
            if padding {
                bail!("invalid Base32 seed padding");
            }
            let value = match ch.to_ascii_uppercase() {
                b'A'..=b'Z' => ch.to_ascii_uppercase() - b'A',
                b'2'..=b'7' => ch - b'2' + 26,
                _ => bail!("invalid Base32 seed character"),
            };
            symbols += 1;
            bits = (bits << 5) | u32::from(value);
            count += 5;
            if count >= 8 {
                count -= 8;
                seed.push((bits >> count) as u8);
                bits &= (1 << count) - 1;
            }
        }
        if !matches!(symbols % 8, 0 | 2 | 4 | 5 | 7)
            || bits != 0
            || (pads > 0 && (symbols + pads) % 8 != 0)
            || pads > 6
        {
            bail!("invalid Base32 seed length or padding");
        }
        if seed.len() < 10 {
            bail!("TOTP seed must contain at least 80 bits");
        }
        Ok(Self {
            seed,
            params: TotpParams::default(),
        })
    }

    pub fn code(&self, counter: u64) -> Zeroizing<String> {
        Zeroizing::new(totp_core::hotp(
            &self.seed,
            counter,
            self.params.digits,
            self.params.algo,
        ))
    }
}

/// Returns a usable counter, avoiding code reuse and the last three seconds of a step.
pub fn usable_counter(unix_seconds: u64, step: u64, last: Option<u64>) -> Option<u64> {
    let step = step.max(1);
    let counter = unix_seconds / step;
    let margin = 3.min(step / 2);
    (unix_seconds % step < step - margin && last.is_none_or(|last| counter > last))
        .then_some(counter)
}

pub fn unix_seconds() -> anyhow::Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_sha1_vectors() {
        // Public RFC test seed, not a real account secret.
        let totp = Totp::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        for (time, expected) in [
            (59, "287082"),
            (1111111109, "081804"),
            (1111111111, "050471"),
            (1234567890, "005924"),
            (2000000000, "279037"),
            (20000000000, "353130"),
        ] {
            assert_eq!(totp.code(time / 30).as_str(), expected);
        }
    }

    #[test]
    fn invalid_seeds() {
        for seed in [
            "",
            "A",
            "1234567890",
            "AAAAAAAAAAAAAAAA1",
            "AAAAAAAAAAAAAAAAB",
            "AA=AA",
        ] {
            assert!(Totp::new(seed).is_err());
        }
        assert!(Totp::new("gezdgnbvgy3tqojqgezdgnbvgy3tqojq").is_ok());
    }

    #[test]
    fn avoids_reuse_expiring_codes_and_clock_rollback() {
        assert_eq!(usable_counter(60, 30, Some(1)), Some(2));
        assert_eq!(usable_counter(60, 30, Some(2)), None);
        assert_eq!(usable_counter(87, 30, Some(1)), None);
        assert_eq!(usable_counter(30, 30, Some(2)), None);
        assert_eq!(usable_counter(119, 60, None), None);
        assert_eq!(usable_counter(120, 60, Some(1)), Some(2));
    }
}
