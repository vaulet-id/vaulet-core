//! Shamir recovery (ADR 0002): split the identity key's 32-byte scalar into
//! `m` shares of which any `n` reconstruct it (threshold n-of-m).
//!
//! Approach A (software-key era): the raw scalar IS the split secret — no
//! Recovery Secret indirection. Each raw share is wrapped in a small text
//! envelope carrying the version, threshold, and a 4-byte checksum of the
//! secret so recovery can (a) reject under-provision and (b) verify it
//! reconstructed the right key before writing anything.

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use sharks::{Share, Sharks};

use crate::{CoreError, Result};

const ENVELOPE_TAG: &str = "VSHAMIR1";

/// Split `secret` into `count` shares, any `threshold` of which reconstruct it.
/// Returns the wrapped share strings the UI hands to custodians.
pub fn split(secret: &[u8], threshold: u8, count: u8) -> Result<Vec<String>> {
    if threshold < 2 {
        return Err(CoreError::Key("threshold must be at least 2".into()));
    }
    if count < threshold {
        return Err(CoreError::Key("shares must be >= threshold".into()));
    }
    let checksum = secret_checksum(secret);
    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(secret);
    Ok(dealer
        .take(count as usize)
        .map(|s| wrap_share(threshold, &checksum, &Vec::from(&s)))
        .collect())
}

/// Reconstruct the secret from wrapped shares. Fails if the shares disagree on
/// threshold/checksum, there are fewer than the threshold, or the checksum of
/// the reconstructed secret does not match (wrong or insufficient shares).
pub fn reconstruct(shares: &[String]) -> Result<Vec<u8>> {
    if shares.is_empty() {
        return Err(CoreError::Key("no shares provided".into()));
    }
    let mut threshold = None;
    let mut checksum: Option<Vec<u8>> = None;
    let mut raw: Vec<Share> = Vec::with_capacity(shares.len());
    for s in shares {
        let (t, ck, share_bytes) = unwrap_share(s)?;
        match threshold {
            None => threshold = Some(t),
            Some(prev) if prev != t => {
                return Err(CoreError::Key("shares are from different splits".into()))
            }
            _ => {}
        }
        match &checksum {
            None => checksum = Some(ck),
            Some(prev) if *prev != ck => {
                return Err(CoreError::Key("shares are from different splits".into()))
            }
            _ => {}
        }
        raw.push(
            Share::try_from(share_bytes.as_slice())
                .map_err(|e| CoreError::Key(format!("bad share: {e}")))?,
        );
    }
    let threshold = threshold.unwrap();
    if (raw.len() as u8) < threshold {
        return Err(CoreError::Key("not enough shares to recover".into()));
    }
    let secret = Sharks(threshold)
        .recover(raw.as_slice())
        .map_err(|e| CoreError::Key(format!("recover: {e}")))?;
    if secret_checksum(&secret) != checksum.unwrap().as_slice() {
        return Err(CoreError::Key("shares did not reconstruct a valid key".into()));
    }
    Ok(secret)
}

fn secret_checksum(secret: &[u8]) -> [u8; 4] {
    let digest = Sha256::digest(secret);
    [digest[0], digest[1], digest[2], digest[3]]
}

// Envelope: "VSHAMIR1.<t>.<b64(share)>.<b64(checksum)>"
fn wrap_share(threshold: u8, checksum: &[u8], share: &[u8]) -> String {
    format!(
        "{ENVELOPE_TAG}.{threshold}.{}.{}",
        STANDARD_NO_PAD.encode(share),
        STANDARD_NO_PAD.encode(checksum),
    )
}

fn unwrap_share(s: &str) -> Result<(u8, Vec<u8>, Vec<u8>)> {
    let parts: Vec<&str> = s.trim().split('.').collect();
    if parts.len() != 4 || parts[0] != ENVELOPE_TAG {
        return Err(CoreError::Key("not a valid recovery share".into()));
    }
    let threshold: u8 = parts[1]
        .parse()
        .map_err(|_| CoreError::Key("not a valid recovery share".into()))?;
    let share = STANDARD_NO_PAD
        .decode(parts[2])
        .map_err(|_| CoreError::Key("not a valid recovery share".into()))?;
    let checksum = STANDARD_NO_PAD
        .decode(parts[3])
        .map_err(|_| CoreError::Key("not a valid recovery share".into()))?;
    Ok((threshold, checksum, share))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_threshold_shares_reconstruct() {
        let secret = [42u8; 32];
        let shares = split(&secret, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);
        // Any 2 of the 3 recover.
        assert_eq!(reconstruct(&shares[0..2]).unwrap(), secret);
        assert_eq!(reconstruct(&[shares[0].clone(), shares[2].clone()]).unwrap(), secret);
        assert_eq!(reconstruct(&shares[1..3]).unwrap(), secret);
        // All 3 also recover.
        assert_eq!(reconstruct(&shares).unwrap(), secret);
    }

    #[test]
    fn one_share_is_not_enough() {
        let shares = split(&[7u8; 32], 2, 3).unwrap();
        assert!(reconstruct(&shares[0..1]).is_err());
    }

    #[test]
    fn threshold_below_two_rejected() {
        assert!(split(&[1u8; 32], 1, 3).is_err());
        assert!(split(&[1u8; 32], 3, 2).is_err()); // count < threshold
    }

    #[test]
    fn mixed_or_garbage_shares_fail() {
        let a = split(&[1u8; 32], 2, 3).unwrap();
        let b = split(&[2u8; 32], 2, 3).unwrap();
        // Shares from different splits must not silently reconstruct.
        assert!(reconstruct(&[a[0].clone(), b[0].clone()]).is_err());
        assert!(reconstruct(&["garbage".to_string(), a[0].clone()]).is_err());
    }
}
