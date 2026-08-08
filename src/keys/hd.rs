//! SLIP-0010 hierarchical key derivation over the BIP39 seed (ADR 0008).
//!
//! Vaulet is **seed-first**: the 24-word mnemonic is a real BIP39 seed (not a
//! raw-scalar encoding — this supersedes ADR 0001 Approach A). The identity/DID
//! key is ONE hardened derivation; future facilities reserve their own paths so
//! one maintained seed powers many keys. P-256 (nist256p1) uses SLIP-0010 with
//! HARDENED-only derivation, as the spec recommends for non-secp256k1 curves.

use hmac::{Hmac, Mac};
use p256::elliptic_curve::ff::{Field, PrimeField};
use p256::{FieldBytes, Scalar};
use sha2::Sha512;
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

/// Vaulet-native SLIP-0010 purpose (the P-256 branch). Documented in ADR 0008.
pub const VAULET_PURPOSE: u32 = 1077;

/// Identity / DID key path: `m/1077'/0'/0'` (account 0 = the primary DID).
pub const IDENTITY_PATH: [u32; 3] = [VAULET_PURPOSE, 0, 0];

// Reserved (documented in ADR 0008, not yet used):
//   m/1077'/1'/{i}'  device attestation (anti-clone)
//   m/1077'/2'/{n}'  passkey (seed-derived, software passkey provider)
//   m/1077'/9'/0'    vault master key (HKDF, symmetric)
//   crypto is a SEPARATE curve (secp256k1/BIP44), interoperable:
//     EVM  m/44'/60'/{acct}'/0/{i}      BTC  m/84'/0'/{acct}'/0/{i}

struct Node {
    key: [u8; 32],
    chain: [u8; 32],
}

impl Drop for Node {
    fn drop(&mut self) {
        // Wipe the derived private scalar (and chain code) from memory when a
        // node is replaced mid-derivation or the final node is dropped.
        self.key.zeroize();
        self.chain.zeroize();
    }
}

fn hmac512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    out
}

fn scalar_from(b: &[u8; 32]) -> Option<Scalar> {
    Option::<Scalar>::from(Scalar::from_repr(*FieldBytes::from_slice(b)))
}

/// A valid SLIP-0010 P-256 key: parses as a scalar in `[1, n-1]`.
fn is_valid(b: &[u8; 32]) -> bool {
    scalar_from(b)
        .map(|s| !bool::from(s.is_zero()))
        .unwrap_or(false)
}

/// SLIP-0010 master node for the nist256p1 curve.
fn master(seed: &[u8]) -> Node {
    let mut i = hmac512(b"Nist256p1 seed", seed);
    loop {
        let mut il: [u8; 32] = i[..32].try_into().unwrap();
        if is_valid(&il) {
            let mut key = [0u8; 32];
            let mut chain = [0u8; 32];
            key.copy_from_slice(&i[..32]);
            chain.copy_from_slice(&i[32..]);
            il.zeroize();
            i.zeroize(); // wipe the HMAC output (holds the private I_L)
            return Node { key, chain };
        }
        // Invalid master (I_L is 0 or >= n): re-hash. Vanishingly rare for P-256.
        il.zeroize();
        i = hmac512(b"Nist256p1 seed", &i);
    }
}

/// SLIP-0010 HARDENED child derivation (the index is hardened automatically).
fn derive_hardened(node: &Node, index: u32) -> Node {
    let hindex = index | 0x8000_0000;
    // data = 0x00 || ser256(k_par) || ser32(i)
    let mut data = Vec::with_capacity(37);
    data.push(0x00);
    data.extend_from_slice(&node.key);
    data.extend_from_slice(&hindex.to_be_bytes());
    let kpar = scalar_from(&node.key).expect("parent key is a valid scalar");
    loop {
        let mut i = hmac512(&node.chain, &data);
        let mut il: [u8; 32] = i[..32].try_into().unwrap();
        let ir: [u8; 32] = i[32..].try_into().unwrap();
        if let Some(il_s) = scalar_from(&il) {
            let ki = il_s + kpar; // (parse256(I_L) + k_par) mod n
            if !bool::from(ki.is_zero()) {
                let mut key = [0u8; 32];
                key.copy_from_slice(ki.to_repr().as_slice());
                il.zeroize();
                i.zeroize();
                data.zeroize(); // heap buffer held 0x00 || parent_scalar || idx
                return Node { key, chain: ir };
            }
        }
        // Invalid child (I_L >= n or k_i == 0): retry with 0x01 || I_R || ser32(i).
        il.zeroize();
        i.zeroize();
        data.clear();
        data.push(0x01);
        data.extend_from_slice(&ir);
        data.extend_from_slice(&hindex.to_be_bytes());
    }
}

/// Derive the 32-byte P-256 identity private scalar from `seed` at
/// [`IDENTITY_PATH`]. Deterministic: same seed → same identity/DID.
pub fn derive_identity_scalar(seed: &[u8]) -> [u8; 32] {
    let mut node = master(seed);
    for &idx in IDENTITY_PATH.iter() {
        node = derive_hardened(&node, idx);
    }
    node.key
}

#[cfg(test)]
mod tests {
    use super::*;

    // SLIP-0010 test vector 1 (nist256p1), seed = 000102...0f.
    #[test]
    fn slip10_master_vector() {
        let seed = hex(b"000102030405060708090a0b0c0d0e0f");
        let m = master(&seed);
        assert_eq!(
            hex_str(&m.key),
            "612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2"
        );
        assert_eq!(
            hex_str(&m.chain),
            "beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea"
        );
    }

    // Vector 1, m/0' (nist256p1).
    #[test]
    fn slip10_child_vector() {
        let seed = hex(b"000102030405060708090a0b0c0d0e0f");
        let child = derive_hardened(&master(&seed), 0);
        assert_eq!(
            hex_str(&child.key),
            "6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c"
        );
    }

    #[test]
    fn identity_is_deterministic_and_valid() {
        let seed = [7u8; 64];
        let a = derive_identity_scalar(&seed);
        let b = derive_identity_scalar(&seed);
        assert_eq!(a, b);
        assert!(is_valid(&a));
    }

    fn hex(h: &[u8]) -> Vec<u8> {
        let s = std::str::from_utf8(h).unwrap();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn hex_str(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
