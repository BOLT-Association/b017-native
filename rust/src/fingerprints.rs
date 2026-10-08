//! src/lib/scanner/fingerprints.ts: per-type recognition of BOLT token locks and the golden p2Proof fingerprint.

use std::sync::OnceLock;

use crate::pay2proof::pay2proof_lock;
use crate::script::{chunk_data, hex_decode, hex_encode, Chunk, Script};
use crate::sighash::sha256;
use crate::suffixes_gen::*;

/// The reference's TokenType.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenType {
    MinSimpleBOLT,
    AuthBOLT,
    SimpleMultiBOLT,
}

impl TokenType {
    /// The type's name, as the scanner reports it.
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenType::MinSimpleBOLT => "MinSimpleBOLT",
            TokenType::AuthBOLT => "AuthBOLT",
            TokenType::SimpleMultiBOLT => "SimpleMultiBOLT",
        }
    }
    /// The type with that name.
    pub fn parse(s: &str) -> Option<TokenType> {
        match s {
            "MinSimpleBOLT" => Some(TokenType::MinSimpleBOLT),
            "AuthBOLT" => Some(TokenType::AuthBOLT),
            "SimpleMultiBOLT" => Some(TokenType::SimpleMultiBOLT),
            _ => None,
        }
    }
}

/// A REGISTRY entry.
#[derive(Debug, Clone)]
pub struct TypeSpec {
    pub token_type: TokenType,
    pub data_push_count: usize,
    pub push_lengths: Vec<usize>,
    pub suffix_hash_hex: String,
}

/// Object.values(REGISTRY) order, which recognizeType walks.
pub const REGISTRY_ORDER: [TokenType; 3] = [
    TokenType::MinSimpleBOLT,
    TokenType::AuthBOLT,
    TokenType::SimpleMultiBOLT,
];

/// `sha256Hex`.
pub fn sha256_hex(b: &[u8]) -> String {
    hex_encode(&sha256(b))
}

/// The REGISTRY entry of a type.
pub fn registry(t: TokenType) -> &'static TypeSpec {
    static R: OnceLock<Vec<TypeSpec>> = OnceLock::new();
    let all = R.get_or_init(|| {
        REGISTRY_ORDER
            .iter()
            .map(|&t| {
                let (layout, suffix): (Vec<usize>, &str) = match t {
                    TokenType::MinSimpleBOLT => {
                        (vec![20, 20, 1, 36, 36, 33], MIN_SIMPLE_LOCK_SUFFIX_HEX)
                    }
                    TokenType::AuthBOLT => (vec![20, 20, 1, 36, 36, 33], AUTH_BOLT_LOCK_SUFFIX_HEX),
                    TokenType::SimpleMultiBOLT => (
                        vec![16, 16, 20, 20, 20, 36, 1, 1, 36, 36, 33],
                        SIMPLE_MULTI_LOCK_SUFFIX_HEX,
                    ),
                };
                TypeSpec {
                    token_type: t,
                    data_push_count: layout.len(),
                    push_lengths: layout,
                    suffix_hash_hex: sha256_hex(&hex_decode(suffix).unwrap()),
                }
            })
            .collect()
    });
    &all[REGISTRY_ORDER.iter().position(|&x| x == t).unwrap()]
}

/// `recognizeType`: the type whose push layout AND suffix hash the lock matches (`expected` None = any).
pub fn recognize_type(lock: Option<&Script>, expected: Option<TokenType>) -> Option<TokenType> {
    let chunks = lock?.chunks();
    for &t in &REGISTRY_ORDER {
        let spec = registry(t);
        if expected.is_some_and(|e| e != t) {
            continue;
        }
        let n = spec.data_push_count;
        if chunks.len() <= n {
            continue;
        }
        if !(0..n).all(|i| chunks[i].data_len() == spec.push_lengths[i]) {
            continue;
        }
        if sha256_hex(&Script::new(chunks[n..].to_vec()).to_binary()) != spec.suffix_hash_hex {
            continue;
        }
        return Some(t);
    }
    None
}

/// `issuerPubKeyOf`: the last dynamic push of a recognised token.
pub fn issuer_pub_key_of(lock: &Script, t: TokenType) -> Vec<u8> {
    chunk_data(lock, registry(t).data_push_count - 1)
}

const P2P_PKH_IDX: usize = 4;

fn p2p_skeleton(lock: &Script) -> Vec<u8> {
    let chunks: Vec<Chunk> = lock
        .chunks()
        .iter()
        .enumerate()
        .map(|(i, c)| {
            if i == P2P_PKH_IDX {
                Chunk {
                    op: c.op,
                    data: Some(vec![0; c.data_len()]),
                }
            } else {
                c.clone()
            }
        })
        .collect();
    Script::new(chunks).to_binary()
}

fn p2p_reference() -> &'static (usize, String) {
    static P: OnceLock<(usize, String)> = OnceLock::new();
    P.get_or_init(|| {
        let r = pay2proof_lock(&[0u8; 20]);
        (r.chunks().len(), sha256_hex(&p2p_skeleton(&r)))
    })
}

/// `recognizeP2P`: a genuine p2Proof lock (static skeleton hash + a 20-byte pkh at chunk 4).
pub fn recognize_p2p(lock: Option<&Script>) -> bool {
    let lock = match lock {
        None => return false,
        Some(l) => l,
    };
    let (len, hash) = p2p_reference();
    if lock.chunks().len() != *len {
        return false;
    }
    match &lock.chunks()[P2P_PKH_IDX].data {
        Some(d) if d.len() == 20 => {}
        _ => return false,
    }
    sha256_hex(&p2p_skeleton(lock)) == *hash
}
