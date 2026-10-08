//! src/tokens/templates/MinSimple.sx.template.ts and AuthBolt.sx.template.ts. A `None` argument is an omitted TS
//! argument (its default applies).

use std::rc::Rc;

use crate::error::{err, Result};
use crate::script::Script;
use crate::sighash::Signer;
use crate::singleancestor::auth_bolt_layout;
use crate::singlespend::{SingleSpendUnlock, SingleUnlockParams};
use crate::suffixes_gen::*;
use crate::tx::TxRef;

/// AUTH_DATA_MAX_BYTES: authOrMiscData is a direct push.
pub const AUTH_DATA_MAX_BYTES: usize = 75;

fn suffix(h: &str) -> Script {
    Script::from_hex(h).unwrap()
}

/// The NFT lock's optional args (None = TS default).
#[derive(Default, Clone)]
pub struct NftLockArgs {
    pub commitment: Option<Vec<u8>>,
    pub txo_type: Option<Vec<u8>>,
    pub parent: Option<Vec<u8>>,
    pub grandparent: Option<Vec<u8>>,
}

fn nft_lock(sfx: &str, pub_key_hash: &[u8], issuer_pub_key: &[u8], a: &NftLockArgs) -> Script {
    let mut s = Script::default();
    s.write_bin(pub_key_hash)
        .write_bin(&a.commitment.clone().unwrap_or(vec![0; 20]))
        .write_bin(&a.txo_type.clone().unwrap_or(vec![0]))
        .write_bin(&a.parent.clone().unwrap_or(vec![0; 36]))
        .write_bin(&a.grandparent.clone().unwrap_or(vec![0; 36]))
        .write_bin(issuer_pub_key);
    let mut chunks = s.chunks().to_vec();
    chunks.extend_from_slice(suffix(sfx).chunks());
    Script::new(chunks)
}

fn params(signer: Rc<dyn Signer>, beneficiary: &[u8], unlock_hex: &str) -> SingleUnlockParams {
    SingleUnlockParams {
        signer,
        beneficiary_pub_key_hash: beneficiary.to_vec(),
        unlock_suffix: suffix(unlock_hex),
        force_no_change: false,
        force_no_fund: false,
        prev_txs: vec![],
        source_satoshis: None,
        locking_script: None,
        leading_value_pushes: 0,
        layout: None,
        auth_or_misc_data: vec![],
        melt: false,
    }
}

/// The MinSimpleBolt identity NFT template.
pub struct MinSimpleTemplate;

impl MinSimpleTemplate {
    pub fn lock(pub_key_hash: &[u8], issuer_pub_key: &[u8], a: &NftLockArgs) -> Script {
        nft_lock(MIN_SIMPLE_LOCK_SUFFIX_HEX, pub_key_hash, issuer_pub_key, a)
    }
    pub fn static_suffix() -> Script {
        suffix(MIN_SIMPLE_LOCK_SUFFIX_HEX)
    }
    /// `unlock(privateKey, beneficiaryPubKeyHash, prevTxs = [], forceNoChange, forceNoFund)`.
    pub fn unlock(signer: Rc<dyn Signer>, beneficiary: &[u8], prev_txs: Vec<TxRef>, force_no_change: bool, force_no_fund: bool) -> SingleSpendUnlock {
        let mut p = params(signer, beneficiary, MIN_SIMPLE_UNLOCK_SUFFIX_HEX);
        p.prev_txs = prev_txs;
        p.force_no_change = force_no_change;
        p.force_no_fund = force_no_fund;
        SingleSpendUnlock(p)
    }
    /// `melt(privateKey)`.
    pub fn melt(signer: Rc<dyn Signer>) -> SingleSpendUnlock {
        let mut p = params(signer, &[], MIN_SIMPLE_UNLOCK_SUFFIX_HEX);
        p.melt = true;
        SingleSpendUnlock(p)
    }
}

/// The AuthBolt identity NFT template (MinSimple + authOrMiscData).
pub struct AuthBoltTemplate;

impl AuthBoltTemplate {
    pub fn lock(pub_key_hash: &[u8], issuer_pub_key: &[u8], a: &NftLockArgs) -> Script {
        nft_lock(AUTH_BOLT_LOCK_SUFFIX_HEX, pub_key_hash, issuer_pub_key, a)
    }
    pub fn static_suffix() -> Script {
        suffix(AUTH_BOLT_LOCK_SUFFIX_HEX)
    }
    /// `unlock(privateKey, beneficiaryPubKeyHash, prevTxs = [], authOrMiscData = [], forceNoChange, forceNoFund)`;
    /// fails when authOrMiscData is longer than 75 bytes.
    pub fn unlock(
        signer: Rc<dyn Signer>,
        beneficiary: &[u8],
        prev_txs: Vec<TxRef>,
        auth_or_misc_data: &[u8],
        force_no_change: bool,
        force_no_fund: bool,
    ) -> Result<SingleSpendUnlock> {
        if auth_or_misc_data.len() > AUTH_DATA_MAX_BYTES {
            return err(format!(
                "authOrMiscData is {} bytes; the maximum is {AUTH_DATA_MAX_BYTES} (a direct push)",
                auth_or_misc_data.len()
            ));
        }
        let mut p = params(signer, beneficiary, AUTH_BOLT_UNLOCK_SUFFIX_HEX);
        p.prev_txs = prev_txs;
        p.force_no_change = force_no_change;
        p.force_no_fund = force_no_fund;
        p.layout = Some(auth_bolt_layout());
        p.auth_or_misc_data = auth_or_misc_data.to_vec();
        Ok(SingleSpendUnlock(p))
    }
    /// `melt(privateKey)`.
    pub fn melt(signer: Rc<dyn Signer>) -> SingleSpendUnlock {
        let mut p = params(signer, &[], AUTH_BOLT_UNLOCK_SUFFIX_HEX);
        p.melt = true;
        p.layout = Some(auth_bolt_layout());
        SingleSpendUnlock(p)
    }
}
