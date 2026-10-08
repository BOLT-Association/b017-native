//! src/tokens/templates/SimpleMulti.sx.template.ts: the SimpleMultiBolt fungible contract (11 lock args; 198
//! unlock args). A `None` argument is an omitted TS argument (its default applies).

use std::rc::Rc;

use crate::boltlib::{build_change_output, build_outpoint, create_signature, input_source_txid, le32, split_ctx, UnlockTemplate};
use crate::error::{err, Result};
use crate::multiboltlib::{create_empty_fungible_ancestor_chunks, smb_ancestor_piece, SMB_PIECE_NAMES};
use crate::script::{chunks_from_bin, ocs_prefix, Script};
use crate::sighash::{format_preimage, hash160, refs_of, BoxFuture, PreimageParams, Signer, SIGNATURE_SCOPE};
use crate::suffixes_gen::{SIMPLE_MULTI_LOCK_SUFFIX_HEX, SIMPLE_MULTI_UNLOCK_SUFFIX_HEX};
use crate::tx::{Transaction, TxRef};

fn lock_suffix() -> Script {
    Script::from_hex(SIMPLE_MULTI_LOCK_SUFFIX_HEX).unwrap()
}
fn unlock_suffix() -> Script {
    Script::from_hex(SIMPLE_MULTI_UNLOCK_SUFFIX_HEX).unwrap()
}

/// lock()'s arguments after toPubKey and prevTxs.
#[derive(Default, Clone)]
pub struct SmbLockArgs {
    pub balance: Option<Vec<u8>>,
    pub balance_commit: Option<Vec<u8>>,
    pub pub_key_hash_commit: Option<Vec<u8>>,
    pub pub_key_hash_commit2: Option<Vec<u8>>,
    pub other_grandparent_outpoint: Option<Vec<u8>>,
    pub txo_type: Option<Vec<u8>>,
    pub output_index_n: Option<Vec<u8>>,
    pub prev_vout_idx: usize,
}

/// unlock()'s arguments after the signer, toPubKey and prevTxs.
#[derive(Default, Clone)]
pub struct SmbUnlockArgs {
    pub force_no_change: bool,
    pub force_no_fund: bool,
    pub next_balance_commit: Option<Vec<u8>>,
    pub next_txo_type: Option<Vec<u8>>,
    pub input_index_n: Option<Vec<u8>>,
    pub pub_key_hash2: Option<Vec<u8>>,
    pub grandparent_bolt_vout_idx: Option<Vec<u8>>,
    pub interop_bolt_vout_idx: Option<Vec<u8>>,
    pub interop_pub_key_hash: Option<Vec<u8>>,
    pub interop_outpoint: Option<Vec<u8>>,
    pub interop_parent_outpoint: Option<Vec<u8>>,
    pub ancestor_tx_b_ref: Option<TxRef>,
}

/// The SimpleMultiBolt template.
pub struct SimpleMultiTemplate;

impl SimpleMultiTemplate {
    /// `lock(toPubKey, prevTxs, balance, balanceCommit, pubKeyHashCommit, pubKeyHashCommit2,
    /// otherGrandparentOutpoint, txoType, outputIndexN, prevVoutIdx)`.
    pub fn lock(to_pub_key: &[u8], prev_txs: &[TxRef], a: &SmbLockArgs) -> Result<Script> {
        let prev = prev_txs.last();
        let prev_chunks = match prev {
            None => None,
            Some(p) => match p.borrow().outputs.get(a.prev_vout_idx).and_then(|o| o.locking_script.clone()) {
                None => return err("Cannot read properties of undefined (reading 'lockingScript')"),
                Some(l) => Some(l.chunks().to_vec()),
            },
        };
        let mut parent = match prev {
            Some(p) => p.borrow().hash()?,
            None => vec![0; 32],
        };
        parent.extend(le32(a.prev_vout_idx as u32));
        let grandparent = match &prev_chunks {
            Some(c) => match c.get(8) {
                None => return err("Cannot read properties of undefined (reading 'data')"),
                Some(ch) => ch.data.clone().unwrap_or(vec![0; 36]),
            },
            None => vec![0; 36],
        };
        let issuer = match &prev_chunks {
            None => to_pub_key.to_vec(),
            Some(c) => match c.get(10).and_then(|ch| ch.data.clone()) {
                None => return err("Cannot read properties of undefined (reading 'length')"),
                Some(d) => d,
            },
        };
        let mut s = Script::default();
        for b in [
            a.balance.clone().unwrap_or(vec![0; 16]),
            a.balance_commit.clone().unwrap_or(vec![0; 16]),
            hash160(to_pub_key),
            a.pub_key_hash_commit.clone().unwrap_or(vec![0; 20]),
            a.pub_key_hash_commit2.clone().unwrap_or(vec![0; 20]),
            a.other_grandparent_outpoint.clone().unwrap_or(vec![0; 36]),
            a.txo_type.clone().unwrap_or(vec![0x20]),
            a.output_index_n.clone().unwrap_or(vec![0x00]),
            parent,
            grandparent,
            issuer,
        ] {
            s.write_bin(&b);
        }
        let mut chunks = s.chunks().to_vec();
        chunks.extend_from_slice(lock_suffix().chunks());
        Ok(Script::new(chunks))
    }

    pub fn static_suffix() -> Script {
        lock_suffix()
    }

    /// `unlock(privateKey, toPubKey, prevTxs, ...)`.
    pub fn unlock(signer: Rc<dyn Signer>, to_pub_key: &[u8], prev_txs: Vec<TxRef>, a: SmbUnlockArgs) -> SmbUnlock {
        SmbUnlock { signer, to_pub_key: to_pub_key.to_vec(), prev_txs, a }
    }

    /// `melt(privateKey, sourceSatoshis?, lockingScript?)`.
    pub fn melt(signer: Rc<dyn Signer>, source_satoshis: Option<u64>, locking_script: Option<Script>) -> SmbMelt {
        SmbMelt { signer, sats: source_satoshis, lock: locking_script }
    }
}

/// extractInputInfo (a 0 amount counts as missing, `!sourceSatoshis`).
fn extract_input_info(tx: &Transaction, i: usize, sats: Option<u64>, lock: Option<Script>) -> Result<(String, u64, Script)> {
    let input = &tx.inputs[i];
    let txid = input_source_txid(tx, i)?;
    if txid.is_empty() {
        return err("The input sourceTXID or sourceTransaction is required for transaction signing.");
    }
    let src = match &input.source_transaction {
        None => None,
        Some(s) => match s.borrow().outputs.get(input.source_output_index as usize).cloned() {
            None => return err("Cannot read properties of undefined (reading 'satoshis')"),
            Some(o) => Some(o),
        },
    };
    let sats = sats.or_else(|| src.as_ref().and_then(|o| o.satoshis));
    let sats = match sats {
        Some(s) if s != 0 => s,
        _ => return err("The sourceSatoshis or input sourceTransaction is required for transaction signing."),
    };
    let lock = match lock.or_else(|| src.and_then(|o| o.locking_script)) {
        None => return err("The lockingScript or input sourceTransaction is required for transaction signing."),
        Some(l) => l,
    };
    Ok((txid, sats, lock))
}

fn fund_and_change(tx: &Transaction, force_no_change: bool, force_no_fund: bool) -> Result<(Vec<u8>, Vec<u8>)> {
    let fund = if force_no_fund {
        vec![]
    } else {
        let input = match tx.inputs.last() {
            None => return err("Cannot read properties of undefined (reading 'sourceTransaction')"),
            Some(i) => i,
        };
        match &input.source_transaction {
            None => return err("Cannot read properties of undefined (reading 'hash')"),
            Some(s) => build_outpoint(&s.borrow(), input.source_output_index)?,
        }
    };
    let change = if force_no_change { vec![] } else { build_change_output(tx, tx.outputs.len().wrapping_sub(1)) };
    Ok((fund, change))
}

/// SimpleMultiTemplate.unlock's template.
pub struct SmbUnlock {
    signer: Rc<dyn Signer>,
    to_pub_key: Vec<u8>,
    prev_txs: Vec<TxRef>,
    a: SmbUnlockArgs,
}

impl UnlockTemplate for SmbUnlock {
    fn estimate_length(&self) -> usize {
        2000
    }
    fn sign<'a>(&'a self, tx: &'a Transaction, input_index: usize) -> BoxFuture<'a, Result<Script>> {
        Box::pin(async move {
            let a = &self.a;
            let (txid, sats, lock) = extract_input_info(tx, input_index, None, None)?;
            let input = &tx.inputs[input_index];
            let mut ocs = ocs_prefix();
            ocs.extend_from_slice(lock.chunks());
            let ocs = Script::new(ocs);
            let pre = format_preimage(&PreimageParams {
                source_txid: &txid,
                source_output_index: input.source_output_index,
                source_satoshis: sats,
                transaction_version: tx.version,
                other_inputs: refs_of(&tx.inputs, input_index),
                input_index,
                outputs: &tx.outputs,
                input_sequence: input.sequence,
                subscript: &ocs,
                lock_time: tx.lock_time,
                scope: SIGNATURE_SCOPE,
            })?;
            let c = split_ctx(&pre, 2);
            let mut for_sig = c.header.clone();
            for_sig.extend(&c.lock_len);
            for_sig.extend(&c.lock_script_code);
            for_sig.extend(&c.footer);
            let (sig, pub_key) = create_signature(self.signer.as_ref(), &for_sig, SIGNATURE_SCOPE).await?;
            let to_pkh = if self.to_pub_key.is_empty() { vec![] } else { hash160(&self.to_pub_key) };
            let tx_idx = self.prev_txs.len() as i64;
            let (fund, change) = fund_and_change(tx, a.force_no_change, a.force_no_fund)?;
            let anc_idx = tx_idx - 3;
            let has_ancestor = anc_idx >= 1 && tx_idx >= 4 && tx_idx % 2 == 0;
            let ancestor = if has_ancestor { Some(Transaction::from_hex(&self.prev_txs[anc_idx as usize].borrow().to_hex()?)?) } else { None };
            let mut out = vec![];
            for p in SMB_PIECE_NAMES {
                let b = match &ancestor {
                    Some(t) => smb_ancestor_piece(p, t)?,
                    None => vec![],
                };
                out.extend(chunks_from_bin(&b));
            }
            let ancestor_b = match &a.ancestor_tx_b_ref {
                Some(t) => Some(Transaction::from_hex(&t.borrow().to_hex()?)?),
                None => None,
            };
            for p in SMB_PIECE_NAMES {
                let b = match &ancestor_b {
                    Some(t) => smb_ancestor_piece(p, t)?,
                    None => vec![],
                };
                out.extend(chunks_from_bin(&b));
            }
            let d = |v: &Option<Vec<u8>>, def: Vec<u8>| v.clone().unwrap_or(def);
            for b in [
                d(&a.grandparent_bolt_vout_idx, vec![]),
                d(&a.interop_bolt_vout_idx, vec![]),
                d(&a.interop_pub_key_hash, vec![]),
                d(&a.interop_outpoint, vec![]),
                d(&a.interop_parent_outpoint, vec![]),
                fund,
                change,
                to_pkh,
                d(&a.pub_key_hash2, vec![]),
                d(&a.next_balance_commit, vec![0; 16]),
                d(&a.next_txo_type, vec![0x21]),
                d(&a.input_index_n, vec![0x00]),
                sig,
                pub_key,
                c.header,
                c.code_len,
                c.unlock_script_code,
                c.lock_script_code,
                c.footer,
                c.lock_len,
            ] {
                out.extend(chunks_from_bin(&b));
            }
            out.extend_from_slice(unlock_suffix().chunks());
            Ok(Script::new(out))
        })
    }
}

/// SimpleMultiTemplate.melt's template.
pub struct SmbMelt {
    signer: Rc<dyn Signer>,
    sats: Option<u64>,
    lock: Option<Script>,
}

impl UnlockTemplate for SmbMelt {
    fn estimate_length(&self) -> usize {
        400
    }
    fn sign<'a>(&'a self, tx: &'a Transaction, input_index: usize) -> BoxFuture<'a, Result<Script>> {
        Box::pin(async move {
            let (txid, sats, lock) = extract_input_info(tx, input_index, self.sats, self.lock.clone())?;
            let input = &tx.inputs[input_index];
            let pre = format_preimage(&PreimageParams {
                source_txid: &txid,
                source_output_index: input.source_output_index,
                source_satoshis: sats,
                transaction_version: tx.version,
                other_inputs: refs_of(&tx.inputs, input_index),
                input_index,
                outputs: &tx.outputs,
                input_sequence: input.sequence,
                subscript: &lock,
                lock_time: tx.lock_time,
                scope: SIGNATURE_SCOPE,
            })?;
            let (sig, pub_key) = create_signature(self.signer.as_ref(), &pre, SIGNATURE_SCOPE).await?;
            let (fund, change) = fund_and_change(tx, false, false)?;
            let mut out = create_empty_fungible_ancestor_chunks();
            for _ in 0..5 {
                out.extend(chunks_from_bin(&[]));
            }
            let pkh = hash160(&pub_key);
            for b in [fund, change, pkh, vec![], vec![], vec![], vec![], sig, pub_key, vec![], vec![], vec![], vec![], vec![], vec![]] {
                out.extend(chunks_from_bin(&b));
            }
            out.extend_from_slice(unlock_suffix().chunks());
            Ok(Script::new(out))
        })
    }
}
