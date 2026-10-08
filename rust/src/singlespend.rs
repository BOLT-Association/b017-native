//! src/lib/single/singleSpend.ts: the shared unlock assembler of the NFT-family templates (transfer commit/settle,
//! back-reaching settle, zero-funding, melt).

use std::rc::Rc;

use crate::boltlib::{build_change_output, build_outpoint, create_signature, input_source_txid, split_ctx, UnlockTemplate};
use crate::error::{err, Result};
use crate::script::{chunks_from_bin, ocs_prefix, Chunk, Script};
use crate::sighash::{format_preimage, refs_of, BoxFuture, PreimageParams, Signer, SIGNATURE_SCOPE};
use crate::singleancestor::{min_simple_layout, single_ancestor_pieces, SingleLayout};
use crate::tx::{Transaction, TxRef};

/// SINGLE_ANCESTOR_ARG_COUNT.
pub const SINGLE_ANCESTOR_ARG_COUNT: usize = 26;

pub(crate) fn is_proof_lock(s: Option<&Script>) -> bool {
    s.and_then(|s| s.chunks().first()).and_then(|c| c.data.as_ref()).is_some_and(|d| d.len() == 2 && d[0] == 0xb0 && d[1] == 0x17)
}

/// `emptySingleAncestorChunks(count)`.
pub fn empty_single_ancestor_chunks(count: usize) -> Vec<Chunk> {
    (0..count).flat_map(|_| chunks_from_bin(&[])).collect()
}

/// singleSpendUnlock's parameters. `source_satoshis` / `locking_script` None = from the attached source (TS `??`).
#[derive(Clone)]
pub struct SingleUnlockParams {
    pub signer: Rc<dyn Signer>,
    pub beneficiary_pub_key_hash: Vec<u8>,
    pub unlock_suffix: Script,
    pub force_no_change: bool,
    pub force_no_fund: bool,
    pub prev_txs: Vec<TxRef>,
    pub source_satoshis: Option<u64>,
    pub locking_script: Option<Script>,
    pub leading_value_pushes: usize,
    pub layout: Option<SingleLayout>,
    pub auth_or_misc_data: Vec<u8>,
    pub melt: bool,
}

/// `singleSpendUnlock`. Requires tx version >= 2.
pub struct SingleSpendUnlock(pub SingleUnlockParams);

impl UnlockTemplate for SingleSpendUnlock {
    fn estimate_length(&self) -> usize {
        2000
    }
    fn sign<'a>(&'a self, tx: &'a Transaction, input_index: usize) -> BoxFuture<'a, Result<Script>> {
        Box::pin(async move {
            let p = &self.0;
            let layout = p.layout.clone().unwrap_or_else(min_simple_layout);
            let input = &tx.inputs[input_index];
            let source_txid = input_source_txid(tx, input_index)?;
            if source_txid.is_empty() {
                return err("input sourceTXID or sourceTransaction required for signing");
            }
            let src_out = input.source_transaction.as_ref().map(|s| s.borrow().outputs.get(input.source_output_index as usize).cloned());
            if let Some(None) = src_out {
                return err("Cannot read properties of undefined (reading 'satoshis')");
            }
            let src_out = src_out.flatten();
            let sats = match p.source_satoshis.or_else(|| src_out.as_ref().and_then(|o| o.satoshis)) {
                Some(s) => s,
                None => return err("sourceSatoshis or input sourceTransaction required"),
            };
            let lock = match p.locking_script.clone().or_else(|| src_out.as_ref().and_then(|o| o.locking_script.clone())) {
                Some(l) => l,
                None => return err("lockingScript or input sourceTransaction required"),
            };

            let tx_idx = p.prev_txs.len() as i64;
            let ancestor_idx = tx_idx - 3;
            let has_ancestor = ancestor_idx >= 1 && tx_idx >= 4 && tx_idx % 2 == 0;
            let ancestor_chunks: Vec<Chunk> = if has_ancestor {
                let anc = p.prev_txs[ancestor_idx as usize].borrow();
                single_ancestor_pieces(&anc, p.leading_value_pushes, &layout)?.iter().flat_map(|b| chunks_from_bin(b)).collect()
            } else {
                empty_single_ancestor_chunks(layout.piece_names.len())
            };

            let mut ocs = ocs_prefix();
            ocs.extend_from_slice(lock.chunks());
            let ocs = Script::new(ocs);
            let pre = format_preimage(&PreimageParams {
                source_txid: &source_txid,
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
            let c = split_ctx(&pre, 2)?;
            let mut ctx_for_sig = c.header.clone();
            ctx_for_sig.extend(&c.lock_len);
            ctx_for_sig.extend(&c.lock_script_code);
            ctx_for_sig.extend(&c.footer);
            let (sig, pub_key) = create_signature(p.signer.as_ref(), &ctx_for_sig, SIGNATURE_SCOPE).await?;
            let suffix = p.unlock_suffix.chunks().to_vec();

            if p.melt {
                let mut out = vec![];
                if layout.has_auth {
                    out.extend(chunks_from_bin(&[]));
                }
                out.extend(empty_single_ancestor_chunks(layout.piece_names.len()));
                for _ in 0..3 {
                    out.extend(chunks_from_bin(&[]));
                }
                out.extend(chunks_from_bin(&sig));
                out.extend(chunks_from_bin(&pub_key));
                for _ in 0..6 {
                    out.extend(chunks_from_bin(&[]));
                }
                out.extend(suffix);
                return Ok(Script::new(out));
            }

            let next_in = tx.inputs.get(input_index + 1);
            let next_lock = next_in.and_then(|i| i.source_output()).and_then(|o| o.locking_script);
            let has_proof = match next_in {
                None => false,
                Some(_) => match &next_lock {
                    Some(l) => is_proof_lock(Some(l)),
                    None => has_ancestor,
                },
            };
            let fund_input = if p.force_no_fund { None } else { tx.inputs.get(input_index + 1 + usize::from(has_proof)) };
            let change_idx = if is_proof_lock(tx.outputs.get(1).and_then(|o| o.locking_script.as_ref())) { 2 } else { 1 };
            let has_change = !p.force_no_change && tx.outputs.len() > change_idx;
            if has_change && fund_input.is_none() {
                return err("an unfunded spend has no change to return (change needs a funding input)");
            }
            let fund_outpoint = match fund_input {
                None => vec![],
                Some(f) => match &f.source_transaction {
                    None => return err("Cannot read properties of undefined (reading 'hash')"),
                    Some(s) => build_outpoint(&s.borrow(), f.source_output_index)?,
                },
            };
            let change_output = if has_change { build_change_output(tx, change_idx) } else { vec![] };

            let mut out = vec![];
            if layout.has_auth {
                out.extend(chunks_from_bin(&p.auth_or_misc_data));
            }
            out.extend(ancestor_chunks);
            for b in [
                &fund_outpoint, &change_output, &p.beneficiary_pub_key_hash, &sig, &pub_key, &c.header, &c.code_len,
                &c.unlock_script_code, &c.lock_script_code, &c.footer, &c.lock_len,
            ] {
                out.extend(chunks_from_bin(b));
            }
            out.extend(suffix);
            Ok(Script::new(out))
        })
    }
}
