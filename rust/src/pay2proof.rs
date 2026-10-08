//! src/tokens/templates/pay2Proof.ts: the "b017 marker" proof output.

use std::cell::RefCell;
use std::rc::Rc;

use crate::boltlib::{create_signature, input_source_txid, UnlockTemplate};
use crate::error::{err, Result};
use crate::script::{Chunk, Script, OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160};
use crate::sighash::{
    format_preimage, refs_of, BoxFuture, PreimageParams, Signer, SIGNATURE_SCOPE,
};
use crate::tx::Transaction;

/// Pay2ProofTemplate.lock: `b017 OP_EQUALVERIFY OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG`.
pub fn pay2proof_lock(pub_key_hash: &[u8]) -> Script {
    Script::new(vec![
        Chunk::push(2, vec![0xb0, 0x17]),
        Chunk::op(OP_EQUALVERIFY),
        Chunk::op(OP_DUP),
        Chunk::op(OP_HASH160),
        Chunk::push(pub_key_hash.len() as u8, pub_key_hash.to_vec()),
        Chunk::op(OP_EQUALVERIFY),
        Chunk::op(OP_CHECKSIG),
    ])
}

/// Pay2ProofTemplate.unlock(privKey, sourceSatoshis?, lockingScript?). As in TS, a 0 amount counts as missing,
/// and an amount / lock taken from the first signed input is kept for later sign() calls (`||=`).
pub struct Pay2ProofUnlock {
    pub signer: Rc<dyn Signer>,
    source_satoshis: RefCell<u64>,
    locking_script: RefCell<Option<Script>>,
}

impl Pay2ProofUnlock {
    pub fn new(
        signer: Rc<dyn Signer>,
        source_satoshis: u64,
        locking_script: Option<Script>,
    ) -> Self {
        Pay2ProofUnlock {
            signer,
            source_satoshis: RefCell::new(source_satoshis),
            locking_script: RefCell::new(locking_script),
        }
    }
}

impl UnlockTemplate for Pay2ProofUnlock {
    fn estimate_length(&self) -> usize {
        111
    }
    fn sign<'a>(
        &'a self,
        tx: &'a Transaction,
        input_index: usize,
    ) -> BoxFuture<'a, Result<Script>> {
        Box::pin(async move {
            let input = &tx.inputs[input_index];
            let source_txid = input_source_txid(tx, input_index)?;
            if source_txid.is_empty() {
                return err("The input sourceTXID or sourceTransaction is required for transaction signing.");
            }
            if *self.source_satoshis.borrow() == 0 {
                if let Some(o) = input.source_output() {
                    *self.source_satoshis.borrow_mut() = o.sats();
                }
            }
            let sats = *self.source_satoshis.borrow();
            if sats == 0 {
                return err("The sourceSatoshis or input sourceTransaction is required for transaction signing.");
            }
            if self.locking_script.borrow().is_none() {
                if let Some(o) = input.source_output() {
                    *self.locking_script.borrow_mut() = o.locking_script;
                }
            }
            let lock = match self.locking_script.borrow().clone() {
                None => return err("The lockingScript or input sourceTransaction is required for transaction signing."),
                Some(l) => l,
            };
            let pre = format_preimage(&PreimageParams {
                source_txid: &source_txid,
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
            let (sig, pub_key) =
                create_signature(self.signer.as_ref(), &pre, SIGNATURE_SCOPE).await?;
            Ok(Script::new(vec![
                Chunk::push(sig.len() as u8, sig),
                Chunk::push(pub_key.len() as u8, pub_key),
                Chunk::push(2, vec![0xb0, 0x17]),
            ]))
        })
    }
}
