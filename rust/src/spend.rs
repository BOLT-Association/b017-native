//! The reference's `new Spend({...}).validate()` on the bsv-sdk crate's interpreter (patched: the OP_CHECKSIG
//! subscript crosses the unlock/lock boundary as in ts-sdk). Like ts-sdk, the crate relaxes a spend by the
//! spending tx's version (> 1). A failure is an error whose text is the crate's (compared by prefix only).

use bsv::script::locking_script::LockingScript;
use bsv::script::spend::{Spend, SpendParams as BsvSpendParams};
use bsv::script::unlocking_script::UnlockingScript;
use bsv::transaction::transaction_input::TransactionInput;
use bsv::transaction::transaction_output::TransactionOutput;

use crate::error::{err, Error, Result};
use crate::script::Script;
use crate::sighash::{refs_of, OutpointRef};
use crate::tx::{Output, Transaction};

/// The TS Spend constructor parameters.
pub struct SpendParams<'a> {
    pub source_txid: &'a str,
    pub source_output_index: u32,
    pub locking_script: &'a Script,
    pub source_satoshis: u64,
    pub transaction_version: u32,
    pub other_inputs: Vec<OutpointRef>,
    pub unlocking_script: &'a Script,
    pub input_sequence: u32,
    pub input_index: usize,
    pub outputs: &'a [Output],
    pub lock_time: u32,
}

/// `new Spend(p).validate()`: Ok when the spend is valid, else the interpreter's error.
pub fn validate(p: &SpendParams) -> Result<()> {
    let mut others = Vec::new();
    for r in &p.other_inputs {
        let txid = match (&r.source_txid, &r.source_transaction) {
            (Some(t), _) => t.clone(),
            (None, Some(s)) => s.borrow().id()?,
            (None, None) => return err("Missing sourceTransaction for input"),
        };
        others.push(TransactionInput {
            source_transaction: None,
            source_txid: Some(txid),
            source_output_index: r.source_output_index,
            unlocking_script: Some(UnlockingScript::from_binary(&[])),
            sequence: r.sequence.unwrap_or(0xffff_ffff),
        });
    }
    let outputs = p
        .outputs
        .iter()
        .map(|o| TransactionOutput {
            satoshis: Some(o.sats()),
            locking_script: LockingScript::from_binary(
                &o.locking_script
                    .as_ref()
                    .map(|s| s.to_binary())
                    .unwrap_or_default(),
            ),
            change: false,
        })
        .collect();
    let mut spend = Spend::new(BsvSpendParams {
        locking_script: LockingScript::from_binary(&p.locking_script.to_binary()),
        unlocking_script: UnlockingScript::from_binary(&p.unlocking_script.to_binary()),
        source_txid: p.source_txid.to_string(),
        source_output_index: p.source_output_index as usize,
        source_satoshis: p.source_satoshis,
        transaction_version: p.transaction_version,
        transaction_lock_time: p.lock_time,
        transaction_sequence: p.input_sequence,
        other_inputs: others,
        other_outputs: outputs,
        input_index: p.input_index,
    });
    match spend.validate() {
        Ok(true) => Ok(()),
        // ts-sdk's validate() never returns false: a falsy top stack item throws this. (b017's own "the script
        // evaluated false" is therefore unreachable in the reference, and must stay so here.)
        Ok(false) => err("Script evaluation error: The top stack element must be truthy after script evaluation."),
        Err(e) => Err(Error(e.to_string())),
    }
}

/// verifyTx's result (scriptExecutions keeps only each input's verdict).
#[derive(Debug, Clone, Default)]
pub struct VerifyTxResult {
    pub valid: bool,
    pub executions: Vec<bool>,
}

/// boltLib `verifyTx`: run every input (each must have its source tx attached and an unlocking script), then
/// check the output total. Errors are what the TS function throws. Fills a missing sourceTXID, as the TS does.
pub fn verify_tx(tx: &mut Transaction, skip_output_check: bool) -> Result<VerifyTxResult> {
    let mut res = VerifyTxResult::default();
    let mut input_total = 0u64;
    let txid = tx.id()?;
    for i in 0..tx.inputs.len() {
        if tx.inputs[i].source_transaction.is_none() {
            return err(format!(
                "Verification failed: input {i} of {txid} is missing its source transaction."
            ));
        }
        if tx.inputs[i].unlocking_script.is_none() {
            return err(format!(
                "Verification failed: input {i} of {txid} is missing its unlocking script."
            ));
        }
        let src = match tx.inputs[i].source_output() {
            Some(o) => o,
            None => return err("Cannot read properties of undefined (reading 'satoshis')"),
        };
        input_total += src.sats();
        let source_txid = tx.inputs[i]
            .source_transaction
            .as_ref()
            .unwrap()
            .borrow()
            .id()?;
        if tx.inputs[i].source_txid.is_none() {
            tx.inputs[i].source_txid = Some(source_txid);
        }
        let empty = Script::default();
        validate(&SpendParams {
            source_txid: tx.inputs[i].source_txid.as_deref().unwrap(),
            source_output_index: tx.inputs[i].source_output_index,
            locking_script: src.locking_script.as_ref().unwrap_or(&empty),
            source_satoshis: src.sats(),
            transaction_version: tx.version,
            other_inputs: refs_of(&tx.inputs, i),
            unlocking_script: tx.inputs[i].unlocking_script.as_ref().unwrap(),
            input_sequence: tx.inputs[i].seq(),
            input_index: i,
            outputs: &tx.outputs,
            lock_time: tx.lock_time,
        })?;
        res.executions.push(true);
    }
    let mut output_total = 0u64;
    for o in &tx.outputs {
        match o.satoshis {
            None => return err("Every output must have a defined amount during verification."),
            Some(s) => output_total += s,
        }
    }
    if !skip_output_check && output_total > input_total {
        return err("Output total greater than input total");
    }
    res.valid = true;
    Ok(res)
}
