//! The two @bsv/sdk Transaction builder steps b017's classes use: fee(0) and sign(). See the Go port's txbuild.go.

use std::collections::HashSet;

use crate::beefsdk::fill_source_txids;
use crate::error::{err, Result};
use crate::script::Script;
use crate::tx::{Transaction, TxRef};

/// `await tx.fee(0)`: change outputs take inputs minus outputs, equally; dropped when that is 0.
pub fn fee0(tx: &mut Transaction) -> Result<()> {
    let mut total_in = 0u64;
    for (i, input) in tx.inputs.iter().enumerate() {
        let src = match &input.source_transaction {
            None => {
                return err(
                    "Source transactions are required for all inputs during fee computation",
                )
            }
            Some(s) => s,
        };
        let o = match src
            .borrow()
            .outputs
            .get(input.source_output_index as usize)
            .cloned()
        {
            None => {
                return err(format!(
                    "Input {i} references a source output that does not exist."
                ))
            }
            Some(o) => o,
        };
        match o.satoshis {
            None => {
                return err(format!(
                    "Input {i} source amount must be a non-negative safe integer"
                ))
            }
            Some(s) => total_in += s,
        }
    }
    let mut total_out = 0u64;
    for (i, o) in tx.outputs.iter().enumerate() {
        if o.change {
            continue;
        }
        match o.satoshis {
            None => {
                return err(format!(
                    "Output {i} amount must be a non-negative safe integer"
                ))
            }
            Some(s) => total_out += s,
        }
    }
    if total_out > total_in {
        return err("Transaction inputs are insufficient for the requested outputs and fee.");
    }
    let change = total_in - total_out;
    if change == 0 {
        tx.outputs.retain(|o| !o.change);
        return Ok(());
    }
    let n = tx.outputs.iter().filter(|o| o.change).count() as u64;
    if n == 0 {
        return Ok(());
    }
    let per = change / n;
    let mut last = None;
    for (i, o) in tx.outputs.iter_mut().enumerate() {
        if o.change {
            o.satoshis = Some(per);
            last = Some(i);
        }
    }
    if let Some(i) = last {
        *tx.outputs[i].satoshis.as_mut().unwrap() += change - per * n;
    }
    Ok(())
}

/// `await tx.sign()`: fill every input's sourceTXID across the graph, sign each templated input on a snapshot of
/// the unsigned tx, then apply all the unlocking scripts.
pub async fn sign_tx(tx: &TxRef) -> Result<()> {
    {
        let b = tx.borrow();
        for o in &b.outputs {
            if o.satoshis.is_none() {
                if o.change {
                    return err("There are still change outputs with uncomputed amounts. Use the fee() method to compute the change amounts and transaction fees prior to signing.");
                }
                return err("One or more transaction outputs is missing an amount. Ensure all output amounts are provided before signing.");
            }
        }
        for (i, input) in b.inputs.iter().enumerate() {
            if let Some(s) = &input.source_transaction {
                if s.borrow()
                    .outputs
                    .get(input.source_output_index as usize)
                    .is_none()
                {
                    return err(format!(
                        "Input {i} references a source output that does not exist."
                    ));
                }
            }
        }
    }
    fill_source_txids(tx, &mut HashSet::new())?;
    let snap = tx.borrow().clone();
    let mut scripts: Vec<Option<Script>> = vec![None; snap.inputs.len()];
    for (i, input) in snap.inputs.iter().enumerate() {
        if let Some(t) = &input.template {
            let view = snap.clone();
            let us = t.sign(&view, i).await?;
            scripts[i] = Some(Script::from_binary(&us.to_binary()));
        }
    }
    let mut b = tx.borrow_mut();
    for (i, s) in scripts.into_iter().enumerate() {
        if b.inputs[i].template.is_some() {
            b.inputs[i].unlocking_script = s;
        }
    }
    Ok(())
}

/// `Transaction.fromHex(tx.toHex())` with each input's source re-attached (what the classes do after signing).
pub fn reparse(tx: &Transaction) -> Result<Transaction> {
    let mut clean = Transaction::from_hex(&tx.to_hex()?)?;
    for (i, input) in tx.inputs.iter().enumerate() {
        clean.inputs[i].source_transaction = input.source_transaction.clone();
    }
    Ok(clean)
}
