//! src/lib/scanner/beef.ts: the off-chain data package, Atomic BEEF (BRC-95) over BEEF V2 (BRC-96).

use crate::beefsdk::{fill_source_txids, Beef, BEEF_V2};
use crate::error::{err, Result};
use crate::script::{hex_encode, js_hex_to_array};
use crate::tx::TxRef;

/// A BEEF / tx input: a hex string or bytes.
pub enum Bin<'a> {
    Hex(&'a str),
    Bytes(&'a [u8]),
}

/// `isBeef`: the hex string / bytes begin with a BEEF magic (V1, V2 or Atomic).
pub fn is_beef(x: &Bin) -> bool {
    let head = match x {
        Bin::Hex(s) => s.chars().take(8).collect::<String>().to_lowercase(),
        Bin::Bytes(b) => hex_encode(&b[..b.len().min(4)]),
    };
    head == "0100beef" || head == "0200beef" || head == "01010101"
}

/// `toAtomicBeef`: tx and every attached source tx (with merkle paths), Atomic BEEF over BEEF V2.
pub fn to_atomic_beef(tx: &TxRef) -> Result<Vec<u8>> {
    fill_source_txids(tx, &mut Default::default())?;
    let mut beef = Beef::new(BEEF_V2);
    beef.merge_transaction(tx)?;
    let id = tx.borrow().id()?;
    beef.to_binary_atomic(&id)
}

/// `fromBeef`: parse BEEF V2 (plain or Atomic) into its subject transaction, ancestors wired in.
pub fn from_beef(input: &Bin) -> Result<TxRef> {
    let bytes = match input {
        Bin::Hex(s) => js_hex_to_array(s)?,
        Bin::Bytes(b) => b.to_vec(),
    };
    let mut beef = Beef::from_binary(&bytes)?;
    if beef.version != BEEF_V2 {
        return err(
            "BEEF V1 (BRC-62) is not accepted; use BEEF V2 (BRC-96) / Atomic BEEF (BRC-95)",
        );
    }
    if !beef.is_valid(false)? {
        return err("BEEF is not self-contained: a tx is neither proven by a BUMP nor has all its inputs in the BEEF");
    }
    let entries = beef.entries()?;
    for (txid, tx, proven) in &entries {
        if let Some(t) = tx {
            if !proven && t.borrow().inputs.is_empty() {
                return err(format!(
                    "BEEF is not self-contained: tx {} has no inputs and no BUMP",
                    &txid[..txid.len().min(8)]
                ));
            }
        }
    }
    let subject = match &beef.atomic_txid {
        Some(a) => Some(a.clone()),
        None => entries
            .iter()
            .rev()
            .find(|(_, t, _)| t.is_some())
            .map(|(id, _, _)| id.clone()),
    };
    let tx = match subject {
        Some(s) => beef.find_atomic_transaction(&s)?,
        None => None,
    };
    match tx {
        Some(t) => Ok(t),
        None => err("BEEF has no subject transaction"),
    }
}
