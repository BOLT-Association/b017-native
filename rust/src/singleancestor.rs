//! src/lib/single/singleAncestor.ts: the NFT ancestor-piece unlock args a settle carries when it reaches back over
//! a chain of >= 4 txs.

use crate::boltlib::{le32, le64, spent_outpoint};
use crate::error::{err, Result};
use crate::script::{chunk_data, Script};
use crate::tx::Transaction;

/// The 26 NFT ancestor-piece names, in unlock-arg order.
pub const PIECE_NAMES: [&str; 26] = [
    "Version",
    "Vin1Outpoint", "Vin1FundOutpoint", "Vin1ChangeOutput", "Vin1BeneficiaryPubKeyHash",
    "Vin1Sig", "Vin1PubKey", "Vin1CTXHeader",
    "Vin1CTXScriptCodePubKeyHash", "Vin1CTXScriptCodePubKeyHashCommitment", "Vin1CTXScriptCodeTxoType",
    "Vin1CTXScriptCodeParentOutpoint", "Vin1CTXScriptCodeGrandparentOutpoint",
    "Vin1CTXFooter", "Vin1NSequence",
    "Vin2Outpoint", "Vin2Script", "Vin2NSequence",
    "Vout1PubKeyHash", "Vout1PubKeyHashCommitment", "Vout1TxoType", "Vout1ParentOutpoint", "Vout1GrandparentOutpoint",
    "ChangeValue", "ChangeScript", "NLockTime",
];

/// AuthBolt's 27: PIECE_NAMES with "Vin1AuthOrMiscData" after "Vin1Outpoint".
pub fn auth_piece_names() -> Vec<&'static str> {
    let mut v = vec!["Version", "Vin1Outpoint", "Vin1AuthOrMiscData"];
    v.extend_from_slice(&PIECE_NAMES[2..]);
    v
}

/// One NFT-family contract's unlock-arg layout.
#[derive(Clone)]
pub struct SingleLayout {
    pub piece_names: Vec<&'static str>,
    pub has_auth: bool,
}

/// MinSimpleBolt: 37 args.
pub fn min_simple_layout() -> SingleLayout {
    SingleLayout { piece_names: PIECE_NAMES.to_vec(), has_auth: false }
}

/// AuthBolt: 39 args.
pub fn auth_bolt_layout() -> SingleLayout {
    SingleLayout { piece_names: auth_piece_names(), has_auth: true }
}

/// `currentArgsStart`.
pub fn current_args_start(l: &SingleLayout) -> usize {
    l.piece_names.len() + usize::from(l.has_auth)
}

/// `ancestorPiece`: one named piece from an ancestor commit tx.
pub fn ancestor_piece(name: &str, tx: &Transaction, leading_value_pushes: usize, layout: &SingleLayout) -> Result<Vec<u8>> {
    let in0 = &tx.inputs[0];
    let in1 = tx.inputs.get(1);
    let u = match &in0.unlocking_script {
        Some(u) => u,
        None => return err("Cannot read properties of undefined (reading 'chunks')"),
    };
    let cur = current_args_start(layout);
    let spent_lock = Script::from_binary(&chunk_data(u, cur + 8));
    let sd = |i: usize| chunk_data(&spent_lock, leading_value_pushes + i);
    let out_lock = tx.outputs[0].locking_script.clone().unwrap_or_default();
    let od = |i: usize| chunk_data(&out_lock, leading_value_pushes + i);
    let change = tx.outputs.get(2);
    let uc = |i: usize| chunk_data(u, i);
    Ok(match name {
        "Version" => le32(tx.version),
        "Vin1Outpoint" => spent_outpoint(tx, 0)?,
        "Vin1AuthOrMiscData" => uc(0),
        "Vin1FundOutpoint" => uc(cur),
        "Vin1ChangeOutput" => uc(cur + 1),
        "Vin1BeneficiaryPubKeyHash" => uc(cur + 2),
        "Vin1Sig" => uc(cur + 3),
        "Vin1PubKey" => uc(cur + 4),
        "Vin1CTXHeader" => uc(cur + 5),
        "Vin1CTXScriptCodePubKeyHash" => sd(0),
        "Vin1CTXScriptCodePubKeyHashCommitment" => sd(1),
        "Vin1CTXScriptCodeTxoType" => sd(2),
        "Vin1CTXScriptCodeParentOutpoint" => sd(3),
        "Vin1CTXScriptCodeGrandparentOutpoint" => sd(4),
        "Vin1CTXFooter" => uc(cur + 9),
        "Vin1NSequence" => le32(in0.seq()),
        "Vin2Outpoint" => match in1 {
            None => vec![],
            Some(_) => spent_outpoint(tx, 1)?,
        },
        "Vin2Script" => match in1 {
            None => vec![],
            Some(i) => match &i.unlocking_script {
                None => return err("Cannot read properties of undefined (reading 'toBinary')"),
                Some(s) => s.to_binary(),
            },
        },
        "Vin2NSequence" => in1.map(|i| le32(i.seq())).unwrap_or_default(),
        "Vout1PubKeyHash" => od(0),
        "Vout1PubKeyHashCommitment" => od(1),
        "Vout1TxoType" => od(2),
        "Vout1ParentOutpoint" => od(3),
        "Vout1GrandparentOutpoint" => od(4),
        "ChangeValue" => change.map(|c| le64(c.sats())).unwrap_or_default(),
        "ChangeScript" => change.and_then(|c| c.locking_script.as_ref()).map(|s| s.to_binary()).unwrap_or_default(),
        "NLockTime" => le32(tx.lock_time),
        _ => vec![],
    })
}

/// `singleAncestorPieces`.
pub fn single_ancestor_pieces(tx: &Transaction, leading_value_pushes: usize, layout: &SingleLayout) -> Result<Vec<Vec<u8>>> {
    layout.piece_names.iter().map(|n| ancestor_piece(n, tx, leading_value_pushes, layout)).collect()
}
