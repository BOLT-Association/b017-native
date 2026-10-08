//! src/lib/multi/multiBoltLib.ts: SimpleMultiBolt ancestor reconstruction and CTX helpers (Go: multiboltlib.go).

use crate::boltlib::{
    output_script, output_value, spent_outpoint, tx_lock_time, tx_version, vin_chunk, vin_script,
    vin_sequence, vout_chunk,
};
use crate::error::Result;
use crate::script::{chunks_from_bin, Chunk, Script};
use crate::singlespend::empty_single_ancestor_chunks;
use crate::tx::{Reader, Transaction};

const ARGS2CTX_SMB: usize = 192;
const SKIP_SMB: usize = 178;
const TXO_TYPE_IDX_SMB: usize = 6;

fn js_slice(b: &[u8], a: usize, e: usize) -> Vec<u8> {
    let a = a.min(b.len());
    let e = e.min(b.len()).max(a);
    b[a..e].to_vec()
}

/// The rebuilt ctx (header + lockLen + lockScriptCode + footer), its one-push serialisation and where the
/// scriptCode starts; None when chunk 192 is absent.
fn vin_ctx(tx: &Transaction, vin: usize) -> Option<(Vec<u8>, Vec<u8>, usize)> {
    let us = tx.inputs.get(vin)?.unlocking_script.as_ref()?;
    let c = us.chunks();
    if c.len() <= ARGS2CTX_SMB {
        return None;
    }
    let d = |i: usize| c.get(i).and_then(|x| x.data.clone()).unwrap_or_default();
    let mut ctx = d(ARGS2CTX_SMB);
    ctx.extend(d(ARGS2CTX_SMB + 5));
    ctx.extend(d(ARGS2CTX_SMB + 3));
    ctx.extend(d(ARGS2CTX_SMB + 4));
    let mut s = Script::default();
    s.write_bin(&ctx);
    let bin = s.to_binary();
    let header_len = bin.len() - ctx.len();
    Some((ctx, bin, 104 + header_len))
}

/// getVinCTXPieceSMB: piece 0 = ctxHeader; piece 2 = the bytes after the scriptCode.
fn get_vin_ctx_piece(tx: &Transaction, vin: usize, piece: usize) -> Result<Vec<u8>> {
    let (ctx, bin, start) = match vin_ctx(tx, vin) {
        None => return Ok(vec![]),
        Some(x) => x,
    };
    let buf = js_slice(&bin, start, bin.len());
    let mut r = Reader::new(&buf);
    let n = r.varint()? as usize;
    if piece == 0 {
        return Ok(js_slice(&ctx, 0, 104));
    }
    Ok(js_slice(&bin, start + n + r.pos, bin.len()))
}

/// getVinCTXDataArgSMB: lock data arg argIdx (0..10) out of the reconstructed scriptCode.
fn get_vin_ctx_data_arg(tx: &Transaction, vin: usize, arg_idx: usize) -> Result<Vec<u8>> {
    let (_, bin, start) = match vin_ctx(tx, vin) {
        None => return Ok(vec![]),
        Some(x) => x,
    };
    let buf = js_slice(&bin, start, bin.len());
    let mut r = Reader::new(&buf);
    let n = r.varint()? as usize;
    let code = Script::from_binary(&js_slice(&buf, r.pos, r.pos + n));
    Ok(match code.chunks().get(arg_idx) {
        None => vec![],
        Some(c) if c.op == 0 => vec![],
        Some(c) => c.data.clone().unwrap_or_default(),
    })
}

/// determineTxTypeSMB: `(data[0] || -1).toString(16)`.
fn determine_tx_type(tx: &Transaction) -> Result<String> {
    let first = match tx.outputs.first() {
        None => {
            return crate::error::err(
                "Cannot read properties of undefined (reading 'lockingScript')",
            )
        }
        Some(o) => o,
    };
    let c = first
        .locking_script
        .as_ref()
        .map(|s| s.chunks().to_vec())
        .unwrap_or_default();
    Ok(
        match c
            .get(TXO_TYPE_IDX_SMB)
            .and_then(|x| x.data.as_ref())
            .and_then(|d| d.first())
        {
            Some(&b) if b != 0 => format!("{b:x}"),
            _ => "-1".into(),
        },
    )
}

/// The 89 SimpleMultiBolt ancestor piece names per ancestor.
pub const SMB_PIECE_NAMES: [&str; 89] = [
    "Version",
    "Vin1Outpoint",
    "Vin1GrandparentProofVoutIdx",
    "Vin1InteropProofVoutIdx",
    "Vin1InteropPubKeyHash",
    "Vin1InteropOutpoint",
    "Vin1InteropParentOutpoint",
    "Vin1FundOutpoint",
    "Vin1ChangeOutput",
    "Vin1PubKeyHash1",
    "Vin1PubKeyHash2",
    "Vin1NextBalanceCommit",
    "Vin1NextTxoType",
    "Vin1InputIndexN",
    "Vin1Sig",
    "Vin1PubKey",
    "Vin1CTXHeader",
    "Vin1CTXBalance",
    "Vin1CTXBalanceCommit",
    "Vin1CTXPubKeyHash",
    "Vin1CTXPubKeyHashCommit",
    "Vin1CTXPubKeyHashCommit2",
    "Vin1CTXOtherGrandparentOutpoint",
    "Vin1CTXTxoType",
    "Vin1CTXOutputIndexN",
    "Vin1CTXParentOutpoint",
    "Vin1CTXGrandparentOutpoint",
    "Vin1CTXIssuerPubKey",
    "Vin1CTXFooter",
    "Vin1NSequence",
    "Vin2Outpoint",
    "Vin2GrandparentProofVoutIdx",
    "Vin2InteropProofVoutIdx",
    "Vin2InteropPubKeyHash",
    "Vin2InteropOutpoint",
    "Vin2InteropParentOutpoint",
    "Vin2FundOutpoint",
    "Vin2ChangeOutput",
    "Vin2PubKeyHash1",
    "Vin2PubKeyHash2",
    "Vin2NextBalanceCommit",
    "Vin2NextTxoType",
    "Vin2InputIndexN",
    "Vin2Sig",
    "Vin2PubKey",
    "Vin2CTXHeader",
    "Vin2CTXBalance",
    "Vin2CTXBalanceCommit",
    "Vin2CTXPubKeyHash",
    "Vin2CTXPubKeyHashCommit",
    "Vin2CTXPubKeyHashCommit2",
    "Vin2CTXOtherGrandparentOutpoint",
    "Vin2CTXTxoType",
    "Vin2CTXOutputIndexN",
    "Vin2CTXParentOutpoint",
    "Vin2CTXGrandparentOutpoint",
    "Vin2CTXIssuerPubKey",
    "Vin2CTXFooter",
    "Vin2NSequence",
    "VinFundOutpoint",
    "VinFundScript",
    "VinFundNSequence",
    "Vout1Balance",
    "Vout1BalanceCommit",
    "Vout1PubKeyHash",
    "Vout1PubKeyHashCommit",
    "Vout1PubKeyHashCommit2",
    "Vout1OtherGrandparentOutpoint",
    "Vout1TxoType",
    "Vout1OutputIndexN",
    "Vout1ParentOutpoint",
    "Vout1GrandparentOutpoint",
    "Vout1IssuerPubKey",
    "Vout2Balance",
    "Vout2BalanceCommit",
    "Vout2PubKeyHash",
    "Vout2PubKeyHashCommit",
    "Vout2PubKeyHashCommit2",
    "Vout2OtherGrandparentOutpoint",
    "Vout2TxoType",
    "Vout2OutputIndexN",
    "Vout2ParentOutpoint",
    "Vout2GrandparentOutpoint",
    "Vout2IssuerPubKey",
    "ProofPubKeyHash1",
    "ProofPubKeyHash2",
    "ChangeValue",
    "ChangeScript",
    "NLockTime",
];

fn vin_offset(rest: &str) -> Option<usize> {
    [
        "GrandparentProofVoutIdx",
        "InteropProofVoutIdx",
        "InteropPubKeyHash",
        "InteropOutpoint",
        "InteropParentOutpoint",
        "FundOutpoint",
        "ChangeOutput",
        "PubKeyHash1",
        "PubKeyHash2",
        "NextBalanceCommit",
        "NextTxoType",
        "InputIndexN",
        "Sig",
        "PubKey",
    ]
    .iter()
    .position(|&x| x == rest)
}

const LOCK_ARGS: [&str; 11] = [
    "Balance",
    "BalanceCommit",
    "PubKeyHash",
    "PubKeyHashCommit",
    "PubKeyHashCommit2",
    "OtherGrandparentOutpoint",
    "TxoType",
    "OutputIndexN",
    "ParentOutpoint",
    "GrandparentOutpoint",
    "IssuerPubKey",
];

fn lock_arg(rest: &str) -> Option<usize> {
    LOCK_ARGS.iter().position(|&x| x == rest)
}

/// multiBoltLib `ancestorPiece(name, tx)`.
pub fn smb_ancestor_piece(name: &str, tx: &Transaction) -> Result<Vec<u8>> {
    let tt = determine_tx_type(tx)?;
    let two_token_inputs = tt == "25";
    let two_bolts = tt == "23";
    let fund_vin = tx.inputs.len().wrapping_sub(1);
    let change_vout = tx.outputs.len().wrapping_sub(1);
    let has_change = tx
        .outputs
        .get(change_vout)
        .and_then(|o| o.locking_script.as_ref())
        .is_some_and(|s| s.chunks().len() == 5);
    let has_funding = tx.inputs.len() > if two_token_inputs { 2 } else { 1 };
    let vin_piece = |vin: usize, rest: &str| -> Result<Vec<u8>> {
        Ok(match rest {
            "Outpoint" => spent_outpoint(tx, vin)?,
            "CTXHeader" => get_vin_ctx_piece(tx, vin, 0)?,
            "CTXFooter" => get_vin_ctx_piece(tx, vin, 2)?,
            "NSequence" => vin_sequence(tx, vin),
            r => {
                if let Some(k) = vin_offset(r) {
                    vin_chunk(tx, vin, SKIP_SMB + k)
                } else if let Some(k) = r.strip_prefix("CTX").and_then(lock_arg) {
                    get_vin_ctx_data_arg(tx, vin, k)?
                } else {
                    vec![]
                }
            }
        })
    };
    if name == "Version" {
        return Ok(tx_version(tx));
    }
    if let Some(rest) = name.strip_prefix("Vin1") {
        return vin_piece(0, rest);
    }
    if let Some(rest) = name.strip_prefix("Vin2") {
        return if two_token_inputs {
            vin_piece(1, rest)
        } else {
            Ok(vec![])
        };
    }
    Ok(match name {
        "VinFundOutpoint" if has_funding => spent_outpoint(tx, fund_vin)?,
        "VinFundScript" if has_funding => vin_script(tx, fund_vin),
        "VinFundNSequence" if has_funding => vin_sequence(tx, fund_vin),
        "ProofPubKeyHash1" => vout_chunk(tx, 1, 4)?,
        "ProofPubKeyHash2" if two_bolts => vout_chunk(tx, 2, 4)?,
        "ChangeValue" if has_change => output_value(tx, change_vout),
        "ChangeScript" if has_change => output_script(tx, change_vout),
        "NLockTime" => tx_lock_time(tx),
        n => {
            if let Some(k) = n.strip_prefix("Vout1").and_then(lock_arg) {
                vout_chunk(tx, 0, k)?
            } else if let Some(k) = n.strip_prefix("Vout2").and_then(lock_arg) {
                if two_bolts {
                    vout_chunk(tx, 1, k)?
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        }
    })
}

/// The 178 OP_0 ancestor chunks a melt carries.
pub fn create_empty_fungible_ancestor_chunks() -> Vec<Chunk> {
    empty_single_ancestor_chunks(SKIP_SMB)
}

#[allow(dead_code)]
fn _unused() -> Vec<Chunk> {
    chunks_from_bin(&[])
}
