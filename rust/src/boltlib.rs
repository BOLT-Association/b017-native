//! src/lib/boltLib.ts: the layout-agnostic helpers shared by both token streams.

use std::rc::Rc;

use crate::error::{err, Result};
use crate::script::{chunk_data, hex_decode, js_hex_to_array, Chunk, Script};
use crate::sighash::{format_preimage, refs_of, sha256, BoxFuture, PreimageParams, Signer, SIGNATURE_SCOPE};
use crate::tx::{reversed, varint_bytes, Transaction, Writer};

/// The TS ScriptTemplate unlocker: `{ sign(tx, inputIndex), estimateLength() }`.
pub trait UnlockTemplate {
    fn sign<'a>(&'a self, tx: &'a Transaction, input_index: usize) -> BoxFuture<'a, Result<Script>>;
    fn estimate_length(&self) -> usize;
}

/// `buildOutpoint`: tx hash (internal order) + LE32 vout.
pub fn build_outpoint(tx: &Transaction, output_index: u32) -> Result<Vec<u8>> {
    let mut h = tx.hash()?;
    h.extend_from_slice(&output_index.to_le_bytes());
    Ok(h)
}

/// `buildChangeOutput`: 8-byte value + varint script length + script, or [] when absent.
pub fn build_change_output(tx: &Transaction, output_index: usize) -> Vec<u8> {
    let o = match tx.outputs.get(output_index) {
        None => return vec![],
        Some(o) => o,
    };
    let mut w = Writer::default();
    w.u64(o.sats());
    let b = o.locking_script.as_ref().map(|s| s.to_binary()).unwrap_or_default();
    w.varint(b.len() as u64);
    w.bytes(&b);
    w.0
}

/// `createSignature`: the signer signs sha256(preimage); returns (checksig-format sig, pubkey).
pub async fn create_signature(signer: &dyn Signer, preimage: &[u8], scope: u32) -> Result<(Vec<u8>, Vec<u8>)> {
    let raw = signer.sign(&sha256(preimage)).await?;
    Ok((raw.checksig_format(scope), signer.public_key()))
}

/// The txid an input spends: its sourceTXID, else the attached source's id ("" when neither).
pub fn input_source_txid(tx: &Transaction, i: usize) -> Result<String> {
    let input = &tx.inputs[i];
    if let Some(id) = input.source_txid.as_ref().filter(|s| !s.is_empty()) {
        return Ok(id.clone());
    }
    match &input.source_transaction {
        Some(s) => s.borrow().id(),
        None => Ok(String::new()),
    }
}

/// boltLib `p2pkhUnlock`: a P2PKH unlock driven by a Signer.
pub struct P2PKHUnlock(pub Rc<dyn Signer>);

impl UnlockTemplate for P2PKHUnlock {
    fn estimate_length(&self) -> usize {
        108
    }
    fn sign<'a>(&'a self, tx: &'a Transaction, input_index: usize) -> BoxFuture<'a, Result<Script>> {
        Box::pin(async move {
            let input = &tx.inputs[input_index];
            let src = input.source_output();
            let source_txid = input_source_txid(tx, input_index)?;
            let src = match src {
                Some(s) if !source_txid.is_empty() => s,
                _ => return err("p2pkhUnlock requires the input's source transaction"),
            };
            let empty = Script::default();
            let pre = format_preimage(&PreimageParams {
                source_txid: &source_txid,
                source_output_index: input.source_output_index,
                source_satoshis: src.sats(),
                transaction_version: tx.version,
                other_inputs: refs_of(&tx.inputs, input_index),
                input_index,
                outputs: &tx.outputs,
                input_sequence: input.sequence,
                subscript: src.locking_script.as_ref().unwrap_or(&empty),
                lock_time: tx.lock_time,
                scope: SIGNATURE_SCOPE,
            })?;
            let (sig, pub_key) = create_signature(self.0.as_ref(), &pre, SIGNATURE_SCOPE).await?;
            Ok(Script::new(vec![Chunk::push(sig.len() as u8, sig), Chunk::push(pub_key.len() as u8, pub_key)]))
        })
    }
}

/// splitCtx's result: a BIP143 preimage split around its scriptCode.
pub struct Ctx {
    pub header: Vec<u8>,
    pub code_len: Vec<u8>,
    pub unlock_script_code: Vec<u8>,
    pub lock_script_code: Vec<u8>,
    pub footer: Vec<u8>,
    pub lock_len: Vec<u8>,
}

fn js_slice(b: &[u8], a: usize, e: usize) -> Vec<u8> {
    let a = a.min(b.len());
    let e = e.min(b.len()).max(a);
    b[a..e].to_vec()
}

/// `splitCtx`.
pub fn split_ctx(ctx: &[u8], unlock_bytes_len: usize) -> Ctx {
    let header = js_slice(ctx, 0, 104);
    let first = ctx.get(104).copied().unwrap_or(0) as usize;
    let len_size = match first {
        0xfd => 3,
        0xfe => 5,
        0xff => 9,
        _ => 1,
    };
    let code_len = js_slice(ctx, 104, 104 + len_size);
    let mut offset = 104 + len_size;
    let at = js_slice(ctx, 105, 113);
    let actual = match first {
        0xfd if at.len() >= 2 => u16::from_le_bytes([at[0], at[1]]) as usize,
        0xfe if at.len() >= 4 => u32::from_le_bytes([at[0], at[1], at[2], at[3]]) as usize,
        0xff if at.len() >= 8 => u64::from_le_bytes(at[..8].try_into().unwrap()) as usize,
        _ => first,
    };
    let code = js_slice(ctx, offset, offset.saturating_add(actual));
    offset = offset.saturating_add(actual);
    let n = unlock_bytes_len.min(code.len());
    let lock = code[n..].to_vec();
    Ctx {
        header,
        code_len,
        unlock_script_code: code[..n].to_vec(),
        footer: js_slice(ctx, offset, offset.saturating_add(52)),
        lock_len: varint_bytes(lock.len() as u64),
        lock_script_code: lock,
    }
}

pub fn le32(n: u32) -> Vec<u8> {
    n.to_le_bytes().to_vec()
}
pub fn le64(n: u64) -> Vec<u8> {
    n.to_le_bytes().to_vec()
}

/// `txVersion` / `txLockTime`.
pub fn tx_version(tx: &Transaction) -> Vec<u8> {
    le32(tx.version)
}
pub fn tx_lock_time(tx: &Transaction) -> Vec<u8> {
    le32(tx.lock_time)
}

/// `spentOutpoint`: the 36-byte outpoint input `vin` spends, or [].
pub fn spent_outpoint(tx: &Transaction, vin: usize) -> Result<Vec<u8>> {
    let input = match tx.inputs.get(vin) {
        None => return Ok(vec![]),
        Some(i) => i,
    };
    let txid = match &input.source_transaction {
        Some(s) => s.borrow().hash()?,
        None => {
            let s = input.source_txid.clone().unwrap_or_default();
            reversed(&hex_decode(&s).unwrap_or_else(|| js_hex_to_array(&s)))
        }
    };
    if txid.is_empty() {
        return Ok(vec![]);
    }
    let mut out = txid;
    out.extend(le32(input.source_output_index));
    Ok(out)
}

/// `vinChunk`.
pub fn vin_chunk(tx: &Transaction, vin: usize, chunk_idx: usize) -> Vec<u8> {
    tx.inputs.get(vin).and_then(|i| i.unlocking_script.as_ref()).map(|s| chunk_data(s, chunk_idx)).unwrap_or_default()
}

/// `vinSequence`.
pub fn vin_sequence(tx: &Transaction, vin: usize) -> Vec<u8> {
    tx.inputs.get(vin).map(|i| le32(i.seq())).unwrap_or_default()
}

/// `vinScript`.
pub fn vin_script(tx: &Transaction, vin: usize) -> Vec<u8> {
    tx.inputs.get(vin).and_then(|i| i.unlocking_script.as_ref()).map(|s| s.to_binary()).unwrap_or_default()
}

/// `voutChunk` (TS throws for a missing output).
pub fn vout_chunk(tx: &Transaction, vout: usize, chunk_idx: usize) -> Result<Vec<u8>> {
    match tx.outputs.get(vout) {
        None => err("Cannot read properties of undefined (reading 'lockingScript')"),
        Some(o) => Ok(o.locking_script.as_ref().map(|s| chunk_data(s, chunk_idx)).unwrap_or_default()),
    }
}

/// `outputValue`.
pub fn output_value(tx: &Transaction, idx: usize) -> Vec<u8> {
    tx.outputs.get(idx).map(|o| le64(o.sats())).unwrap_or_default()
}

/// `outputScript`.
pub fn output_script(tx: &Transaction, idx: usize) -> Vec<u8> {
    tx.outputs.get(idx).and_then(|o| o.locking_script.as_ref()).map(|s| s.to_binary()).unwrap_or_default()
}
