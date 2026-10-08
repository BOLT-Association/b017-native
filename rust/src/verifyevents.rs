//! src/lib/scanner/verifyEvents.ts: the shared off-chain BOLT validator (the scanner): verify_event (one event),
//! verify_events (a batch), verify_and_broadcast (a batch, then its anchors broadcast). A line-by-line
//! transcription (as the Go port's verifyevents.go). The scanner never fails: anything that errors inside becomes
//! `unverifiable input: …`, as the TS catch does.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use serde_json_lite::Json;

use crate::beef::{from_beef, is_beef, Bin};
use crate::error::{err, Error, Result};
use crate::fingerprints::{issuer_pub_key_of, recognize_p2p, recognize_type, TokenType};
use crate::script::{chunk_data, hex_encode, Script, OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160};
use crate::sighash::{BoxFuture, OutpointRef};
use crate::spend::{validate, SpendParams};
use crate::tx::{reversed, tx_ref, Input, Output, Transaction, TxRef};

/// Minimal JSON values for results (so the crate needs no serde).
pub mod serde_json_lite {
    /// A JSON value.
    #[derive(Debug, Clone, PartialEq)]
    pub enum Json {
        Null,
        Bool(bool),
        Num(u64),
        Str(String),
        Arr(Vec<Json>),
        Obj(Vec<(String, Json)>),
    }
    impl Json {
        /// Serialise (keys in insertion order).
        pub fn to_string(&self) -> String {
            match self {
                Json::Null => "null".into(),
                Json::Bool(b) => b.to_string(),
                Json::Num(n) => n.to_string(),
                Json::Str(s) => {
                    let mut o = String::from("\"");
                    for c in s.chars() {
                        match c {
                            '"' => o.push_str("\\\""),
                            '\\' => o.push_str("\\\\"),
                            '\n' => o.push_str("\\n"),
                            '\r' => o.push_str("\\r"),
                            '\t' => o.push_str("\\t"),
                            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
                            c => o.push(c),
                        }
                    }
                    o.push('"');
                    o
                }
                Json::Arr(a) => format!("[{}]", a.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")),
                Json::Obj(m) => format!(
                    "{{{}}}",
                    m.iter().map(|(k, v)| format!("{}:{}", Json::Str(k.clone()).to_string(), v.to_string())).collect::<Vec<_>>().join(",")
                ),
            }
        }
    }
}

const F_PUB_KEY_HASH: usize = 0;
const F_COMMITMENT: usize = 1;
const F_TXO_TYPE: usize = 2;
const F_PARENT: usize = 3;
const F_GRANDPARENT: usize = 4;

fn field_idx(t: TokenType, f: usize) -> usize {
    match t {
        TokenType::MinSimpleBOLT | TokenType::AuthBOLT => [0, 1, 2, 3, 4][f],
        TokenType::SimpleMultiBOLT => [2, 3, 6, 8, 9][f],
    }
}

fn field(lock: &Script, t: TokenType, f: usize) -> Vec<u8> {
    chunk_data(lock, field_idx(t, f))
}

fn parse_outpoint(op: &[u8]) -> (String, u32) {
    let n = op.len().min(32);
    let txid = hex_encode(&reversed(&op[..n]));
    let mut v = [0u8; 4];
    if op.len() > 32 {
        let e = op.len().min(36);
        v[..e - 32].copy_from_slice(&op[32..e]);
    }
    (txid, u32::from_le_bytes(v))
}

/// A trusted issuer key: hex (compared lowercased) or bytes.
#[derive(Clone)]
pub enum TrustedKey {
    Hex(String),
    Bytes(Vec<u8>),
}

/// isKnownBlockRoot: `Ok(true)` only for a known root; an `Err` is a throwing lookup (not known).
pub type KnownRoot = Rc<dyn Fn(&str, u64) -> Result<bool>>;

/// The scanner options.
#[derive(Clone, Default)]
pub struct ScanOpts {
    pub expected_type: Option<TokenType>,
    pub trusted_issuer_pub_key: Option<TrustedKey>,
    pub is_known_block_root: Option<KnownRoot>,
    pub require_broadcastable: bool,
}

/// An event tx: a Transaction, raw tx hex, or BEEF hex / bytes; `Other` is anything else a caller handed in.
#[derive(Clone)]
pub enum TxInput {
    Tx(TxRef),
    Hex(String),
    Bytes(Vec<u8>),
    Other,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OffChainOnlyTx {
    pub txid: String,
    pub input_sats: u64,
    pub output_sats: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SourceTx {
    pub txid: String,
    pub proven: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub kind: String,
    pub txids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnchorRef {
    pub txid: String,
    pub kind: String,
    pub status: Option<String>,
    pub detail: Option<String>,
}

/// verifyEvents' result; `None` fields are absent (TS `undefined`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScanResult {
    pub ok: bool,
    pub reason: Option<String>,
    pub token_type: Option<TokenType>,
    pub issuer_pub_key_hex: Option<String>,
    pub sources: Option<Vec<SourceTx>>,
    pub unauthenticated: bool,
    pub events: Option<Vec<Event>>,
    pub anchors: Option<Vec<AnchorRef>>,
    pub off_chain_only: Option<Vec<OffChainOnlyTx>>,
}

/// verifyEvent's result (`kind` may be a tx category on an arrangement failure, as in the reference).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EventResult {
    pub ok: bool,
    pub reason: Option<String>,
    pub token_type: Option<TokenType>,
    pub kind: Option<String>,
    pub sources: Option<Vec<SourceTx>>,
    pub unauthenticated: bool,
    pub anchors: Option<Vec<AnchorRef>>,
    pub off_chain_only: Option<Vec<OffChainOnlyTx>>,
}

fn j_sources(v: &[SourceTx]) -> Json {
    Json::Arr(v.iter().map(|s| Json::Obj(vec![("txid".into(), Json::Str(s.txid.clone())), ("proven".into(), Json::Bool(s.proven))])).collect())
}
fn j_anchors(v: &[AnchorRef]) -> Json {
    Json::Arr(
        v.iter()
            .map(|a| {
                let mut m = vec![("txid".into(), Json::Str(a.txid.clone())), ("kind".into(), Json::Str(a.kind.clone()))];
                if let Some(s) = &a.status {
                    m.push(("status".into(), Json::Str(s.clone())));
                }
                if let Some(d) = &a.detail {
                    m.push(("detail".into(), Json::Str(d.clone())));
                }
                Json::Obj(m)
            })
            .collect(),
    )
}
fn j_offchain(v: &[OffChainOnlyTx]) -> Json {
    Json::Arr(
        v.iter()
            .map(|o| {
                Json::Obj(vec![
                    ("txid".into(), Json::Str(o.txid.clone())),
                    ("inputSats".into(), Json::Num(o.input_sats)),
                    ("outputSats".into(), Json::Num(o.output_sats)),
                ])
            })
            .collect(),
    )
}

impl ScanResult {
    fn fail(reason: impl Into<String>) -> Self {
        ScanResult { reason: Some(reason.into()), ..Default::default() }
    }
    /// The fields the reference sets, as JSON.
    pub fn to_json(&self) -> Json {
        let mut m = vec![("ok".to_string(), Json::Bool(self.ok))];
        if let Some(r) = &self.reason {
            m.push(("reason".into(), Json::Str(r.clone())));
        }
        if let Some(t) = self.token_type {
            m.push(("type".into(), Json::Str(t.as_str().into())));
        }
        if let Some(i) = &self.issuer_pub_key_hex {
            m.push(("issuerPubKeyHex".into(), Json::Str(i.clone())));
        }
        if let Some(s) = &self.sources {
            m.push(("sources".into(), j_sources(s)));
        }
        if self.unauthenticated {
            m.push(("unauthenticated".into(), Json::Bool(true)));
        }
        if let Some(e) = &self.events {
            m.push((
                "events".into(),
                Json::Arr(
                    e.iter()
                        .map(|e| {
                            Json::Obj(vec![
                                ("kind".into(), Json::Str(e.kind.clone())),
                                ("txids".into(), Json::Arr(e.txids.iter().map(|t| Json::Str(t.clone())).collect())),
                            ])
                        })
                        .collect(),
                ),
            ));
        }
        if let Some(a) = &self.anchors {
            m.push(("anchors".into(), j_anchors(a)));
        }
        if let Some(o) = &self.off_chain_only {
            m.push(("offChainOnly".into(), j_offchain(o)));
        }
        Json::Obj(m)
    }
}

impl EventResult {
    fn fail(reason: impl Into<String>) -> Self {
        EventResult { reason: Some(reason.into()), ..Default::default() }
    }
    /// The fields the reference sets, as JSON.
    pub fn to_json(&self) -> Json {
        let mut m = vec![("ok".to_string(), Json::Bool(self.ok))];
        if let Some(r) = &self.reason {
            m.push(("reason".into(), Json::Str(r.clone())));
        }
        if let Some(t) = self.token_type {
            m.push(("type".into(), Json::Str(t.as_str().into())));
        }
        if let Some(k) = &self.kind {
            m.push(("kind".into(), Json::Str(k.clone())));
        }
        if let Some(s) = &self.sources {
            m.push(("sources".into(), j_sources(s)));
        }
        if self.unauthenticated {
            m.push(("unauthenticated".into(), Json::Bool(true)));
        }
        if let Some(a) = &self.anchors {
            m.push(("anchors".into(), j_anchors(a)));
        }
        if let Some(o) = &self.off_chain_only {
            m.push(("offChainOnly".into(), j_offchain(o)));
        }
        Json::Obj(m)
    }
}

/// What the network said about a broadcast anchor.
#[derive(Debug, Clone, Default)]
pub struct AnchorBroadcastResult {
    pub status: Option<String>,
    pub detail: Option<String>,
}

/// The caller's broadcaster: send ONE anchor and report accepted / already-seen / rejected.
pub trait AnchorBroadcaster {
    fn broadcast<'a>(&'a self, anchor: TxRef) -> BoxFuture<'a, Result<AnchorBroadcastResult>>;
}

/// An async source of block headers (the ChainTracker shape).
pub trait HeaderSource {
    fn is_valid_root_for_height<'a>(&'a self, root: &'a str, height: u64) -> BoxFuture<'a, Result<bool>>;
}

/// The first line of an error's message.
fn err_text(e: &Error) -> String {
    e.0.split('\n').next().unwrap_or("").to_string()
}

fn to_tx(t: &TxInput) -> std::result::Result<TxRef, String> {
    let bin = match t {
        TxInput::Tx(x) => return Ok(x.clone()),
        TxInput::Hex(h) => Bin::Hex(h),
        TxInput::Bytes(b) => Bin::Bytes(b),
        TxInput::Other => return Err("not a transaction: expected a Transaction, raw tx hex, or BEEF hex / bytes".into()),
    };
    if is_beef(&bin) {
        return from_beef(&bin).map_err(|e| format!("invalid BEEF: {}", err_text(&e)));
    }
    let r = match bin {
        Bin::Hex(h) => Transaction::from_hex(h),
        Bin::Bytes(b) => Transaction::from_binary(b),
    };
    r.map(tx_ref).map_err(|e| format!("malformed transaction hex: {}", err_text(&e)))
}

fn opt_hex(k: &Option<TrustedKey>) -> String {
    match k {
        None => String::new(),
        Some(TrustedKey::Hex(s)) => s.to_lowercase(),
        Some(TrustedKey::Bytes(b)) => hex_encode(b),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Cls {
    Token,
    P2p,
    P2pkh,
    External,
    Other,
}

impl Cls {
    fn s(&self) -> &'static str {
        match self {
            Cls::Token => "token",
            Cls::P2p => "p2p",
            Cls::P2pkh => "p2pkh",
            Cls::External => "external",
            Cls::Other => "other",
        }
    }
}

type ById = HashMap<String, TxRef>;

fn id_of(t: &TxRef) -> Result<String> {
    t.borrow().id()
}
fn id8(t: &TxRef) -> Result<String> {
    Ok(id_of(t)?[..8].to_string())
}
fn first8(s: &str) -> &str {
    &s[..s.len().min(8)]
}

fn source_of(input: &Input, ids: &ById) -> Option<TxRef> {
    if let Some(s) = &input.source_transaction {
        return Some(s.clone());
    }
    input.source_txid.as_ref().and_then(|id| ids.get(id).cloned())
}

fn spent_txid(input: &Input) -> Result<Option<String>> {
    if let Some(id) = &input.source_txid {
        return Ok(Some(id.clone()));
    }
    match &input.source_transaction {
        Some(s) => Ok(Some(s.borrow().id()?)),
        None => Ok(None),
    }
}

fn out_at(t: &Option<TxRef>, i: u32) -> Option<Output> {
    t.as_ref().and_then(|t| t.borrow().outputs.get(i as usize).cloned())
}

fn classify_out(lock: Option<&Script>, t: TokenType) -> Cls {
    if recognize_type(lock, Some(t)).is_some() {
        return Cls::Token;
    }
    if recognize_p2p(lock) {
        return Cls::P2p;
    }
    let c = lock.map(|l| l.chunks()).unwrap_or(&[]);
    if c.len() == 5
        && c[0].op == OP_DUP
        && c[1].op == OP_HASH160
        && c[2].data.as_ref().is_some_and(|d| d.len() == 20)
        && c[3].op == OP_EQUALVERIFY
        && c[4].op == OP_CHECKSIG
    {
        return Cls::P2pkh;
    }
    Cls::Other
}

fn classify_in(input: &Input, t: TokenType, ids: &ById) -> Cls {
    match out_at(&source_of(input, ids), input.source_output_index).and_then(|o| o.locking_script) {
        None => Cls::External,
        Some(l) => classify_out(Some(&l), t),
    }
}

#[derive(Clone, Copy)]
struct Shape {
    kind: &'static str,
    token_in: usize,
    token_out: usize,
    proof_out: usize,
}

#[derive(Clone, Copy)]
struct Category {
    shape: Shape,
    token_out_idx: i64,
}

fn token_out_index(tx: &Transaction, t: TokenType) -> i64 {
    tx.outputs.iter().position(|o| recognize_type(o.locking_script.as_ref(), Some(t)).is_some()).map_or(-1, |i| i as i64)
}

fn categorise(tx: &TxRef, t: TokenType, ids: &ById) -> Option<Category> {
    let b = tx.borrow();
    let idx = token_out_index(&b, t);
    if idx >= 0 {
        let lock = b.outputs[idx as usize].locking_script.clone().unwrap_or_default();
        if field(&lock, t, F_PARENT).iter().all(|&x| x == 0) {
            return Some(Category { shape: Shape { kind: "mint", token_in: 0, token_out: 1, proof_out: 0 }, token_out_idx: idx });
        }
        let s = |kind, a, bb, c| Some(Category { shape: Shape { kind, token_in: a, token_out: bb, proof_out: c }, token_out_idx: idx });
        return match hex_encode(&field(&lock, t, F_TXO_TYPE)).as_str() {
            "21" => s("commit", 1, 1, 1),
            "23" => s("commit", 1, 1, 2),
            "25" => s("commit", 2, 1, 1),
            "22" => s("settle", 1, 2, 0),
            _ => s("settle", 1, 1, 0),
        };
    }
    if b.inputs.iter().any(|i| classify_in(i, t, ids) == Cls::Token) {
        return Some(Category { shape: Shape { kind: "melt", token_in: 1, token_out: 0, proof_out: 0 }, token_out_idx: -1 });
    }
    None
}

fn unauthenticated_mint(txs: &[TxRef], t: TokenType, ids: &ById) -> Result<Option<TxRef>> {
    let cats: Vec<(TxRef, Option<Category>)> = txs.iter().map(|tx| (tx.clone(), categorise(tx, t, ids))).collect();
    let commits: Vec<&TxRef> = cats.iter().filter(|(_, c)| c.is_some_and(|c| c.shape.kind == "commit")).map(|(tx, _)| tx).collect();
    for (tx, cat) in &cats {
        let cat = match cat {
            Some(c) if c.shape.kind == "mint" => c,
            _ => continue,
        };
        let txid = id_of(tx)?;
        let mut spent = false;
        for c in &commits {
            for i in &c.borrow().inputs {
                if spent_txid(i)?.as_deref() == Some(txid.as_str()) && i.source_output_index as i64 == cat.token_out_idx {
                    spent = true;
                }
            }
        }
        if !spent {
            return Ok(Some(tx.clone()));
        }
    }
    Ok(None)
}

fn execute_inputs(txs: &[TxRef], ids: &ById) -> Result<Option<String>> {
    for tx in txs {
        let id = id8(tx)?;
        let b = tx.borrow();
        for (vin, input) in b.inputs.iter().enumerate() {
            let out = match out_at(&source_of(input, ids), input.source_output_index) {
                None => return Ok(Some(format!("script execution failed: tx {id} input {vin}: its source tx was not supplied"))),
                Some(o) => o,
            };
            let failure = (|| -> Result<Option<String>> {
                let us = match &input.unlocking_script {
                    None => return Ok(Some("no unlocking script".into())),
                    Some(u) => u,
                };
                let mut others = vec![];
                for (k, o) in b.inputs.iter().enumerate() {
                    if k != vin {
                        others.push(OutpointRef {
                            source_txid: spent_txid(o)?,
                            source_transaction: None,
                            source_output_index: o.source_output_index,
                            sequence: Some(o.seq()),
                        });
                    }
                }
                let empty = Script::default();
                let txid = spent_txid(input)?.unwrap_or_default();
                match validate(&SpendParams {
                    source_txid: &txid,
                    source_output_index: input.source_output_index,
                    locking_script: out.locking_script.as_ref().unwrap_or(&empty),
                    source_satoshis: out.sats(),
                    transaction_version: b.version,
                    other_inputs: others,
                    unlocking_script: us,
                    input_sequence: input.seq(),
                    input_index: vin,
                    outputs: &b.outputs,
                    lock_time: b.lock_time,
                }) {
                    Ok(()) => Ok(None),
                    Err(e) => Ok(Some(err_text(&e))),
                }
            })();
            let failure = match failure {
                Ok(f) => f,
                Err(e) => Some(err_text(&e)),
            };
            if let Some(f) = failure {
                return Ok(Some(format!("script execution failed: tx {id} input {vin}: {f}")));
            }
        }
    }
    Ok(None)
}

fn require_sources(txs: &[TxRef], ids: &ById) -> Result<(Option<String>, Vec<SourceTx>)> {
    let mut seen = HashSet::new();
    let mut sources = vec![];
    for tx in txs {
        let id = id8(tx)?;
        for (vin, input) in tx.borrow().inputs.iter().enumerate() {
            let src = source_of(input, ids);
            if out_at(&src, input.source_output_index).is_none() {
                let name = input.source_txid.clone().unwrap_or_else(|| "?".into());
                return Ok((Some(format!("source tx {} of tx {id} input {vin} was not supplied (send the package as BEEF)", first8(&name))), vec![]));
            }
            let src = src.unwrap();
            let sid = id_of(&src)?;
            if let Some(named) = &input.source_txid {
                if *named != sid {
                    return Ok((
                        Some(format!(
                            "attached source {} of tx {id} input {vin} is not the tx its outpoint names ({})",
                            &sid[..8],
                            first8(named)
                        )),
                        vec![],
                    ));
                }
            }
            if !ids.contains_key(&sid) && seen.insert(sid.clone()) {
                let proven = src.borrow().merkle_path.is_some();
                sources.push(SourceTx { txid: sid, proven });
            }
        }
    }
    Ok((None, sources))
}

#[derive(Clone)]
struct Proof {
    proven: bool,
    why: String,
}

fn header_proof(tx: &TxRef, opts: &ScanOpts) -> Result<Proof> {
    let path = match tx.borrow().merkle_path.clone() {
        None => return Ok(Proof { proven: false, why: "it is accepted only with an SPV proof (a merkle path) to a known block header".into() }),
        Some(p) => p,
    };
    let known_fn = match &opts.is_known_block_root {
        None => {
            return Ok(Proof {
                proven: false,
                why: "it carries a merkle path, but no block headers were supplied to check it against (isKnownBlockRoot)".into(),
            })
        }
        Some(f) => f.clone(),
    };
    let height = path.borrow().block_height;
    let root = match path.borrow().compute_root(&id_of(tx)?) {
        Err(e) => return Ok(Proof { proven: false, why: format!("its merkle path does not prove it ({})", err_text(&e)) }),
        Ok(r) => r,
    };
    if known_fn(&root, height).unwrap_or(false) {
        Ok(Proof { proven: true, why: String::new() })
    } else {
        Ok(Proof { proven: false, why: format!("its merkle root is not a known block header at height {height}") })
    }
}

fn value_of(tx: &TxRef, ids: &ById) -> (u64, u64) {
    let b = tx.borrow();
    let i = b.inputs.iter().filter_map(|i| out_at(&source_of(i, ids), i.source_output_index)).map(|o| o.sats()).sum();
    let o = b.outputs.iter().map(|o| o.sats()).sum();
    (i, o)
}

fn anchor_not_minable(tx: &TxRef, t: TokenType, ids: &ById, why: &str) -> Result<Option<String>> {
    let id = id8(tx)?;
    let (i, o) = value_of(tx, ids);
    if o > i {
        return Ok(Some(format!("anchor {id} creates value (inputs {i} sat, outputs {o} sat): the network will never accept it; {why}")));
    }
    let funded = tx.borrow().inputs.iter().any(|x| matches!(classify_in(x, t, ids), Cls::P2pkh | Cls::External));
    if !funded {
        let note = if tx.borrow().merkle_path.is_none() { "it pays no fee, so the network will not mine it on sight; " } else { "" };
        return Ok(Some(format!("unfunded anchor {id}: {note}{why}")));
    }
    Ok(None)
}

fn unauthenticated_reason(tx: &TxRef) -> Result<String> {
    Ok(format!("unauthenticated mint {}: no commit in the event spends it, so nothing shows the sender holds the issuer key", id8(tx)?))
}

fn action_kind(h: &str) -> &'static str {
    match h {
        "23" => "split",
        "25" => "merge",
        _ => "transfer",
    }
}

fn join(c: &[Cls]) -> String {
    c.iter().map(|x| x.s()).collect::<Vec<_>>().join(",")
}

fn check_arrangement(tx: &TxRef, t: TokenType, sh: Shape, ids: &ById, outputs_only: bool) -> Result<Option<String>> {
    let id = id8(tx)?;
    let b = tx.borrow();
    let outs: Vec<Cls> = b.outputs.iter().map(|o| classify_out(o.locking_script.as_ref(), t)).collect();
    let ins: Vec<Cls> = b.inputs.iter().map(|i| classify_in(i, t, ids)).collect();
    if outs.contains(&Cls::Other) {
        return Ok(Some(format!("uninspected output in {id} [{}]", join(&outs))));
    }
    if !outputs_only && ins.contains(&Cls::Other) {
        return Ok(Some(format!("uninspected input in {id} [{}]", join(&ins))));
    }
    for k in 0..sh.token_out {
        if outs.get(k) != Some(&Cls::Token) {
            let got = outs.get(k).map_or("none", |c| c.s());
            return Ok(Some(format!("{} {id}: token output @{k} (got {got}) [{}]", sh.kind, join(&outs))));
        }
    }
    for k in 0..sh.proof_out {
        if outs.get(sh.token_out + k) != Some(&Cls::P2p) {
            return Ok(Some(format!("{} {id}: p2p output @{} [{}]", sh.kind, sh.token_out + k, join(&outs))));
        }
    }
    for (k, c) in outs.iter().enumerate().skip(sh.token_out + sh.proof_out) {
        if *c != Cls::P2pkh {
            return Ok(Some(format!("{} {id}: change p2pkh @{k} (got {}) [{}]", sh.kind, c.s(), join(&outs))));
        }
    }
    if outputs_only {
        return Ok(None);
    }
    for k in 0..sh.token_in {
        if ins.get(k) != Some(&Cls::Token) {
            let got = ins.get(k).map_or("none", |c| c.s());
            return Ok(Some(format!("{} {id}: token input @{k} (got {got}) [{}]", sh.kind, join(&ins))));
        }
    }
    let mut k = sh.token_in;
    if sh.kind == "settle" {
        while k < ins.len() && ins[k] == Cls::P2p {
            k += 1;
        }
    }
    while k < ins.len() {
        if !matches!(ins[k], Cls::External | Cls::P2pkh) {
            return Ok(Some(format!(
                "{} {id}: unexpected input @{k}: {} (a p2Proof input is only valid on a settle, immediately after the token input) [{}]",
                sh.kind,
                ins[k].s(),
                join(&ins)
            )));
        }
        k += 1;
    }
    Ok(None)
}

fn event_type(txs: &[TxRef], ids: &ById, expected: Option<TokenType>) -> Option<TokenType> {
    for tx in txs {
        for o in &tx.borrow().outputs {
            if let Some(t) = recognize_type(o.locking_script.as_ref(), expected) {
                return Some(t);
            }
        }
    }
    for tx in txs {
        for i in &tx.borrow().inputs {
            if let Some(o) = out_at(&source_of(i, ids), i.source_output_index) {
                if let Some(t) = o.locking_script.as_ref().and_then(|l| recognize_type(Some(l), expected)) {
                    return Some(t);
                }
            }
        }
    }
    None
}

fn id_map(txs: &[TxRef]) -> Result<ById> {
    let mut m = HashMap::new();
    for t in txs {
        m.insert(id_of(t)?, t.clone());
    }
    Ok(m)
}

/// `verifyEvent`: verify ONE token event.
pub fn verify_event(event_txs: &[TxInput], opts: &ScanOpts) -> EventResult {
    match verify_one_event(event_txs, opts) {
        Ok(r) => r,
        Err(e) => EventResult::fail(format!("unverifiable input: {}", err_text(&e))),
    }
}

fn verify_one_event(event_txs: &[TxInput], opts: &ScanOpts) -> Result<EventResult> {
    let mut txs = vec![];
    for x in event_txs {
        match to_tx(x) {
            Ok(t) => txs.push(t),
            Err(m) => return Ok(EventResult::fail(m)),
        }
    }
    if txs.is_empty() {
        return Ok(EventResult::fail("empty event"));
    }
    let ids = id_map(&txs)?;
    let t = match event_type(&txs, &ids, opts.expected_type) {
        None => return Ok(EventResult::fail("no BOLT token recognised in event")),
        Some(t) => t,
    };
    if let Some(e) = opts.expected_type {
        if t != e {
            return Ok(EventResult { token_type: Some(t), ..EventResult::fail(format!("expected {}, got {}", e.as_str(), t.as_str())) });
        }
    }
    for tx in &txs {
        let cat = match categorise(tx, t, &ids) {
            None => return Ok(EventResult { token_type: Some(t), ..EventResult::fail(format!("tx {} is not a token tx", id8(tx)?)) }),
            Some(c) => c,
        };
        if let Some(r) = check_arrangement(tx, t, cat.shape, &ids, false)? {
            return Ok(EventResult { token_type: Some(t), kind: Some(cat.shape.kind.into()), ..EventResult::fail(r) });
        }
    }
    if let Some(stray) = unauthenticated_mint(&txs, t, &ids)? {
        return Ok(EventResult {
            token_type: Some(t),
            kind: Some("mint".into()),
            unauthenticated: true,
            ..EventResult::fail(unauthenticated_reason(&stray)?)
        });
    }
    if let (Some(f), _) = require_sources(&txs, &ids)? {
        return Ok(EventResult { token_type: Some(t), ..EventResult::fail(f) });
    }
    let commit_tx = txs.iter().find(|x| categorise(x, t, &ids).is_some_and(|c| c.shape.kind == "commit")).cloned();
    let settle_txs: Vec<TxRef> = txs.iter().filter(|x| categorise(x, t, &ids).is_some_and(|c| c.shape.kind == "settle")).cloned().collect();
    if let Some(c) = &commit_tx {
        if !settle_txs.is_empty() {
            let c_idx = token_out_index(&c.borrow(), t);
            let cid = id_of(c)?;
            let mut linked = false;
            for s in &settle_txs {
                let b = s.borrow();
                let s_idx = token_out_index(&b, t);
                let lock = b.outputs[s_idx as usize].locking_script.clone().unwrap_or_default();
                let (pid, pv) = parse_outpoint(&field(&lock, t, F_PARENT));
                if pid == cid && pv as i64 == c_idx {
                    linked = true;
                }
            }
            if !linked {
                return Ok(EventResult { token_type: Some(t), ..EventResult::fail("settle.parent does not link to the commit token") });
            }
        }
    }
    let inputs: Vec<TxInput> = txs.iter().map(|x| TxInput::Tx(x.clone())).collect();
    let r = scan(&inputs, opts, None);
    if !r.ok {
        return Ok(EventResult {
            ok: false,
            reason: r.reason,
            token_type: Some(t),
            unauthenticated: r.unauthenticated,
            off_chain_only: r.off_chain_only,
            ..Default::default()
        });
    }
    let actions: Vec<&Event> = r.events.as_ref().unwrap().iter().filter(|e| e.kind != "mint").collect();
    if actions.len() != 1 {
        return Ok(EventResult {
            token_type: Some(t),
            ..EventResult::fail(format!("expected exactly one event, got {} (use verifyEvents for a batch)", actions.len()))
        });
    }
    Ok(EventResult {
        ok: true,
        token_type: Some(t),
        kind: Some(actions[0].kind.clone()),
        sources: r.sources,
        anchors: r.anchors,
        off_chain_only: r.off_chain_only,
        ..Default::default()
    })
}

/// `verifyEvents`: verify a BATCH of events end to end (offline).
pub fn verify_events(txs_in: &[TxInput], opts: &ScanOpts) -> ScanResult {
    scan(txs_in, opts, None)
}

/// `verifyAndBroadcast`: verifyEvents, then broadcast every anchor. `tracker` is used when
/// `opts.is_known_block_root` is None.
pub async fn verify_and_broadcast(
    txs_in: &[TxInput],
    broadcaster: Option<&dyn AnchorBroadcaster>,
    opts: &ScanOpts,
    tracker: Option<&dyn HeaderSource>,
) -> ScanResult {
    let broadcaster = match broadcaster {
        None => return ScanResult::fail("an anchor broadcaster is required"),
        Some(b) => b,
    };
    let mut scan_opts = opts.clone();
    if let (None, Some(tracker)) = (&opts.is_known_block_root, tracker) {
        let offered: Rc<std::cell::RefCell<Vec<(String, String, u64)>>> = Default::default();
        let mut pre = opts.clone();
        let o2 = offered.clone();
        pre.is_known_block_root = Some(Rc::new(move |root: &str, height: u64| {
            let k = format!("{height}:{root}");
            let mut v = o2.borrow_mut();
            if !v.iter().any(|(key, _, _)| *key == k) {
                v.push((k, root.to_string(), height));
            }
            Ok(false)
        }));
        scan(txs_in, &pre, None);
        let mut known = HashSet::new();
        let list = offered.borrow().clone();
        for (k, root, height) in list {
            if let Ok(true) = tracker.is_valid_root_for_height(&root, height).await {
                known.insert(k);
            }
        }
        scan_opts.is_known_block_root = Some(Rc::new(move |root: &str, height: u64| Ok(known.contains(&format!("{height}:{root}")))));
    }
    let mut anchor_txs = vec![];
    let result = scan(txs_in, &scan_opts, Some(&mut anchor_txs));
    if !result.ok {
        return result;
    }
    let mut anchors = vec![];
    for (k, tx) in anchor_txs.into_iter().enumerate() {
        let r = result.anchors.as_ref().unwrap()[k].clone();
        let sent = match broadcaster.broadcast(tx).await {
            Ok(s) => s,
            Err(e) => AnchorBroadcastResult { status: Some("rejected".into()), detail: Some(format!("broadcast failed: {}", err_text(&e))) },
        };
        let st = sent.status.clone();
        let known = matches!(st.as_deref(), Some("accepted") | Some("already-seen"));
        let detail = sent.detail.clone().or_else(|| {
            if known || st.as_deref() == Some("rejected") {
                None
            } else {
                Some(format!("unknown broadcast status {}", st.clone().unwrap_or_else(|| "undefined".into())))
            }
        });
        anchors.push(AnchorRef {
            txid: r.txid.clone(),
            kind: r.kind.clone(),
            status: Some(if known { st.clone().unwrap() } else { "rejected".into() }),
            detail: detail.clone(),
        });
        if !known {
            let mut reason = format!("anchor {} {} was not accepted by the network", r.kind, &r.txid[..8]);
            if let Some(d) = detail.filter(|d| !d.is_empty()) {
                reason.push_str(&format!(": {d}"));
            }
            return ScanResult {
                ok: false,
                reason: Some(reason),
                token_type: result.token_type,
                issuer_pub_key_hex: result.issuer_pub_key_hex,
                anchors: Some(anchors),
                ..Default::default()
            };
        }
    }
    ScanResult { anchors: Some(anchors), ..result }
}

fn scan(txs_in: &[TxInput], opts: &ScanOpts, anchor_out: Option<&mut Vec<TxRef>>) -> ScanResult {
    match scan_batch(txs_in, opts, anchor_out) {
        Ok(r) => r,
        Err(e) => ScanResult::fail(format!("unverifiable input: {}", err_text(&e))),
    }
}

struct TokenRef {
    t: TokenType,
    lock: Script,
}

fn scan_batch(txs_in: &[TxInput], opts: &ScanOpts, anchor_out: Option<&mut Vec<TxRef>>) -> Result<ScanResult> {
    let mut txs = vec![];
    for x in txs_in {
        match to_tx(x) {
            Ok(t) => txs.push(t),
            Err(m) => return Ok(ScanResult::fail(m)),
        }
    }
    if txs.is_empty() {
        return Ok(ScanResult::fail("empty batch"));
    }
    let mut ids = id_map(&txs)?;
    let tokens_of = |list: &[TxRef]| -> Vec<TokenRef> {
        let mut found = vec![];
        for tx in list {
            for o in &tx.borrow().outputs {
                if let Some(t) = recognize_type(o.locking_script.as_ref(), opts.expected_type) {
                    found.push(TokenRef { t, lock: o.locking_script.clone().unwrap() });
                }
            }
        }
        found
    };
    let mut tokens = tokens_of(&txs);
    let mut t = tokens.first().map(|x| x.t);
    for tx in &txs {
        if t.is_some() {
            break;
        }
        for i in &tx.borrow().inputs {
            t = i.source_output().and_then(|o| o.locking_script).and_then(|l| recognize_type(Some(&l), opts.expected_type));
            if t.is_some() {
                break;
            }
        }
    }
    let t = match t {
        None => return Ok(ScanResult::fail("no BOLT token output recognised")),
        Some(t) => t,
    };

    // THE ANCHOR STEP.
    let mut promoted: HashSet<String> = HashSet::new();
    let snapshot = txs.clone();
    for tx in &snapshot {
        let kind = categorise(tx, t, &ids).map(|c| c.shape.kind);
        if kind != Some("commit") && kind != Some("melt") {
            continue;
        }
        let inputs = tx.borrow().inputs.clone();
        for i in &inputs {
            let src = match &i.source_transaction {
                Some(s) => s.clone(),
                None => continue,
            };
            if classify_in(i, t, &ids) != Cls::Token {
                continue;
            }
            let sid = id_of(&src)?;
            if ids.contains_key(&sid) {
                continue;
            }
            ids.insert(sid.clone(), src.clone());
            promoted.insert(sid);
            txs.insert(0, src);
        }
    }
    if !promoted.is_empty() {
        tokens = tokens_of(&txs);
    }
    if tokens.iter().any(|x| x.t != t) {
        return Ok(ScanResult::fail("mixed token types in batch"));
    }
    if let Some(e) = opts.expected_type {
        if e != t {
            return Ok(ScanResult::fail(format!("expected {}, got {}", e.as_str(), t.as_str())));
        }
    }
    let mut issuers: Vec<String> = vec![];
    for tk in &tokens {
        let h = hex_encode(&issuer_pub_key_of(&tk.lock, t));
        if !issuers.contains(&h) {
            issuers.push(h);
        }
    }
    if issuers.len() != 1 {
        return Ok(ScanResult::fail("inconsistent issuerPubKey across batch"));
    }
    let issuer = issuers[0].clone();
    if issuer.len() != 66 {
        return Ok(ScanResult { token_type: Some(t), ..ScanResult::fail("issuerPubKey is not a 33-byte compressed public key") });
    }
    let trusted = opt_hex(&opts.trusted_issuer_pub_key);
    if !trusted.is_empty() && trusted != issuer {
        return Ok(ScanResult::fail("issuerPubKey != trusted issuer"));
    }
    let with = |r: ScanResult| ScanResult { token_type: Some(t), ..r };
    let with_issuer = |r: ScanResult| ScanResult { token_type: Some(t), issuer_pub_key_hex: Some(issuer.clone()), ..r };

    let mut cats: Vec<(TxRef, Category)> = vec![];
    for tx in &txs {
        match categorise(tx, t, &ids) {
            None => return Ok(with(ScanResult::fail(format!("tx {} is not a BOLT token tx", id8(tx)?)))),
            Some(c) => cats.push((tx.clone(), c)),
        }
    }
    let commits: Vec<(TxRef, Category)> = cats.iter().filter(|(_, c)| c.shape.kind == "commit").cloned().collect();
    let mut settled = HashSet::new();
    let mut events: Vec<Event> = vec![];
    let mut anchors: Vec<AnchorRef> = vec![];
    let mut anchor_txs: Vec<TxRef> = vec![];
    let spent_as_token = |tt: &TxRef| -> Result<bool> {
        let id = id_of(tt)?;
        for (c, cat) in &cats {
            if cat.shape.kind != "commit" && cat.shape.kind != "melt" {
                continue;
            }
            for i in &c.borrow().inputs {
                let lock = tt.borrow().outputs.get(i.source_output_index as usize).and_then(|o| o.locking_script.clone());
                if spent_txid(i)?.as_deref() == Some(id.as_str()) && lock.is_some_and(|l| recognize_type(Some(&l), Some(t)).is_some()) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    };
    for (tx, cat) in &cats {
        if promoted.contains(&id_of(tx)?) && cat.shape.kind != "settle" && cat.shape.kind != "mint" {
            return Ok(with(ScanResult::fail(format!(
                "anchor {} is not a settled token or a mint (it is a {})",
                id8(tx)?,
                cat.shape.kind
            ))));
        }
    }
    for (s, cat) in &cats {
        if cat.shape.kind != "settle" {
            continue;
        }
        let lock = s.borrow().outputs[cat.token_out_idx as usize].locking_script.clone().unwrap_or_default();
        let (pid, pv) = parse_outpoint(&field(&lock, t, F_PARENT));
        let mut commit = None;
        for (c, cc) in &commits {
            if id_of(c)? == pid && cc.token_out_idx == pv as i64 {
                commit = Some((c.clone(), *cc));
                break;
            }
        }
        let (c, cc) = match commit {
            None => {
                if spent_as_token(s)? {
                    anchors.push(AnchorRef { txid: id_of(s)?, kind: "settle".into(), status: None, detail: None });
                    anchor_txs.push(s.clone());
                    continue;
                }
                return Ok(with(ScanResult::fail(format!("settle {} links to no commit in the batch (orphan settle)", id8(s)?))));
            }
            Some(x) => x,
        };
        settled.insert(format!("{}:{}", id_of(&c)?, cc.token_out_idx));
        let c_lock = c.borrow().outputs[cc.token_out_idx as usize].locking_script.clone().unwrap_or_default();
        events.push(Event {
            kind: action_kind(&hex_encode(&field(&c_lock, t, F_TXO_TYPE))).into(),
            txids: vec![id_of(&c)?, id_of(s)?],
        });
    }
    for (c, cc) in &commits {
        if !settled.contains(&format!("{}:{}", id_of(c)?, cc.token_out_idx)) {
            return Ok(with(ScanResult::fail(format!("commit {} has no settle in the batch (unsettled commit)", id8(c)?))));
        }
    }

    let is_anchor = |tx: &TxRef, list: &[TxRef]| list.iter().any(|a| Rc::ptr_eq(a, tx));
    let mut proofs: HashMap<*const std::cell::RefCell<Transaction>, Proof> = HashMap::new();
    for (tx, cat) in &cats {
        if cat.shape.kind == "mint" || is_anchor(tx, &anchor_txs) {
            proofs.insert(Rc::as_ptr(tx), header_proof(tx, opts)?);
        }
    }
    let header_proven = |tx: &TxRef| proofs.get(&Rc::as_ptr(tx)).is_some_and(|p| p.proven);
    let to_execute: Vec<TxRef> = txs.iter().filter(|x| !header_proven(x)).cloned().collect();

    for (tx, cat) in &cats {
        if let Some(r) = check_arrangement(tx, t, cat.shape, &ids, header_proven(tx))? {
            return Ok(with(ScanResult::fail(r)));
        }
    }
    if let Some(stray) = unauthenticated_mint(&txs, t, &ids)? {
        return Ok(ScanResult { unauthenticated: true, ..with_issuer(ScanResult::fail(unauthenticated_reason(&stray)?)) });
    }
    let (failure, sources) = require_sources(&to_execute, &ids)?;
    if let Some(f) = failure {
        return Ok(with_issuer(ScanResult::fail(f)));
    }
    for (tx, cat) in &cats {
        if cat.shape.kind == "mint" {
            anchors.push(AnchorRef { txid: id_of(tx)?, kind: "mint".into(), status: None, detail: None });
            anchor_txs.push(tx.clone());
        }
        if (cat.shape.kind == "mint" || cat.shape.kind == "melt") && !promoted.contains(&id_of(tx)?) {
            events.push(Event { kind: cat.shape.kind.into(), txids: vec![id_of(tx)?] });
        }
    }
    if let Some(f) = execute_inputs(&to_execute, &ids)? {
        return Ok(with_issuer(ScanResult::fail(f)));
    }
    for a in &anchor_txs {
        if header_proven(a) {
            continue;
        }
        let why = proofs.get(&Rc::as_ptr(a)).map(|p| p.why.clone()).unwrap_or_default();
        if let Some(r) = anchor_not_minable(a, t, &ids, &why)? {
            return Ok(with_issuer(ScanResult::fail(r)));
        }
    }
    let mut off = vec![];
    for tx in &to_execute {
        if is_anchor(tx, &anchor_txs) {
            continue;
        }
        let (i, o) = value_of(tx, &ids);
        if o > i {
            off.push(OffChainOnlyTx { txid: id_of(tx)?, input_sats: i, output_sats: o });
        }
    }
    if opts.require_broadcastable && !off.is_empty() {
        let o = off[0].clone();
        return Ok(ScanResult {
            off_chain_only: Some(off),
            ..with_issuer(ScanResult::fail(format!(
                "tx {} creates value (inputs {} sat, outputs {} sat): it cannot be broadcast as built",
                &o.txid[..8],
                o.input_sats,
                o.output_sats
            )))
        });
    }
    if let Some(out) = anchor_out {
        out.extend(anchor_txs.iter().cloned());
    }
    Ok(ScanResult {
        ok: true,
        token_type: Some(t),
        issuer_pub_key_hex: Some(issuer),
        events: Some(events),
        sources: Some(sources),
        anchors: Some(anchors),
        off_chain_only: if off.is_empty() { None } else { Some(off) },
        ..Default::default()
    })
}

#[allow(dead_code)]
fn _unused() -> Result<()> {
    let _ = (F_PUB_KEY_HASH, F_COMMITMENT, F_GRANDPARENT);
    err("unused")
}
