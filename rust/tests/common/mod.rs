//! Shared harness: load the recorded vectors (../vectors) into the crate's model.
#![allow(dead_code)]

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::OnceLock;

use b017::merklepath::MerklePath;
use b017::script::{hex_decode, Script};
use b017::sighash::block_on;
use b017::sighash::{KeySigner, Signer};
use b017::tx::{tx_ref, Input, Output, Transaction, TxRef};
use serde_json::Value;

pub fn vectors_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("vectors")
}

pub fn nodes() -> &'static serde_json::Map<String, Value> {
    static N: OnceLock<serde_json::Map<String, Value>> = OnceLock::new();
    N.get_or_init(|| {
        let s = std::fs::read_to_string(vectors_dir().join("nodes.json")).unwrap();
        serde_json::from_str(&s).unwrap()
    })
}

pub fn calls(name: &str) -> Vec<Value> {
    let s =
        std::fs::read_to_string(vectors_dir().join("calls").join(format!("{name}.json"))).unwrap();
    serde_json::from_str(&s).unwrap()
}

pub fn label(rec: &Value, i: usize) -> String {
    format!(
        "#{i} {} :: {}",
        rec["file"].as_str().unwrap_or(""),
        rec["test"].as_str().unwrap_or("")
    )
}

/// Rebuilds tx nodes; one shared object per node id within a record, as the reference had.
#[derive(Default)]
pub struct Graph {
    memo: HashMap<String, TxRef>,
    pub extra: Option<std::rc::Rc<serde_json::Map<String, Value>>>,
}

impl Graph {
    pub fn tx(&mut self, id: &str) -> TxRef {
        if let Some(t) = self.memo.get(id) {
            return t.clone();
        }
        let extra = self.extra.clone();
        let n = nodes()
            .get(id)
            .or_else(|| extra.as_ref().and_then(|e| e.get(id)))
            .unwrap_or_else(|| panic!("unknown node {id}"))
            .clone();
        let t = tx_ref(Transaction::default());
        self.memo.insert(id.to_string(), t.clone());
        let mut tx = Transaction {
            version: n["v"].as_u64().unwrap_or(0) as u32,
            lock_time: n["lt"].as_u64().unwrap_or(0) as u32,
            ..Default::default()
        };
        for i in n["ins"].as_array().unwrap() {
            tx.inputs.push(Input {
                source_txid: i["txid"].as_str().map(|s| s.to_string()),
                source_output_index: i["vout"].as_u64().unwrap_or(0) as u32,
                sequence: i["seq"].as_u64().map(|v| v as u32),
                unlocking_script: i["us"].as_str().map(|h| Script::from_hex(h).unwrap()),
                source_transaction: i["src"].as_str().map(|s| self.tx(s)),
                template: None,
            });
        }
        for o in n["outs"].as_array().unwrap() {
            tx.outputs.push(Output {
                satoshis: o["sat"].as_u64(),
                locking_script: o["ls"].as_str().map(|h| Script::from_hex(h).unwrap()),
                change: false,
            });
        }
        if let Some(mp) = n["mp"].as_str() {
            tx.merkle_path = Some(Rc::new(std::cell::RefCell::new(
                MerklePath::from_hex(mp).unwrap(),
            )));
        }
        *t.borrow_mut() = tx;
        t
    }
}

fn js_str(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

/// The content address the recorder gives a tx graph (vectors/gen/ser.ts).
pub fn node_id(
    t: &TxRef,
    memo: &mut HashMap<*const std::cell::RefCell<Transaction>, String>,
) -> String {
    if let Some(id) = memo.get(&Rc::as_ptr(t)) {
        return id.clone();
    }
    memo.insert(Rc::as_ptr(t), "cycle".into());
    let tx = t.borrow();
    let mut s = format!(r#"{{"v":{},"lt":{},"ins":["#, tx.version, tx.lock_time);
    for (k, i) in tx.inputs.iter().enumerate() {
        if k > 0 {
            s.push(',');
        }
        let txid = i
            .source_txid
            .as_deref()
            .map(js_str)
            .unwrap_or("null".into());
        let seq = i.sequence.map(|v| v.to_string()).unwrap_or("null".into());
        let us = i
            .unlocking_script
            .as_ref()
            .map(|u| js_str(&u.to_hex()))
            .unwrap_or("null".into());
        let src = i
            .source_transaction
            .as_ref()
            .map(|x| js_str(&node_id(x, memo)))
            .unwrap_or("null".into());
        s.push_str(&format!(
            r#"{{"txid":{txid},"vout":{},"seq":{seq},"us":{us},"src":{src}}}"#,
            i.source_output_index
        ));
    }
    s.push_str(r#"],"outs":["#);
    for (k, o) in tx.outputs.iter().enumerate() {
        if k > 0 {
            s.push(',');
        }
        let sat = o.satoshis.map(|v| v.to_string()).unwrap_or("null".into());
        let ls = o
            .locking_script
            .as_ref()
            .map(|l| js_str(&l.to_hex()))
            .unwrap_or("null".into());
        s.push_str(&format!(r#"{{"sat":{sat},"ls":{ls}}}"#));
    }
    let mp = tx
        .merkle_path
        .as_ref()
        .map(|m| js_str(&m.borrow().to_hex()))
        .unwrap_or("null".into());
    s.push_str(&format!(r#"],"mp":{mp}}}"#));
    let h = b017::script::hex_encode(&b017::sighash::sha256(s.as_bytes()));
    let id = h[..32].to_string();
    memo.insert(Rc::as_ptr(t), id.clone());
    id
}

/// A recorded argument (vectors/gen/ser.ts Graph.input).
pub struct Arg<'a>(pub &'a Value);

impl<'a> Arg<'a> {
    pub fn t(&self) -> &str {
        self.0["t"].as_str().unwrap_or("undefined")
    }
    pub fn bytes(&self) -> Option<Vec<u8>> {
        match self.t() {
            "undefined" => None,
            "bytes" | "u8" => Some(hex_decode(self.0["hex"].as_str().unwrap()).unwrap()),
            other => panic!("arg {other} is not bytes"),
        }
    }
    pub fn signer(&self) -> Rc<dyn Signer> {
        let key = match self.t() {
            "key" => self.0["hex"].as_str().unwrap().to_string(),
            "signer" => self.0["key"]
                .as_str()
                .expect("signer without a recorded key")
                .to_string(),
            other => panic!("arg {other} is not a key"),
        };
        Rc::new(KeySigner::from_hex(&key).unwrap())
    }
    pub fn boolean(&self) -> bool {
        self.0["v"].as_bool().unwrap_or(false)
    }
    pub fn number(&self) -> Option<u64> {
        if self.t() == "json" {
            self.0["v"].as_u64()
        } else {
            None
        }
    }
    pub fn tx_list(&self, g: &mut Graph) -> Vec<TxRef> {
        match self.t() {
            "undefined" => vec![],
            "bytes" => vec![],
            "list" => self.0["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|it| g.tx(it["id"].as_str().unwrap()))
                .collect(),
            other => panic!("prevTxs kind {other}"),
        }
    }
    pub fn tx_or_none(&self, g: &mut Graph) -> Option<TxRef> {
        if self.t() == "tx" {
            Some(g.tx(self.0["id"].as_str().unwrap()))
        } else {
            None
        }
    }
}

pub fn arg_at(args: &[Value], i: usize) -> Arg<'_> {
    static UNDEF: OnceLock<Value> = OnceLock::new();
    Arg(args
        .get(i)
        .unwrap_or_else(|| UNDEF.get_or_init(|| serde_json::json!({"t": "undefined"}))))
}

/// Whether a thrown message is b017's own text (exact comparison) rather than an SDK's.
pub fn is_b017_error(msg: &str) -> bool {
    [
        "Verification failed:",
        "Every output must have",
        "Output total greater",
        "BEEF ",
        "p2pkhUnlock requires",
        "The input sourceTXID",
        "The sourceSatoshis",
        "The lockingScript",
        "input sourceTXID or",
        "sourceSatoshis or",
        "lockingScript or",
        "authOrMiscData is",
        "an unfunded spend",
        "Mint tx not valid",
    ]
    .iter()
    .any(|p| msg.starts_with(p))
}

/// Replay every recorded sign() of `name` with the template `build` makes from the recorded arguments.
/// Builds the template a recorded sign() call used.
pub type SignBuilder<'a> =
    &'a dyn Fn(
        &mut Graph,
        &str,
        &[serde_json::Value],
    ) -> b017::Result<std::rc::Rc<dyn b017::boltlib::UnlockTemplate>>;

pub fn replay_sign(name: &str, build: SignBuilder) -> Vec<String> {
    let mut fails = vec![];
    for (i, rec) in calls(name).iter().enumerate() {
        let mut g = Graph::default();
        let args = rec["args"].as_array().cloned().unwrap_or_default();
        let tx = g.tx(rec["tx"].as_str().unwrap());
        let idx = rec["inputIndex"].as_u64().unwrap() as usize;
        let res =
            build(&mut g, rec["method"].as_str().unwrap_or("unlock"), &args).and_then(|tpl| {
                let t = tx.borrow();
                block_on(tpl.sign(&t, idx))
            });
        match (rec.get("throws"), res) {
            (Some(w), Ok(_)) => {
                fails.push(format!("{}: TS threw {w}, Rust succeeded", label(rec, i)))
            }
            (Some(w), Err(e)) => {
                let w = w.as_str().unwrap();
                if is_b017_error(w) && e.0 != w {
                    fails.push(format!("{}: error {:?}, want {w:?}", label(rec, i), e.0))
                }
            }
            (None, Err(e)) => fails.push(format!("{}: Rust error {e}", label(rec, i))),
            (None, Ok(us)) => {
                if us.to_hex() != rec["result"].as_str().unwrap() {
                    fails.push(format!("{}: unlocking script differs", label(rec, i)))
                }
            }
        }
    }
    fails
}
