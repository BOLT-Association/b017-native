//! Phase 3 vectors: every recorded verifyEvents / verifyEvent / verifyAndBroadcast call, field for field.
mod common;

use std::cell::RefCell;
use std::rc::Rc;

use b017::fingerprints::TokenType;
use b017::script::hex_decode;
use b017::sighash::{block_on, BoxFuture};
use b017::tx::TxRef;
use b017::verifyevents::*;
use common::*;
use serde_json::Value;

/// The b017 prefix of a reason whose tail is an SDK's own text, or None when the reason is all b017's.
fn sdk_prefix(reason: &str) -> Option<String> {
    let own_tails = ["no unlocking script", "the script evaluated false", "its source tx was not supplied", "BEEF "];
    let split = |prefix_end: usize| -> Option<String> {
        let tail = &reason[prefix_end..];
        if own_tails.iter().any(|t| tail.starts_with(t)) {
            None
        } else {
            Some(reason[..prefix_end].to_string())
        }
    };
    if reason.starts_with("script execution failed: tx ") {
        let rest = &reason["script execution failed: tx ".len()..];
        if let Some(p) = rest.find(": ") {
            return split("script execution failed: tx ".len() + p + 2);
        }
    }
    for p in ["unverifiable input: ", "malformed transaction hex: ", "invalid BEEF: "] {
        if reason.starts_with(p) {
            return split(p.len());
        }
    }
    if let Some(i) = reason.find("its merkle path does not prove it (") {
        return split(i + "its merkle path does not prove it (".len());
    }
    None
}

fn reasons_match(got: &str, want: &str) -> bool {
    if got == want {
        return true;
    }
    match sdk_prefix(want) {
        Some(p) => got.starts_with(&p) && sdk_prefix(got).as_deref() == Some(p.as_str()),
        None => false,
    }
}

fn compare(got: &str, want: &Value) -> Option<String> {
    let mut g: Value = serde_json::from_str(got).unwrap();
    let mut w = want.clone();
    let gr = g["reason"].as_str().unwrap_or("").to_string();
    let wr = w["reason"].as_str().unwrap_or("").to_string();
    if !reasons_match(&gr, &wr) {
        return Some(format!("reason\n got {gr:?}\nwant {wr:?}"));
    }
    g.as_object_mut().unwrap().remove("reason");
    w.as_object_mut().unwrap().remove("reason");
    if g != w {
        return Some(format!("result\n got {g}\nwant {w}"));
    }
    None
}

struct Replay {
    rec: Value,
    errors: RefCell<Vec<String>>,
    bcast: RefCell<usize>,
    graph: RefCell<Graph>,
}

impl Replay {
    fn answer(&self, cb: &str, root: &str, height: u64) -> b017::Result<bool> {
        for c in self.rec["calls"].as_array().unwrap() {
            if c["cb"] == cb && c["root"] == root && c["height"].as_u64() == Some(height) {
                if c.get("throws").is_some() {
                    return Err("threw".into());
                }
                return Ok(c["ans"].as_bool() == Some(true) && c["ans"] == Value::Bool(true));
            }
        }
        self.errors.borrow_mut().push(format!("Rust asked {cb}({root}, {height}), which the reference never asked"));
        Ok(false)
    }

    fn opts(self: &Rc<Self>) -> ScanOpts {
        let mut o = ScanOpts::default();
        let raw = &self.rec["opts"];
        if raw.get("t").is_some() || !raw.is_object() {
            return o;
        }
        if let Some(s) = raw["expectedType"].as_str() {
            o.expected_type = TokenType::parse(s);
        }
        o.require_broadcastable = raw["requireBroadcastable"].as_bool().unwrap_or(false);
        if raw.get("trustedIssuerPubKey").is_some() {
            let a = &raw["trustedIssuerPubKey"];
            o.trusted_issuer_pub_key = match a["t"].as_str() {
                Some("str") => Some(TrustedKey::Hex(a["v"].as_str().unwrap().to_string())),
                Some("bytes") | Some("u8") => Some(TrustedKey::Bytes(hex_decode(a["hex"].as_str().unwrap()).unwrap())),
                _ => None,
            };
        }
        if raw["isKnownBlockRoot"] == "fn" {
            let me = self.clone();
            o.is_known_block_root = Some(Rc::new(move |root: &str, height: u64| me.answer("isKnownBlockRoot", root, height)));
        }
        o
    }

    fn batch(&self) -> Vec<TxInput> {
        self.rec["batch"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|it| match it["t"].as_str().unwrap() {
                "tx" => TxInput::Tx(self.graph.borrow_mut().tx(it["id"].as_str().unwrap())),
                "str" => TxInput::Hex(it["v"].as_str().unwrap().to_string()),
                "u8" | "bytes" => TxInput::Bytes(hex_decode(it["hex"].as_str().unwrap()).unwrap()),
                _ => TxInput::Other,
            })
            .collect()
    }
}

struct Tracker(Rc<Replay>);
impl HeaderSource for Tracker {
    fn is_valid_root_for_height<'a>(&'a self, root: &'a str, height: u64) -> BoxFuture<'a, b017::Result<bool>> {
        Box::pin(async move { self.0.answer("chainTracker", root, height) })
    }
}

struct Broadcaster(Rc<Replay>);
impl AnchorBroadcaster for Broadcaster {
    fn broadcast<'a>(&'a self, anchor: TxRef) -> BoxFuture<'a, b017::Result<AnchorBroadcastResult>> {
        Box::pin(async move {
            let r = &self.0;
            let calls: Vec<&Value> = r.rec["calls"].as_array().unwrap().iter().filter(|c| c["cb"] == "broadcast").collect();
            let k = *r.bcast.borrow();
            *r.bcast.borrow_mut() += 1;
            let c = match calls.get(k) {
                None => {
                    r.errors.borrow_mut().push("Rust broadcast more anchors than the reference".into());
                    return Ok(AnchorBroadcastResult { status: Some("rejected".into()), detail: None });
                }
                Some(c) => *c,
            };
            let got = node_id(&anchor, &mut Default::default());
            if c["tx"].as_str() != Some(got.as_str()) {
                r.errors.borrow_mut().push(format!("broadcast anchor {got}, reference broadcast {}", c["tx"]));
            }
            if let Some(t) = c.get("throws") {
                return Err(t.as_str().unwrap_or("").into());
            }
            let ans = &c["ans"];
            if !ans.is_object() || ans.get("t").is_some() {
                return Ok(AnchorBroadcastResult::default());
            }
            Ok(AnchorBroadcastResult {
                status: ans.get("status").map(|s| s.as_str().map(|x| x.to_string()).unwrap_or_else(|| s.to_string())),
                detail: ans["detail"].as_str().map(|s| s.to_string()),
            })
        })
    }
}

fn run(name: &str, f: &dyn Fn(&Rc<Replay>) -> String) {
    let mut fails = vec![];
    let mut skipped = 0;
    let recs = calls(name);
    for (i, rec) in recs.iter().enumerate() {
        if rec.get("unserializable").is_some() || rec["batch"]["t"] != "array" {
            skipped += 1;
            continue;
        }
        let r = Rc::new(Replay { rec: rec.clone(), errors: Default::default(), bcast: RefCell::new(0), graph: Default::default() });
        let got = f(&r);
        if let Some(m) = compare(&got, &rec["result"]) {
            fails.push(format!("{}: {m}", label(rec, i)));
        }
        for e in r.errors.borrow().iter() {
            fails.push(format!("{}: {e}", label(rec, i)));
        }
    }
    eprintln!("{name}: {} records, {skipped} not representable (non-array batch)", recs.len());
    assert!(fails.is_empty(), "{} failures:\n{}", fails.len(), fails.join("\n"));
}

#[test]
fn vectors_verify_events() {
    run("verifyEvents", &|r| verify_events(&r.batch(), &r.opts()).to_json().to_string());
}

#[test]
fn vectors_verify_event() {
    run("verifyEvent", &|r| verify_event(&r.batch(), &r.opts()).to_json().to_string());
}

#[test]
fn vectors_verify_and_broadcast() {
    run("verifyAndBroadcast", &|r| {
        let b = Broadcaster(r.clone());
        let tr = Tracker(r.clone());
        let has_bc = r.rec["broadcaster"] == "fn";
        let has_tr = r.rec["opts"]["chainTracker"] == "fn";
        block_on(verify_and_broadcast(
            &r.batch(),
            if has_bc { Some(&b) } else { None },
            &r.opts(),
            if has_tr { Some(&tr) } else { None },
        ))
        .to_json()
        .to_string()
    });
}
