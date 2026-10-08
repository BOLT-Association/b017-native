//! Interpreter differential (vectors/interp.json): random script pairs through the reference's Spend; the crate's
//! Spend wrapper must reach the same verdict on each.
mod common;

use std::collections::BTreeMap;

use b017::script::Script;
use b017::spend::{validate, SpendParams};
use common::*;
use serde_json::Value;

#[test]
fn vectors_interpreter() {
    let path = std::env::var("B017_INTERP_FILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| vectors_dir().join("interp.json"));
    let cases: Vec<Value> = match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap(),
        Err(_) => return,
    };
    let mut diff: BTreeMap<String, usize> = BTreeMap::new();
    let mut first = vec![];
    let txid = "ab".repeat(32);
    for (i, c) in cases.iter().enumerate() {
        if std::env::var("B017_INTERP_TRACE").is_ok() {
            eprintln!("case {i} v{} u={} l={}", c["v"], c["u"], c["l"]);
        }
        let lock = Script::from_hex(c["l"].as_str().unwrap()).unwrap();
        let unlock = Script::from_hex(c["u"].as_str().unwrap()).unwrap();
        let r = validate(&SpendParams {
            source_txid: &txid,
            source_output_index: 0,
            locking_script: &lock,
            source_satoshis: 1000,
            transaction_version: c["v"].as_u64().unwrap() as u32,
            other_inputs: vec![],
            unlocking_script: &unlock,
            input_sequence: 0xffff_ffff,
            input_index: 0,
            outputs: &[],
            lock_time: 0,
        });
        let want = c["ok"].as_bool().unwrap();
        if r.is_ok() != want {
            let key = if want {
                format!("reference valid; port: {}", r.unwrap_err())
            } else {
                c["err"].as_str().unwrap().to_string()
            };
            *diff.entry(key.clone()).or_default() += 1;
            if first.len() < 15 {
                first.push(format!(
                    "#{i} v{} u={} l={} | {key}",
                    c["v"], c["u"], c["l"]
                ));
            }
        }
    }
    eprintln!("interpreter: {} cases", cases.len());
    let lines: Vec<String> = diff.iter().map(|(k, n)| format!("{n:5}  {k}")).collect();
    assert!(
        diff.is_empty(),
        "{} kinds of disagreement:\n{}\n{}",
        diff.len(),
        lines.join("\n"),
        first.join("\n")
    );
}
