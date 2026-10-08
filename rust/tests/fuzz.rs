//! The differential corpus (vectors/fuzz.json): batches the reference accepted, each with one seeded mutation,
//! and the reference's verdict on it.
mod common;

use std::rc::Rc;

use b017::fingerprints::TokenType;
use b017::script::hex_decode;
use b017::verifyevents::*;
use common::*;
use serde_json::Value;

#[path = "scanner_compare.rs"]
mod scanner_compare;

#[test]
fn vectors_fuzz() {
    let path = std::env::var("B017_FUZZ_FILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| vectors_dir().join("fuzz.json"));
    let corpus: Value = match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap(),
        Err(_) => return,
    };
    let extra = Rc::new(corpus["nodes"].as_object().unwrap().clone());
    let mut fails = vec![];
    let (mut agree, mut refused) = (0, 0);
    let cases = corpus["cases"].as_array().unwrap();
    for (i, c) in cases.iter().enumerate() {
        let mut g = Graph::default();
        g.extra = Some(extra.clone());
        let mut o = ScanOpts::default();
        let raw = &c["opts"];
        if raw.is_object() && raw.get("t").is_none() {
            o.expected_type = raw["expectedType"].as_str().and_then(TokenType::parse);
            o.require_broadcastable = raw["requireBroadcastable"].as_bool().unwrap_or(false);
            let a = &raw["trustedIssuerPubKey"];
            o.trusted_issuer_pub_key = match a["t"].as_str() {
                Some("str") => Some(TrustedKey::Hex(a["v"].as_str().unwrap().into())),
                Some("bytes") => Some(TrustedKey::Bytes(
                    hex_decode(a["hex"].as_str().unwrap()).unwrap(),
                )),
                _ => None,
            };
            if raw["isKnownBlockRoot"] == "fn" {
                let known: Vec<String> = c["known"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|k| k.as_str().unwrap().to_string())
                    .collect();
                o.is_known_block_root = Some(Rc::new(move |root: &str, h: u64| {
                    Ok(known.contains(&format!("{h}:{root}")))
                }));
            }
        }
        let batch: Vec<TxInput> = c["batch"]
            .as_array()
            .unwrap()
            .iter()
            .map(|it| TxInput::Tx(g.tx(it["id"].as_str().unwrap())))
            .collect();
        let got = if c["kind"] == "verifyEvents" {
            verify_events(&batch, &o).to_json()
        } else {
            verify_event(&batch, &o).to_json()
        };
        match scanner_compare::compare(&got.to_string(), &c["result"]) {
            Some(m) => fails.push(format!(
                "case {i} ({}; {} on {}): {m}",
                c["kind"], c["mutation"], c["base"]
            )),
            None => {
                agree += 1;
                if c["result"]["ok"] != true {
                    refused += 1;
                }
            }
        }
    }
    eprintln!(
        "fuzz: {agree}/{} cases agree with the reference ({refused} refused by both)",
        cases.len()
    );
    assert!(
        fails.is_empty(),
        "{} failures:\n{}",
        fails.len(),
        fails.join("\n")
    );
}
