//! Phase 1 vectors: static data, verifyTx, BEEF, p2pkh / p2Proof signing.
mod common;

use b017::beef::{from_beef, to_atomic_beef, Bin};
use b017::boltlib::P2PKHUnlock;
use b017::fingerprints::{registry, TokenType};
use b017::pay2proof::{pay2proof_lock, Pay2ProofUnlock};
use b017::script::{hex_decode, hex_encode, Script};
use b017::sighash::block_on;
use b017::spend::verify_tx;
use common::*;
use serde_json::Value;

#[test]
fn static_suffixes_match_registry() {
    let s: Value = serde_json::from_str(&std::fs::read_to_string(vectors_dir().join("static.json")).unwrap()).unwrap();
    for (name, spec) in s["registry"].as_object().unwrap() {
        let t = TokenType::parse(name).unwrap();
        assert_eq!(registry(t).suffix_hash_hex, spec["suffixHashHex"].as_str().unwrap(), "{name}");
    }
    assert_eq!(pay2proof_lock(&[0u8; 20]).to_hex(), s["p2pZeroLockHex"].as_str().unwrap());
}

#[test]
fn vectors_verify_tx() {
    let mut fails = vec![];
    for (i, rec) in calls("verifyTx").iter().enumerate() {
        let mut g = Graph::default();
        let tx = g.tx(rec["tx"].as_str().unwrap());
        let skip = rec["skipOutputCheck"].as_bool().unwrap_or(false);
        let res = verify_tx(&mut tx.borrow_mut(), skip);
        if let Some(want) = rec.get("throws") {
            let want = want.as_str().unwrap();
            match res {
                Ok(r) => fails.push(format!("{}: TS threw {want:?}, Rust returned {r:?}", label(rec, i))),
                Err(e) if is_b017_error(want) && e.0 != want => fails.push(format!("{}: error {:?}, want {want:?}", label(rec, i), e.0)),
                _ => {}
            }
            continue;
        }
        match res {
            Err(e) => fails.push(format!("{}: Rust error {}, TS returned {}", label(rec, i), e, rec["result"])),
            Ok(r) if r.valid != rec["result"]["valid"].as_bool().unwrap() => fails.push(format!("{}: valid differs", label(rec, i))),
            _ => {}
        }
    }
    assert!(fails.is_empty(), "{} failures:\n{}", fails.len(), fails.join("\n"));
}

#[test]
fn vectors_beef() {
    let mut fails = vec![];
    for (i, rec) in calls("toAtomicBeef").iter().enumerate() {
        let mut g = Graph::default();
        let tx = g.tx(rec["tx"].as_str().unwrap());
        let res = to_atomic_beef(&tx);
        match (rec.get("throws"), res) {
            (Some(_), Ok(_)) => fails.push(format!("{}: TS threw, Rust succeeded", label(rec, i))),
            (Some(_), Err(_)) => {}
            (None, Err(e)) => fails.push(format!("{}: {e}", label(rec, i))),
            (None, Ok(b)) => {
                if hex_encode(&b) != rec["result"].as_str().unwrap() {
                    fails.push(format!("{}: atomic BEEF differs", label(rec, i)))
                }
            }
        }
    }
    for (i, rec) in calls("fromBeef").iter().enumerate() {
        let input = &rec["input"];
        let owned;
        let bin = match input["t"].as_str().unwrap() {
            "str" => Bin::Hex(input["v"].as_str().unwrap()),
            _ => {
                owned = hex_decode(input["hex"].as_str().unwrap()).unwrap();
                Bin::Bytes(&owned)
            }
        };
        let res = from_beef(&bin);
        match (rec.get("throws"), res) {
            (Some(w), Ok(_)) => fails.push(format!("{}: TS threw {w}, Rust succeeded", label(rec, i))),
            (Some(w), Err(e)) => {
                let w = w.as_str().unwrap();
                if is_b017_error(w) && e.0 != w {
                    fails.push(format!("{}: error {:?}, want {w:?}", label(rec, i), e.0))
                }
            }
            (None, Err(e)) => fails.push(format!("{}: {e}", label(rec, i))),
            (None, Ok(t)) => {
                if node_id(&t, &mut Default::default()) != rec["result"].as_str().unwrap() {
                    fails.push(format!("{}: parsed graph differs", label(rec, i)))
                }
            }
        }
    }
    assert!(fails.is_empty(), "{} failures:\n{}", fails.len(), fails.join("\n"));
}

#[test]
fn vectors_sign_p2pkh_and_pay2proof() {
    let mut fails = replay_sign("sign.p2pkhUnlock", &|_, _, args| Ok(std::rc::Rc::new(P2PKHUnlock(arg_at(args, 0).signer()))));
    fails.extend(replay_sign("sign.Pay2Proof", &|_, _, args| {
        let sats = arg_at(args, 1).number().unwrap_or(0);
        let lock = if arg_at(args, 2).t() == "script" { Some(Script::from_hex(args[2]["hex"].as_str().unwrap()).unwrap()) } else { None };
        Ok(std::rc::Rc::new(Pay2ProofUnlock::new(arg_at(args, 0).signer(), sats, lock)))
    }));
    assert!(fails.is_empty(), "{} failures:\n{}", fails.len(), fails.join("\n"));
}

#[test]
fn vectors_lock_pay2proof() {
    for (i, rec) in calls("lock.Pay2Proof").iter().enumerate() {
        let args = rec["args"].as_array().unwrap();
        assert_eq!(pay2proof_lock(&arg_at(args, 0).bytes().unwrap()).to_hex(), rec["result"].as_str().unwrap(), "{}", label(rec, i));
    }
}
