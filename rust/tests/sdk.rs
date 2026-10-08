//! The @bsv/sdk parts the crate re-implements, against vectors/sdk.json.
mod common;

use b017::beef::{from_beef, to_atomic_beef, Bin};
use b017::beefsdk::Beef;
use b017::merklepath::MerklePath;
use b017::script::{hex_decode, hex_encode, Chunk, Script};
use b017::sighash::{format_preimage, refs_of, PreimageParams};
use b017::tx::{tx_ref, Transaction};
use common::*;
use serde_json::Value;

fn sdk() -> Value {
    serde_json::from_str(&std::fs::read_to_string(vectors_dir().join("sdk.json")).unwrap()).unwrap()
}

/// Compare a port result with a recorded `{ok}` / `{throws}`.
fn expect(fails: &mut Vec<String>, what: &str, want: &Value, got: b017::Result<String>) {
    if want.is_null() {
        return;
    }
    match (want.get("throws"), got) {
        (Some(w), Ok(v)) => fails.push(format!("{what}: reference threw {w}, port returned {v}")),
        (Some(_), Err(_)) => {}
        (None, Err(e)) => fails.push(format!("{what}: port error {e}, reference {}", want["ok"])),
        (None, Ok(v)) => {
            if Some(v.as_str()) != want["ok"].as_str() {
                fails.push(format!("{what}: {v}, reference {}", want["ok"]))
            }
        }
    }
}

#[test]
fn sdk_merkle_path() {
    let mut fails = vec![];
    for (i, c) in sdk()["merkle"].as_array().unwrap().iter().enumerate() {
        let h = c["hex"].as_str().unwrap();
        let mp = MerklePath::from_hex(h).unwrap();
        if mp.to_hex() != h {
            fails.push(format!("#{i}: round trip"));
        }
        for (k, txid) in c["txids"].as_array().unwrap().iter().enumerate() {
            expect(&mut fails, &format!("#{i} root"), &c["roots"][k], mp.compute_root(txid.as_str().unwrap()));
        }
        expect(&mut fails, &format!("#{i} root()"), &c["rootNoArg"], mp.compute_root(""));
        if let Some(w) = c["combineWith"].as_str() {
            let mut a = MerklePath::from_hex(h).unwrap();
            let b = MerklePath::from_hex(w).unwrap();
            let r = a.combine(&b).map(|_| a.to_hex());
            expect(&mut fails, &format!("#{i} combine"), &c["combined"], r);
        }
        let mut w = MerklePath::from_hex(h).unwrap();
        let r = w.trim().map(|_| w.to_hex());
        expect(&mut fails, &format!("#{i} trim"), &c["trimmed"], r);
        let bad = hex_decode(c["corrupt"].as_str().unwrap()).unwrap();
        expect(&mut fails, &format!("#{i} corrupt legal"), &c["corruptLegal"], MerklePath::from_binary(&bad, true).map(|m| m.to_hex()));
        expect(&mut fails, &format!("#{i} corrupt loose"), &c["corruptLoose"], MerklePath::from_binary(&bad, false).map(|m| m.to_hex()));
    }
    assert!(fails.is_empty(), "{} failures:\n{}", fails.len(), fails.join("\n"));
}

#[test]
fn sdk_scripts() {
    let s = sdk();
    let mut fails = vec![];
    for (i, c) in s["scripts"].as_array().unwrap().iter().enumerate() {
        let h = c["hex"].as_str().unwrap();
        let sc = Script::from_hex(h).unwrap();
        let want: Vec<Chunk> = c["chunks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| Chunk { op: x["op"].as_u64().unwrap() as u8, data: x["data"].as_str().map(|d| hex_decode(d).unwrap()) })
            .collect();
        if sc.chunks() != want.as_slice() {
            fails.push(format!("#{i} {h}: chunks differ"));
        }
        if sc.to_hex() != h {
            fails.push(format!("#{i}: toHex is not the parsed bytes"));
        }
        if Script::new(sc.chunks().to_vec()).to_hex() != c["rewritten"].as_str().unwrap() {
            fails.push(format!("#{i} {h}: re-serialised differently"));
        }
    }
    for e in s["scriptHexErrors"].as_array().unwrap() {
        if let Some(w) = e["result"]["throws"].as_str() {
            match Script::from_hex(e["hex"].as_str().unwrap()) {
                Err(err) if err.0 == w => {}
                other => fails.push(format!("fromHex({}): {:?}, reference {w:?}", e["hex"], other.map(|s| s.to_hex()))),
            }
        }
    }
    assert!(fails.is_empty(), "{} failures:\n{}", fails.len(), fails.join("\n"));
}

#[test]
fn sdk_transactions() {
    let s = sdk();
    let src = tx_ref(Transaction::from_hex(s["srcHex"].as_str().unwrap()).unwrap());
    let scopes = [0x41u32, 0x42, 0x43, 0xc1, 0xc2, 0xc3];
    let mut fails = vec![];
    for (i, c) in s["txs"].as_array().unwrap().iter().enumerate() {
        let mut tx = Transaction::from_hex(c["hex"].as_str().unwrap()).unwrap();
        if tx.id().unwrap() != c["id"].as_str().unwrap() {
            fails.push(format!("#{i}: id"));
        }
        for inp in tx.inputs.iter_mut() {
            inp.source_transaction = Some(src.clone());
        }
        expect(&mut fails, &format!("#{i} ef"), &c["ef"], tx.to_binary_ef().map(|b| hex_encode(&b)));
        expect(&mut fails, &format!("#{i} truncated"), &c["truncatedResult"], Transaction::from_hex(c["truncated"].as_str().unwrap()).and_then(|t| t.id()));
        expect(&mut fails, &format!("#{i} padded"), &c["paddedResult"], Transaction::from_hex(c["padded"].as_str().unwrap()).and_then(|t| t.id()));
        for (k, inp) in tx.inputs.iter().enumerate() {
            let out = src.borrow().outputs[inp.source_output_index as usize].clone();
            for (si, scope) in scopes.iter().enumerate() {
                let pre = format_preimage(&PreimageParams {
                    source_txid: inp.source_txid.as_deref().unwrap(),
                    source_output_index: inp.source_output_index,
                    source_satoshis: out.sats(),
                    transaction_version: tx.version,
                    other_inputs: refs_of(&tx.inputs, k),
                    input_index: k,
                    outputs: &tx.outputs,
                    input_sequence: inp.sequence,
                    subscript: out.locking_script.as_ref().unwrap(),
                    lock_time: tx.lock_time,
                    scope: *scope,
                })
                .map(|p| hex_encode(&p));
                if pre.as_deref().ok() != c["preimages"][k][si].as_str() {
                    fails.push(format!("#{i} input {k} scope {scope:x}: preimage differs"));
                }
            }
        }
    }
    assert!(fails.is_empty(), "{} failures:\n{}", fails.len(), fails.join("\n"));
}

#[test]
fn sdk_beef() {
    let mut fails = vec![];
    for (i, c) in sdk()["beefs"].as_array().unwrap().iter().enumerate() {
        for (what, input, want) in [("v2", &c["v2"], &c["v2parsed"]), ("atomic", &c["atomic"], &c["atomicParsed"]), ("v1", &c["v1"], &c["v1parsed"])] {
            let h = match input["ok"].as_str() {
                Some(h) => h,
                None => continue,
            };
            if want.is_null() {
                continue;
            }
            let parsed = Beef::from_binary(&hex_decode(h).unwrap());
            if want.get("throws").is_some() {
                if let Ok(mut b) = parsed {
                    if b.is_valid(false).is_ok() {
                        fails.push(format!("#{i} {what}: reference threw, port parsed"));
                    }
                }
                continue;
            }
            let mut b = match parsed {
                Err(e) => {
                    fails.push(format!("#{i} {what}: {e}"));
                    continue;
                }
                Ok(b) => b,
            };
            let w = &want["ok"];
            let v = b.is_valid(false).unwrap();
            let vt = b.is_valid(true).unwrap();
            let order: Vec<Value> = b.entries().unwrap().into_iter().map(|(id, _, _)| Value::String(id)).collect();
            if v != w["valid"] || vt != w["validTxidOnly"] || Value::Array(order) != w["order"] || b.atomic_txid.as_deref() != w["atomic"].as_str() {
                fails.push(format!("#{i} {what}: valid/order/atomic differ"));
            }
        }
        if let (Some(h), true) = (c["atomic"]["ok"].as_str(), c["atomicParsed"]["ok"]["valid"] == true) {
            if let Ok(t) = from_beef(&Bin::Hex(h)) {
                match to_atomic_beef(&t) {
                    Ok(b) if hex_encode(&b) == h => {}
                    _ => fails.push(format!("#{i}: atomic BEEF does not round-trip")),
                }
            }
        }
    }
    assert!(fails.is_empty(), "{} failures:\n{}", fails.len(), fails.join("\n"));
}
