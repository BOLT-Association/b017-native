//! The reference's behaviour on edge inputs (vectors/edges.json).
mod common;

use std::rc::Rc;

use b017::beef::{from_beef, is_beef, Bin};
use b017::boltlib::*;
use b017::fingerprints::{recognize_p2p, recognize_type};
use b017::multibolt::{p2pkh_lock, SimpleMultiBOLT};
use b017::multiboltlib::smb_ancestor_piece;
use b017::script::{hex_decode, hex_encode, Script};
use b017::sighash::{block_on, hash160, KeySigner, Signer};
use b017::simplemulti::{SimpleMultiTemplate, SmbLockArgs, SmbUnlockArgs};
use b017::singleancestor::{ancestor_piece, auth_bolt_layout, min_simple_layout};
use b017::tx::{tx_ref, Output, Transaction};
use common::*;
use serde_json::{json, Value};

#[test]
fn vectors_edges() {
    let file: Value = serde_json::from_str(&std::fs::read_to_string(vectors_dir().join("edges.json")).unwrap()).unwrap();
    let extra = Rc::new(file["nodes"].as_object().unwrap().clone());
    let key: Rc<dyn Signer> = Rc::new(KeySigner::from_hex(&"22".repeat(32)).unwrap());
    let mut fails = vec![];
    for (i, r) in file["records"].as_array().unwrap().iter().enumerate() {
        let mut g = Graph::default();
        g.extra = Some(extra.clone());
        let a = r["args"].as_array().unwrap();
        let fname = r["fn"].as_str().unwrap();
        let n = |k: usize| a[k].as_f64().unwrap() as usize;
        let s = |k: usize| a[k].as_str().unwrap().to_string();
        let by = |k: usize| hex_decode(a[k]["bytes"].as_str().unwrap()).unwrap();
        let hx = |v: Vec<u8>| json!({ "bytes": hex_encode(&v) });
        let mut tx = |k: usize| g.tx(a[k]["tx"].as_str().unwrap());
        let got: b017::Result<Value> = match fname {
            "spentOutpoint" => spent_outpoint(&tx(0).borrow(), n(1)).map(hx),
            "vinSequence" => Ok(hx(vin_sequence(&tx(0).borrow(), n(1)))),
            "vinScript" => Ok(hx(vin_script(&tx(0).borrow(), n(1)))),
            "vinChunk" => Ok(hx(vin_chunk(&tx(0).borrow(), n(1), n(2)))),
            "outputValue" => Ok(hx(output_value(&tx(0).borrow(), n(1)))),
            "outputScript" => Ok(hx(output_script(&tx(0).borrow(), n(1)))),
            "buildChangeOutput" => Ok(hx(build_change_output(&tx(0).borrow(), n(1)))),
            "voutChunk" => vout_chunk(&tx(0).borrow(), n(1), n(2)).map(hx),
            "splitCtx" => split_ctx(&by(0), n(1)).map(|c| {
                json!({
                    "ctxHeader": hex_encode(&c.header), "ctxCodeUnlockScriptCode": hex_encode(&c.unlock_script_code),
                    "ctxCodeLen": hex_encode(&c.code_len), "ctxFooter": hex_encode(&c.footer),
                    "ctxCodeLockScriptCode": hex_encode(&c.lock_script_code), "ctxCodeLockLen": hex_encode(&c.lock_len)
                })
            }),
            "le32" => Ok(hx(le32(a[0].as_f64().unwrap() as u32))),
            "le64" => Ok(hx(le64(a[0].as_f64().unwrap() as u64))),
            "recognizeType" => Ok(recognize_type(Some(&Script::from_hex(&s(0)).unwrap()), None).map_or(Value::Null, |t| json!(t.as_str()))),
            "recognizeP2P" => Ok(json!(recognize_p2p(Some(&Script::from_hex(&s(0)).unwrap())))),
            "isBeef" => Ok(json!(is_beef(&Bin::Hex(&s(0))))),
            "isBeefBytes" => Ok(json!(is_beef(&Bin::Bytes(&by(0))))),
            "fromBeef" => from_beef(&Bin::Hex(&s(0))).and_then(|t| t.borrow().id()).map(|id| json!(id)),
            "smbAncestorPiece" => smb_ancestor_piece(&s(0), &tx(1).borrow()).map(hx),
            "nftAncestorPiece" => ancestor_piece(&s(0), &tx(1).borrow(), 0, &min_simple_layout()).map(hx),
            "authAncestorPiece" => ancestor_piece(&s(0), &tx(1).borrow(), 0, &auth_bolt_layout()).map(hx),
            "smbLock" => {
                let prev: Vec<_> = a[1]["txs"].as_array().map(|l| l.iter().map(|id| g.tx(id.as_str().unwrap())).collect()).unwrap_or_default();
                SimpleMultiTemplate::lock(&by(0), &prev, &SmbLockArgs { prev_vout_idx: n(2), ..Default::default() }).map(|s| json!(s.to_hex()))
            }
            "smbUnlockSign" => {
                let t = tx(0);
                let b = t.borrow();
                block_on(b017::boltlib::UnlockTemplate::sign(&SimpleMultiTemplate::unlock(key.clone(), &key.public_key(), vec![], SmbUnlockArgs::default()), &b, 0))
                    .map(|s| json!(s.to_hex()))
            }
            "smbMeltSign" => {
                let t = tx(0);
                let b = t.borrow();
                block_on(b017::boltlib::UnlockTemplate::sign(&SimpleMultiTemplate::melt(key.clone(), None, None), &b, 0)).map(|s| json!(s.to_hex()))
            }
            "mintNoMatchingOutput" | "mintTooPoor" | "mintOddSource" => {
                let (lock, sats) = match fname {
                    "mintNoMatchingOutput" => (p2pkh_lock(&[9u8; 20]), 1000),
                    "mintTooPoor" => (p2pkh_lock(&hash160(&key.public_key())), 0),
                    _ => (Script::from_hex("51").unwrap(), 10),
                };
                let src = tx_ref(Transaction { version: 1, outputs: vec![Output::new(sats, lock)], ..Default::default() });
                block_on(SimpleMultiBOLT::new().mint(key.clone(), &src, None)).map(|_| json!("minted"))
            }
            other => panic!("no Rust mapping for {other}"),
        };
        match (r.get("throws"), got) {
            (Some(w), Ok(v)) => fails.push(format!("#{i} {fname}: reference threw {w}, Rust returned {v}")),
            (Some(w), Err(e)) => {
                let w = w.as_str().unwrap();
                if e.0 != w && !w.starts_with("Cannot read properties of") {
                    fails.push(format!("#{i} {fname}: error {:?}, reference {w:?}", e.0));
                }
            }
            (None, Err(e)) => fails.push(format!("#{i} {fname}: Rust error {e}, reference {}", r["result"])),
            (None, Ok(v)) => {
                if v != r["result"] {
                    fails.push(format!("#{i} {fname} {}: {v}, reference {}", a[0], r["result"]));
                }
            }
        }
    }
    assert!(fails.is_empty(), "{} failures:\n{}", fails.len(), fails.join("\n"));
}
