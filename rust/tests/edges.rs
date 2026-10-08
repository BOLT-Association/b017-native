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
    let file: Value =
        serde_json::from_str(&std::fs::read_to_string(vectors_dir().join("edges.json")).unwrap())
            .unwrap();
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
            "singleSpendSign" | "p2pkhUnlockSign" | "pay2ProofSign" => {
                let (t, sats, lock) = edge_spend(&key, &s(0));
                let b = t.borrow();
                let tpl: Rc<dyn b017::boltlib::UnlockTemplate> = match fname {
                    "singleSpendSign" => Rc::new(b017::singlespend::SingleSpendUnlock(b017::singlespend::SingleUnlockParams {
                        signer: key.clone(),
                        beneficiary_pub_key_hash: hash160(&key.public_key()),
                        unlock_suffix: Script::from_hex(b017::suffixes_gen::MIN_SIMPLE_UNLOCK_SUFFIX_HEX).unwrap(),
                        force_no_change: false,
                        force_no_fund: false,
                        prev_txs: vec![],
                        source_satoshis: sats,
                        locking_script: lock,
                        leading_value_pushes: 0,
                        layout: None,
                        auth_or_misc_data: vec![],
                        melt: false,
                    })),
                    "p2pkhUnlockSign" => Rc::new(P2PKHUnlock(key.clone())),
                    _ => Rc::new(b017::pay2proof::Pay2ProofUnlock::new(key.clone(), sats.unwrap_or(0), lock)),
                };
                block_on(tpl.sign(&b, 0)).map(|x| json!(x.to_hex()))
            }
            other => panic!("no Rust mapping for {other}"),
        };
        match (r.get("throws"), got) {
            (Some(w), Ok(v)) => fails.push(format!(
                "#{i} {fname}: reference threw {w}, Rust returned {v}"
            )),
            (Some(w), Err(e)) => {
                let w = w.as_str().unwrap();
                if e.0 != w && !w.starts_with("Cannot read properties of") {
                    fails.push(format!("#{i} {fname}: error {:?}, reference {w:?}", e.0));
                }
            }
            (None, Err(e)) => fails.push(format!(
                "#{i} {fname}: Rust error {e}, reference {}",
                r["result"]
            )),
            (None, Ok(v)) => {
                if v != r["result"] {
                    fails.push(format!(
                        "#{i} {fname} {}: {v}, reference {}",
                        a[0], r["result"]
                    ));
                }
            }
        }
    }
    assert!(
        fails.is_empty(),
        "{} failures:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

/// The crafted spends of edges.test.ts, by name: the tx and the sourceSatoshis / lockingScript overrides.
fn edge_spend(key: &Rc<dyn Signer>, name: &str) -> (b017::TxRef, Option<u64>, Option<Script>) {
    use b017::nfttemplates::{MinSimpleTemplate, NftLockArgs};
    use b017::tx::Input;
    let pkh = hash160(&key.public_key());
    let lock_ms = MinSimpleTemplate::lock(&pkh, &key.public_key(), &NftLockArgs::default());
    let out = || Output::new(1, p2pkh_lock(&pkh));
    let empty = || Some(Script::default());
    let with_src = |sats: Option<u64>| {
        let s0 = tx_ref(Transaction {
            version: 1,
            outputs: vec![Output {
                satoshis: sats,
                locking_script: Some(lock_ms.clone()),
                change: false,
            }],
            ..Default::default()
        });
        Transaction {
            version: 2,
            outputs: vec![out()],
            inputs: vec![Input {
                source_transaction: Some(s0),
                unlocking_script: empty(),
                sequence: Some(0xffff_ffff),
                ..Default::default()
            }],
            ..Default::default()
        }
    };
    let txid_only = || Transaction {
        version: 2,
        outputs: vec![out()],
        inputs: vec![Input {
            source_txid: Some("ef".repeat(32)),
            unlocking_script: empty(),
            sequence: Some(0xffff_ffff),
            ..Default::default()
        }],
        ..Default::default()
    };
    let (t, sats, lock) = match name {
        "noRef" => (
            Transaction {
                version: 2,
                outputs: vec![out()],
                inputs: vec![Input {
                    unlocking_script: empty(),
                    sequence: Some(0xffff_ffff),
                    ..Default::default()
                }],
                ..Default::default()
            },
            None,
            None,
        ),
        "txidOnly" => (txid_only(), None, None),
        "txidOnlyWithAmount" => (txid_only(), Some(5), None),
        "txidOnlyWithAmountAndLock" => (txid_only(), Some(5), Some(lock_ms.clone())),
        "noAmount" => (with_src(None), None, None),
        "zeroAmount" => (with_src(Some(0)), None, None),
        "fundWithoutSource" => {
            let mut t = with_src(Some(1));
            t.inputs.push(Input {
                source_txid: Some("aa".repeat(32)),
                unlocking_script: empty(),
                sequence: Some(0xffff_ffff),
                ..Default::default()
            });
            t.outputs.push(out());
            (t, None, None)
        }
        other => panic!("unknown edge spend {other}"),
    };
    (tx_ref(t), sats, lock)
}
