//! Phase 4 vectors: SimpleMulti lock / sign, and the SimpleMultiBOLT class flows (vectors/flows.json).
mod common;

use std::rc::Rc;

use b017::boltlib::P2PKHUnlock;
use b017::multibolt::{p2pkh_lock, FundingSource, SimpleMultiBOLT, TransferOpts};
use b017::script::{hex_encode, Script};
use b017::sighash::{block_on, hash160, KeySigner, Recipient, Signer};
use b017::simplemulti::{SimpleMultiTemplate, SmbLockArgs, SmbUnlockArgs};
use b017::tx::{tx_ref, Input, Output, Transaction, TxRef};
use common::*;
use serde_json::Value;

#[test]
fn vectors_lock_simple_multi() {
    let mut fails = vec![];
    for (i, rec) in calls("lock.SimpleMulti").iter().enumerate() {
        let args = rec["args"].as_array().unwrap();
        let mut g = Graph::default();
        let a = SmbLockArgs {
            balance: arg_at(args, 2).bytes(),
            balance_commit: arg_at(args, 3).bytes(),
            pub_key_hash_commit: arg_at(args, 4).bytes(),
            pub_key_hash_commit2: arg_at(args, 5).bytes(),
            other_grandparent_outpoint: arg_at(args, 6).bytes(),
            txo_type: arg_at(args, 7).bytes(),
            output_index_n: arg_at(args, 8).bytes(),
            prev_vout_idx: arg_at(args, 9).number().unwrap_or(0) as usize,
        };
        let r = SimpleMultiTemplate::lock(
            &arg_at(args, 0).bytes().unwrap(),
            &arg_at(args, 1).tx_list(&mut g),
            &a,
        );
        match (rec.get("throws"), r) {
            (Some(_), Ok(_)) => fails.push(format!("{}: TS threw, Rust succeeded", label(rec, i))),
            (None, Err(e)) => fails.push(format!("{}: {e}", label(rec, i))),
            (None, Ok(s)) if s.to_hex() != rec["result"].as_str().unwrap() => {
                fails.push(format!("{}: lock differs", label(rec, i)))
            }
            _ => {}
        }
    }
    assert!(
        fails.is_empty(),
        "{} failures:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

#[test]
fn vectors_sign_simple_multi() {
    let fails = replay_sign("sign.SimpleMulti", &|g, method, args| {
        if method == "melt" {
            let lock = if arg_at(args, 2).t() == "script" {
                Some(Script::from_hex(args[2]["hex"].as_str().unwrap()).unwrap())
            } else {
                None
            };
            return Ok(Rc::new(SimpleMultiTemplate::melt(
                arg_at(args, 0).signer(),
                arg_at(args, 1).number(),
                lock,
            )));
        }
        let a = SmbUnlockArgs {
            force_no_change: arg_at(args, 3).boolean(),
            force_no_fund: arg_at(args, 4).boolean(),
            next_balance_commit: arg_at(args, 5).bytes(),
            next_txo_type: arg_at(args, 6).bytes(),
            input_index_n: arg_at(args, 7).bytes(),
            pub_key_hash2: arg_at(args, 8).bytes(),
            grandparent_bolt_vout_idx: arg_at(args, 9).bytes(),
            interop_bolt_vout_idx: arg_at(args, 10).bytes(),
            interop_pub_key_hash: arg_at(args, 11).bytes(),
            interop_outpoint: arg_at(args, 12).bytes(),
            interop_parent_outpoint: arg_at(args, 13).bytes(),
            ancestor_tx_b_ref: arg_at(args, 14).tx_or_none(g),
        };
        let prev = arg_at(args, 2).tx_list(g);
        Ok(Rc::new(SimpleMultiTemplate::unlock(
            arg_at(args, 0).signer(),
            &arg_at(args, 1).bytes().unwrap_or_default(),
            prev,
            a,
        )))
    });
    assert!(
        fails.is_empty(),
        "{} failures:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

// ---- class flows ----

#[derive(Debug, Clone, PartialEq)]
struct Step {
    step: String,
    tx: Option<String>,
    prev_txs: Vec<String>,
    balance: String,
    error: Option<String>,
}

fn key(n: u64) -> Rc<dyn Signer> {
    Rc::new(KeySigner::from_hex(&format!("{n:064x}")).unwrap())
}
fn rk(n: u64) -> Recipient {
    Recipient::Signer(key(n))
}
fn bal(n: u128) -> Vec<u8> {
    n.to_le_bytes().to_vec()
}
fn fresh(k: &Rc<dyn Signer>) -> TxRef {
    tx_ref(Transaction {
        version: 1,
        outputs: vec![Output::new(1000, p2pkh_lock(&hash160(&k.public_key())))],
        ..Default::default()
    })
}
fn snap(step: &str, b: &SimpleMultiBOLT) -> Step {
    Step {
        step: step.into(),
        tx: b.tx.as_ref().map(|t| t.borrow().to_hex().unwrap()),
        prev_txs: b
            .prev_txs
            .iter()
            .map(|t| t.borrow().to_hex().unwrap())
            .collect(),
        balance: hex_encode(&b.balance),
        error: None,
    }
}

const SIM: u128 = 0x1ffffffffffffe;

async fn scenario(name: &str, log: &mut Vec<Step>) -> b017::Result<()> {
    let issuer = key(1);
    match name {
        "lifecycle" => {
            let mut t = SimpleMultiBOLT::new();
            t.mint(issuer.clone(), &fresh(&issuer), Some(bal(SIM)))
                .await?;
            log.push(snap("mint", &t));
            t.transfer(&rk(101), false, TransferOpts::default()).await?;
            log.push(snap("transfer1", &t));
            t.transfer(&rk(102), false, TransferOpts::default()).await?;
            log.push(snap("transfer2", &t));
            let piece = t.split(&rk(110), &rk(111), &bal(1), None).await?;
            log.push(snap("split.main", &t));
            log.push(snap("split.piece", &piece));
        }
        "merge-melt" => {
            let mut a = SimpleMultiBOLT::new();
            a.mint(issuer.clone(), &fresh(&issuer), Some(bal(SIM)))
                .await?;
            let mut b = SimpleMultiBOLT::new();
            b.mint(issuer.clone(), &fresh(&issuer), Some(bal(1)))
                .await?;
            log.push(snap("mintA", &a));
            log.push(snap("mintB", &b));
            a.transfer(&rk(101), false, TransferOpts::default()).await?;
            b.transfer(&rk(102), false, TransferOpts::default()).await?;
            log.push(snap("transferA", &a));
            log.push(snap("transferB", &b));
            a.merge(&mut b, &rk(400), None).await?;
            log.push(snap("merge", &a));
            log.push(snap("merge.other", &b));
            a.melt(None).await?;
            log.push(snap("melt", &a));
        }
        "builder-branches" => {
            let mut a = SimpleMultiBOLT::new();
            a.mint(issuer.clone(), &fresh(&issuer), Some(bal(SIM)))
                .await?;
            a.skip_verify = true;
            a.transfer(
                &rk(901),
                false,
                TransferOpts {
                    force_no_change: true,
                    force_no_fund: true,
                    ..Default::default()
                },
            )
            .await?;
            log.push(snap("noChange.noFund", &a));
            let mut b = SimpleMultiBOLT::new();
            b.mint(issuer.clone(), &fresh(&issuer), Some(bal(SIM)))
                .await?;
            b.skip_verify = true;
            let ov = Input {
                source_transaction: Some(fresh(&issuer)),
                source_output_index: 0,
                template: Some(Rc::new(P2PKHUnlock(issuer.clone()))),
                sequence: Some(0xffff_ffff),
                ..Default::default()
            };
            b.transfer(
                &rk(902),
                false,
                TransferOpts {
                    fund_override: Some(ov),
                    ..Default::default()
                },
            )
            .await?;
            log.push(snap("fundOverride", &b));
            let mut c = SimpleMultiBOLT::new();
            c.mint(issuer.clone(), &fresh(&issuer), Some(bal(SIM)))
                .await?;
            c.melt(Some(hash160(&key(901).public_key()))).await?;
            log.push(snap("melt.pkh", &c));
        }
        "funding-source" => {
            let fsrc = || {
                Some(FundingSource {
                    tx: Some(fresh(&issuer)),
                    vout: Some(0),
                    key: Some(issuer.clone()),
                })
            };
            let mut t = SimpleMultiBOLT::new();
            t.mint(issuer.clone(), &fresh(&issuer), Some(bal(SIM)))
                .await?;
            t.transfer(&rk(101), false, TransferOpts::default()).await?;
            let piece = t.split(&rk(110), &rk(111), &bal(1), fsrc()).await?;
            log.push(snap("split.main", &t));
            log.push(snap("split.piece", &piece));
            let mut a = SimpleMultiBOLT::new();
            a.mint(issuer.clone(), &fresh(&issuer), Some(bal(SIM)))
                .await?;
            let mut b = SimpleMultiBOLT::new();
            b.mint(issuer.clone(), &fresh(&issuer), Some(bal(1)))
                .await?;
            a.transfer(&rk(101), false, TransferOpts::default()).await?;
            b.transfer(&rk(102), false, TransferOpts::default()).await?;
            a.merge(&mut b, &rk(400), fsrc()).await?;
            log.push(snap("merge", &a));
        }
        "second-piece" => {
            let (ka, kb) = (key(110), key(111));
            let mut t = SimpleMultiBOLT::new();
            t.mint(issuer.clone(), &fresh(&issuer), Some(bal(1000)))
                .await?;
            t.transfer(&rk(101), false, TransferOpts::default()).await?;
            let mut piece_b = t
                .split(
                    &Recipient::Signer(ka),
                    &Recipient::Signer(kb.clone()),
                    &bal(300),
                    None,
                )
                .await?;
            let mut piece_b2 = piece_b.clone();
            let fund = Input {
                source_transaction: Some(fresh(&kb)),
                source_output_index: 0,
                template: Some(Rc::new(P2PKHUnlock(kb.clone()))),
                sequence: Some(0xffff_ffff),
                ..Default::default()
            };
            piece_b
                .commit(
                    &rk(120),
                    TransferOpts {
                        fund_override: Some(fund),
                        ..Default::default()
                    },
                )
                .await?;
            log.push(snap("pieceB.commit", &piece_b));
            piece_b.settle(&rk(120), TransferOpts::default()).await?;
            log.push(snap("pieceB.settle", &piece_b));
            let b2 = piece_b2
                .split(
                    &rk(130),
                    &rk(131),
                    &bal(100),
                    Some(FundingSource {
                        tx: Some(fresh(&kb)),
                        vout: Some(0),
                        key: Some(kb.clone()),
                    }),
                )
                .await?;
            log.push(snap("pieceB2.split.main", &piece_b2));
            log.push(snap("pieceB2.split.piece", &b2));
        }
        "settle-wrong-key" => {
            let mut t = SimpleMultiBOLT::new();
            t.mint(issuer.clone(), &fresh(&issuer), Some(bal(1000)))
                .await?;
            t.commit(&rk(101), TransferOpts::default()).await?;
            log.push(snap("commit", &t));
            t.signer = Some(key(55));
            t.settle(&rk(101), TransferOpts::default()).await?;
        }
        "merge-bad-other" => {
            let mut a = SimpleMultiBOLT::new();
            a.mint(issuer.clone(), &fresh(&issuer), Some(bal(SIM)))
                .await?;
            let mut b = SimpleMultiBOLT::new();
            b.mint(issuer.clone(), &fresh(&issuer), Some(bal(1)))
                .await?;
            a.transfer(&rk(101), false, TransferOpts::default()).await?;
            b.transfer(&rk(102), false, TransferOpts::default()).await?;
            b.balance = bal(2);
            log.push(snap("before", &a));
            a.merge(&mut b, &rk(400), None).await?;
        }
        "split-bad-balance" => {
            let mut t = SimpleMultiBOLT::new();
            t.mint(issuer.clone(), &fresh(&issuer), Some(bal(1000)))
                .await?;
            t.transfer(&rk(101), false, TransferOpts::default()).await?;
            t.balance = bal(999);
            log.push(snap("before", &t));
            t.split(&rk(110), &rk(111), &bal(1), None).await?;
        }
        "melt-wrong-key" => {
            let mut t = SimpleMultiBOLT::new();
            t.mint(issuer.clone(), &fresh(&issuer), Some(bal(1000)))
                .await?;
            t.transfer(&rk(101), false, TransferOpts::default()).await?;
            t.signer = Some(key(55));
            log.push(snap("before", &t));
            t.melt(None).await?;
        }
        "inflated-balance" => {
            let mut t = SimpleMultiBOLT::new();
            t.mint(issuer.clone(), &fresh(&issuer), Some(bal(1000)))
                .await?;
            t.balance = bal(1001);
            log.push(snap("mint", &t));
            t.transfer(&rk(101), false, TransferOpts::default()).await?;
            log.push(snap("transfer", &t));
        }
        other => panic!("no Rust scenario for {other}"),
    }
    Ok(())
}

#[test]
fn vectors_flows() {
    let want: Value =
        serde_json::from_str(&std::fs::read_to_string(vectors_dir().join("flows.json")).unwrap())
            .unwrap();
    let mut fails = vec![];
    for (name, steps) in want.as_object().unwrap() {
        let mut got = vec![];
        if let Err(e) = block_on(scenario(name, &mut got)) {
            got.push(Step {
                step: "error".into(),
                tx: None,
                prev_txs: vec![],
                balance: String::new(),
                error: Some(e.0),
            });
        }
        let steps = steps.as_array().unwrap();
        if got.len() != steps.len() {
            fails.push(format!(
                "{name}: {} steps, want {} (last {:?})",
                got.len(),
                steps.len(),
                got.last().and_then(|s| s.error.clone())
            ));
            continue;
        }
        for (g, w) in got.iter().zip(steps) {
            if g.step != w["step"] {
                fails.push(format!("{name}: step {} want {}", g.step, w["step"]));
                break;
            }
            if g.step == "error" {
                let we = w["error"].as_str().unwrap();
                if is_b017_error(we) && g.error.as_deref() != Some(we) {
                    fails.push(format!("{name}: error {:?} want {we:?}", g.error));
                }
                continue;
            }
            if g.tx.as_deref() != w["tx"].as_str() {
                fails.push(format!("{name}/{}: tx differs", g.step));
            }
            let wp: Vec<&str> = w["prevTxs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap())
                .collect();
            if g.prev_txs.iter().map(|s| s.as_str()).collect::<Vec<_>>() != wp {
                fails.push(format!("{name}/{}: prevTxs differ", g.step));
            }
            if g.balance != w["balance"].as_str().unwrap() {
                fails.push(format!(
                    "{name}/{}: balance {} want {}",
                    g.step, g.balance, w["balance"]
                ));
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
