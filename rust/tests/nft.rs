//! Phase 2 vectors: NFT locks and every recorded MinSimple / AuthBolt sign().
mod common;

use std::rc::Rc;

use b017::nfttemplates::{AuthBoltTemplate, MinSimpleTemplate, NftLockArgs};
use common::*;

fn lock_args(args: &[serde_json::Value]) -> NftLockArgs {
    NftLockArgs {
        commitment: arg_at(args, 2).bytes(),
        txo_type: arg_at(args, 3).bytes(),
        parent: arg_at(args, 4).bytes(),
        grandparent: arg_at(args, 5).bytes(),
    }
}

#[test]
fn vectors_lock_nft() {
    for (name, lock) in [
        (
            "lock.MinSimple",
            MinSimpleTemplate::lock as fn(&[u8], &[u8], &NftLockArgs) -> b017::Script,
        ),
        ("lock.AuthBolt", AuthBoltTemplate::lock),
    ] {
        for (i, rec) in calls(name).iter().enumerate() {
            let args = rec["args"].as_array().unwrap();
            let s = lock(
                &arg_at(args, 0).bytes().unwrap(),
                &arg_at(args, 1).bytes().unwrap(),
                &lock_args(args),
            );
            assert_eq!(
                s.to_hex(),
                rec["result"].as_str().unwrap(),
                "{name} {}",
                label(rec, i)
            );
        }
    }
}

#[test]
fn vectors_sign_nft() {
    let mut fails = replay_sign("sign.MinSimple", &|g, method, args| {
        Ok(Rc::new(if method == "melt" {
            MinSimpleTemplate::melt(arg_at(args, 0).signer())
        } else {
            MinSimpleTemplate::unlock(
                arg_at(args, 0).signer(),
                &arg_at(args, 1).bytes().unwrap_or_default(),
                arg_at(args, 2).tx_list(g),
                arg_at(args, 3).boolean(),
                arg_at(args, 4).boolean(),
            )
        }))
    });
    fails.extend(replay_sign("sign.AuthBolt", &|g, method, args| {
        Ok(Rc::new(if method == "melt" {
            AuthBoltTemplate::melt(arg_at(args, 0).signer())
        } else {
            AuthBoltTemplate::unlock(
                arg_at(args, 0).signer(),
                &arg_at(args, 1).bytes().unwrap_or_default(),
                arg_at(args, 2).tx_list(g),
                &arg_at(args, 3).bytes().unwrap_or_default(),
                arg_at(args, 4).boolean(),
                arg_at(args, 5).boolean(),
            )?
        }))
    }));
    assert!(
        fails.is_empty(),
        "{} failures:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

#[test]
fn vectors_template_auth_bolt_refuses_long_data() {
    for (i, rec) in calls("template.AuthBolt").iter().enumerate() {
        let args = rec["args"].as_array().unwrap();
        let mut g = Graph::default();
        let r = AuthBoltTemplate::unlock(
            arg_at(args, 0).signer(),
            &arg_at(args, 1).bytes().unwrap_or_default(),
            arg_at(args, 2).tx_list(&mut g),
            &arg_at(args, 3).bytes().unwrap_or_default(),
            false,
            false,
        );
        assert_eq!(
            r.err().map(|e| e.0).as_deref(),
            rec["throws"].as_str(),
            "{}",
            label(rec, i)
        );
    }
}
