//! Seeded random fuzzing for crash-freedom and round trips (cargo-fuzz needs nightly; this runs on stable).
//! `cargo test -p b017 --release --test fuzz_random -- --ignored` runs the long version (B017_FUZZ_ITERS).
mod common;

use b017::beef::{from_beef, to_atomic_beef, Bin};
use b017::script::{hex_decode, Script};
use b017::tx::Transaction;
use b017::verifyevents::{verify_event, verify_events, ScanOpts, TxInput};
use common::*;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn seeds() -> Vec<Vec<u8>> {
    calls("toAtomicBeef")
        .iter()
        .step_by(4)
        .filter_map(|r| r["result"].as_str().map(|h| hex_decode(h).unwrap()))
        .collect()
}

fn mutate(r: &mut Rng, b: &[u8]) -> Vec<u8> {
    let mut v = b.to_vec();
    match r.below(4) {
        0 if !v.is_empty() => {
            let i = r.below(v.len());
            v[i] ^= 1 + r.below(255) as u8;
        }
        1 => v.truncate(r.below(v.len() + 1)),
        2 => {
            let i = r.below(v.len() + 1);
            v.insert(i, r.below(256) as u8);
        }
        _ => {
            let n = r.below(40);
            v = (0..n).map(|_| r.below(256) as u8).collect();
        }
    }
    v
}

fn run(iters: usize) {
    let mut r = Rng(0x9e3779b97f4a7c15);
    let seeds = seeds();
    for k in 0..iters {
        let base = &seeds[k % seeds.len()];
        let b = mutate(&mut r, base);
        // script: parsed bytes serialise back; re-serialised chunks are stable
        let s = Script::from_binary(&b);
        assert_eq!(s.to_binary(), b);
        let re = Script::new(s.chunks().to_vec());
        assert_eq!(
            Script::from_binary(&re.to_binary()).to_binary(),
            re.to_binary()
        );
        // tx: a parsed tx serialises to its bytes
        if let Ok(t) = Transaction::from_binary(&b) {
            assert_eq!(t.to_binary().unwrap(), b);
        }
        // BEEF: a parsed subject re-serialises
        if let Ok(t) = from_beef(&Bin::Bytes(&b)) {
            to_atomic_beef(&t).unwrap();
        }
        // the scanner answers, never panics
        let res = verify_events(&[TxInput::Bytes(b.clone())], &ScanOpts::default());
        assert!(!res.ok || res.token_type.is_some());
        let half = b.len() / 2;
        let _ = verify_event(
            &[
                TxInput::Bytes(b[..half].to_vec()),
                TxInput::Bytes(b[half..].to_vec()),
            ],
            &ScanOpts::default(),
        );
    }
}

#[test]
fn fuzz_short() {
    run(2_000);
}

#[test]
#[ignore]
fn fuzz_long() {
    let n = std::env::var("B017_FUZZ_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300_000);
    run(n);
}
