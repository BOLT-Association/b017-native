//! TransactionSignature.format (BIP143 with FORKID, @bsv/sdk 2.8.11 formatBip143), the signature encodings,
//! hashes, and boltLib's Signer / Recipient (async-signer branch).

use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use bsv::primitives::big_number::Endian;
use bsv::primitives::private_key::PrivateKey;

use crate::error::{err, Error, Result};
use crate::script::{hex_decode, Script};
use crate::tx::{reversed, sha256d, Output, TxRef, Writer};

pub const SIGHASH_ALL: u32 = 0x01;
pub const SIGHASH_NONE: u32 = 0x02;
pub const SIGHASH_SINGLE: u32 = 0x03;
pub const SIGHASH_FORKID: u32 = 0x40;
pub const SIGHASH_ANYONECANPAY: u32 = 0x80;
/// SIGHASH_FORKID | SIGHASH_ALL, the only scope b017 signs with.
pub const SIGNATURE_SCOPE: u32 = SIGHASH_FORKID | SIGHASH_ALL;

/// An input as the preimage sees it.
#[derive(Clone, Default)]
pub struct OutpointRef {
    pub source_txid: Option<String>,
    pub source_transaction: Option<TxRef>,
    pub source_output_index: u32,
    pub sequence: Option<u32>,
}

/// The TransactionSignature.format parameters.
pub struct PreimageParams<'a> {
    pub source_txid: &'a str,
    pub source_output_index: u32,
    pub source_satoshis: u64,
    pub transaction_version: u32,
    pub other_inputs: Vec<OutpointRef>,
    pub input_index: usize,
    pub outputs: &'a [Output],
    pub input_sequence: Option<u32>,
    pub subscript: &'a Script,
    pub lock_time: u32,
    pub scope: u32,
}

/// `tx.inputs.filter((_, i) => i !== skip)` as OutpointRefs (`skip` = usize::MAX for none).
pub fn refs_of(inputs: &[crate::tx::Input], skip: usize) -> Vec<OutpointRef> {
    inputs
        .iter()
        .enumerate()
        .filter(|(k, _)| *k != skip)
        .map(|(_, i)| OutpointRef {
            source_txid: i.source_txid.clone(),
            source_transaction: i.source_transaction.clone(),
            source_output_index: i.source_output_index,
            sequence: i.sequence,
        })
        .collect()
}

fn hex_bytes(s: &str) -> Result<Vec<u8>> {
    hex_decode(s).ok_or_else(|| Error("Invalid hex string".into()))
}

/// TransactionSignature.format for a FORKID scope (BIP143).
pub fn format_preimage(p: &PreimageParams) -> Result<Vec<u8>> {
    let cur = OutpointRef {
        source_txid: Some(p.source_txid.to_string()),
        source_transaction: None,
        source_output_index: p.source_output_index,
        sequence: p.input_sequence,
    };
    let mut inputs = p.other_inputs.clone();
    if p.input_index > inputs.len() {
        return err("inputIndex out of range");
    }
    inputs.insert(p.input_index, cur);
    let base = p.scope & 31;
    let zero = vec![0u8; 32];

    let mut hash_prevouts = zero.clone();
    if p.scope & SIGHASH_ANYONECANPAY == 0 {
        let mut w = Writer::default();
        for i in &inputs {
            match &i.source_txid {
                None => match &i.source_transaction {
                    None => return err("Missing sourceTransaction for input"),
                    Some(s) => w.bytes(&s.borrow().hash()?),
                },
                Some(id) => w.bytes(&reversed(&hex_bytes(id)?)),
            }
            w.u32(i.source_output_index);
        }
        hash_prevouts = sha256d(&w.0);
    }
    let mut hash_sequence = zero.clone();
    if p.scope & SIGHASH_ANYONECANPAY == 0 && base != SIGHASH_SINGLE && base != SIGHASH_NONE {
        let mut w = Writer::default();
        for i in &inputs {
            w.u32(i.sequence.unwrap_or(0xffff_ffff));
        }
        hash_sequence = sha256d(&w.0);
    }
    let write_out = |w: &mut Writer, o: &Output| {
        w.u64(o.sats());
        let s = o
            .locking_script
            .as_ref()
            .map(|s| s.to_binary())
            .unwrap_or_default();
        w.varint(s.len() as u64);
        w.bytes(&s);
    };
    let hash_outputs = if base != SIGHASH_SINGLE && base != SIGHASH_NONE {
        let mut w = Writer::default();
        for o in p.outputs {
            write_out(&mut w, o);
        }
        sha256d(&w.0)
    } else if base == SIGHASH_SINGLE && p.input_index < p.outputs.len() {
        let mut w = Writer::default();
        write_out(&mut w, &p.outputs[p.input_index]);
        sha256d(&w.0)
    } else {
        zero
    };

    let mut w = Writer::default();
    w.u32(p.transaction_version);
    w.bytes(&hash_prevouts);
    w.bytes(&hash_sequence);
    w.bytes(&reversed(&hex_bytes(p.source_txid)?));
    w.u32(p.source_output_index);
    let sub = p.subscript.to_binary();
    w.varint(sub.len() as u64);
    w.bytes(&sub);
    w.u64(p.source_satoshis);
    w.u32(p.input_sequence.unwrap_or(0xffff_ffff));
    w.bytes(&hash_outputs);
    w.u32(p.lock_time);
    w.u32(p.scope);
    Ok(w.0)
}

/// Hash.sha256.
pub fn sha256(b: &[u8]) -> Vec<u8> {
    bsv::primitives::hash::sha256(b).to_vec()
}

/// Hash.hash160.
pub fn hash160(b: &[u8]) -> Vec<u8> {
    bsv::primitives::hash::hash160(b).to_vec()
}

/// An ECDSA (r, s) pair as a Signer returns it, big-endian (S not normalised: TS keeps what the signer gave).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

impl Signature {
    /// TS Signature.toDER: canonical integers, S as given.
    pub fn der(&self) -> Vec<u8> {
        let enc = |n: &[u8]| -> Vec<u8> {
            let mut b: Vec<u8> = n.iter().copied().skip_while(|&x| x == 0).collect();
            if b.is_empty() {
                b.push(0);
            }
            if b[0] & 0x80 != 0 {
                b.insert(0, 0);
            }
            b
        };
        let (r, s) = (enc(&self.r), enc(&self.s));
        let mut out = vec![0x30, (4 + r.len() + s.len()) as u8, 0x02, r.len() as u8];
        out.extend_from_slice(&r);
        out.extend_from_slice(&[0x02, s.len() as u8]);
        out.extend_from_slice(&s);
        out
    }
    /// TransactionSignature.toChecksigFormat: DER + the scope byte.
    pub fn checksig_format(&self, scope: u32) -> Vec<u8> {
        let mut d = self.der();
        d.push(scope as u8);
        d
    }
}

/// A boxed future (what a Signer's / template's `sign` returns).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// boltLib's Signer: a compressed public key and a signature over sha256(msg) (what PrivateKey.sign does). It may
/// be asynchronous (a wallet over IPC).
pub trait Signer {
    fn public_key(&self) -> Vec<u8>;
    fn sign<'a>(&'a self, msg: &'a [u8]) -> BoxFuture<'a, Result<Signature>>;
}

/// A PrivateKey as a Signer (TS `toSigner(privateKey)`).
pub struct KeySigner(pub PrivateKey);

impl KeySigner {
    pub fn from_hex(h: &str) -> Result<Self> {
        PrivateKey::from_hex(h)
            .map(KeySigner)
            .map_err(|e| Error(e.to_string()))
    }
}

impl Signer for KeySigner {
    fn public_key(&self) -> Vec<u8> {
        self.0.to_public_key().to_der()
    }
    fn sign<'a>(&'a self, msg: &'a [u8]) -> BoxFuture<'a, Result<Signature>> {
        Box::pin(async move {
            let sig = self.0.sign(msg, true).map_err(|e| Error(e.to_string()))?;
            Ok(Signature {
                r: sig.r().to_array(Endian::Big, None),
                s: sig.s().to_array(Endian::Big, None),
            })
        })
    }
}

/// boltLib's Recipient: a Signer the caller controls, or a third party's 33-byte compressed public key.
#[derive(Clone)]
pub enum Recipient {
    Signer(Rc<dyn Signer>),
    PubKey(Vec<u8>),
}

impl Recipient {
    /// `recipientPubKey`.
    pub fn pub_key(&self) -> Vec<u8> {
        match self {
            Recipient::Signer(s) => s.public_key(),
            Recipient::PubKey(p) => p.clone(),
        }
    }
    /// `recipientSigner`.
    pub fn signer(&self) -> Option<Rc<dyn Signer>> {
        match self {
            Recipient::Signer(s) => Some(s.clone()),
            Recipient::PubKey(_) => None,
        }
    }
}

/// Drive a future to completion on the current thread (for callers without a runtime; signers that need one
/// must be driven by the caller's executor instead).
pub fn block_on<F: Future>(f: F) -> F::Output {
    fn noop(_: *const ()) {}
    fn clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut f = Box::pin(f);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::yield_now();
    }
}
