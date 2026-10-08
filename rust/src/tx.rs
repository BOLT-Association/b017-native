//! The transaction model of the reference (@bsv/sdk 2.8.11 `Transaction`), as far as b017 relies on it (see the
//! Go port's tx.go). Transactions are shared and mutated in place by the reference (sources attached, txids
//! filled in, merkle paths wired), and its scanner compares them by identity, so they live in `Rc<RefCell<_>>`.

use std::cell::RefCell;
use std::rc::Rc;

use crate::error::{err, Error, Result};
use crate::merklepath::MerklePath;
use crate::script::{hex_decode, hex_encode, Script};

/// A shared transaction (a TS object reference).
pub type TxRef = Rc<RefCell<Transaction>>;

/// Wrap a transaction as a shared reference.
pub fn tx_ref(t: Transaction) -> TxRef {
    Rc::new(RefCell::new(t))
}

/// A TS TransactionInput.
#[derive(Clone, Default)]
pub struct Input {
    /// Display-order txid hex; `None` is TS `undefined`.
    pub source_txid: Option<String>,
    pub source_output_index: u32,
    pub source_transaction: Option<TxRef>,
    /// `None` when the input has no unlocking script.
    pub unlocking_script: Option<Script>,
    /// `None` is TS `undefined` (serialised and executed as 0xffffffff).
    pub sequence: Option<u32>,
    /// TS `unlockingScriptTemplate`.
    pub template: Option<Rc<dyn crate::boltlib::UnlockTemplate>>,
}

impl Input {
    /// `sequence ?? 0xffffffff`.
    pub fn seq(&self) -> u32 {
        self.sequence.unwrap_or(0xffff_ffff)
    }
    /// `sourceTransaction?.outputs[sourceOutputIndex]` (cloned; `None` when absent or out of range).
    pub fn source_output(&self) -> Option<Output> {
        let src = self.source_transaction.as_ref()?;
        let b = src.borrow();
        b.outputs.get(self.source_output_index as usize).cloned()
    }
}

/// A TS TransactionOutput.
#[derive(Clone, Default, Debug)]
pub struct Output {
    /// `None` when the amount is undefined (serialised as 0).
    pub satoshis: Option<u64>,
    pub locking_script: Option<Script>,
    /// TS `change`: fee(0) computes its amount.
    pub change: bool,
}

impl Output {
    /// `satoshis ?? 0`.
    pub fn sats(&self) -> u64 {
        self.satoshis.unwrap_or(0)
    }
    /// An output with an amount and a lock.
    pub fn new(satoshis: u64, lock: Script) -> Self {
        Output { satoshis: Some(satoshis), locking_script: Some(lock), change: false }
    }
}

/// A TS Transaction.
#[derive(Clone, Default)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub lock_time: u32,
    pub merkle_path: Option<Rc<RefCell<MerklePath>>>,
}

impl Transaction {
    /// TS `toBinary` (an error where the TS throws).
    pub fn to_binary(&self) -> Result<Vec<u8>> {
        let mut w = Writer::default();
        w.u32(self.version);
        w.varint(self.inputs.len() as u64);
        for i in &self.inputs {
            match &i.source_txid {
                None => match &i.source_transaction {
                    None => return err("sourceTransaction is undefined"),
                    Some(s) => w.bytes(&s.borrow().hash()?),
                },
                Some(id) => {
                    let b = require_txid(id)?;
                    w.bytes(&reversed(&b));
                }
            }
            w.u32(i.source_output_index);
            let us = match &i.unlocking_script {
                None => return err("unlockingScript is undefined"),
                Some(s) => s.to_binary(),
            };
            w.varint(us.len() as u64);
            w.bytes(&us);
            w.u32(i.seq());
        }
        w.varint(self.outputs.len() as u64);
        for o in &self.outputs {
            w.u64(o.sats());
            let ls = match &o.locking_script {
                None => return err("Cannot read properties of undefined (reading 'toUint8Array')"),
                Some(s) => s.to_binary(),
            };
            w.varint(ls.len() as u64);
            w.bytes(&ls);
        }
        w.u32(self.lock_time);
        Ok(w.0)
    }

    /// TS `hash()`: sha256d of the serialisation (internal order).
    pub fn hash(&self) -> Result<Vec<u8>> {
        Ok(sha256d(&self.to_binary()?))
    }

    /// TS `id('hex')`.
    pub fn id(&self) -> Result<String> {
        Ok(hex_encode(&reversed(&self.hash()?)))
    }

    /// TS `toHex`.
    pub fn to_hex(&self) -> Result<String> {
        Ok(hex_encode(&self.to_binary()?))
    }

    /// TS `toEF()` (BRC-30 Extended Format): every input carries its source output's amount and lock.
    pub fn to_binary_ef(&self) -> Result<Vec<u8>> {
        let mut w = Writer::default();
        w.u32(self.version);
        w.bytes(&[0, 0, 0, 0, 0, 0xef]);
        w.varint(self.inputs.len() as u64);
        for i in &self.inputs {
            let src = match &i.source_transaction {
                None => return err("All inputs must have source transactions when serializing to EF format"),
                Some(s) => s,
            };
            match &i.source_txid {
                None => w.bytes(&src.borrow().hash()?),
                Some(id) => w.bytes(&reversed(&require_txid(id)?)),
            }
            w.u32(i.source_output_index);
            let us = match &i.unlocking_script {
                None => return err("unlockingScript is undefined"),
                Some(s) => s.to_binary(),
            };
            w.varint(us.len() as u64);
            w.bytes(&us);
            w.u32(i.seq());
            let out = match i.source_output() {
                Some(o) if o.locking_script.is_some() => o,
                _ => return err("Cannot read properties of undefined (reading 'satoshis')"),
            };
            w.u64(out.sats());
            let ls = out.locking_script.unwrap().to_binary();
            w.varint(ls.len() as u64);
            w.bytes(&ls);
        }
        w.varint(self.outputs.len() as u64);
        for o in &self.outputs {
            w.u64(o.sats());
            let ls = match &o.locking_script {
                None => return err("Cannot read properties of undefined (reading 'toUint8Array')"),
                Some(s) => s.to_binary(),
            };
            w.varint(ls.len() as u64);
            w.bytes(&ls);
        }
        w.u32(self.lock_time);
        Ok(w.0)
    }

    /// TS `Transaction.fromBinary` (strict varints, no trailing data).
    pub fn from_binary(b: &[u8]) -> Result<Transaction> {
        let mut r = Reader::new(b);
        let t = read_transaction(&mut r)?;
        if !r.eof() {
            return err("Serialized transaction contains trailing data");
        }
        Ok(t)
    }

    /// TS `Transaction.fromHex`.
    pub fn from_hex(h: &str) -> Result<Transaction> {
        match hex_decode(h) {
            Some(b) => Transaction::from_binary(&b),
            None => err("Invalid hex string"),
        }
    }
}

fn read_transaction(r: &mut Reader) -> Result<Transaction> {
    let mut t = Transaction { version: r.u32()?, ..Default::default() };
    let n = r.varint_strict()?;
    for _ in 0..n {
        let id = r.read(32)?;
        let vout = r.u32()?;
        let sl = r.varint_strict()? as usize;
        let sb = r.read(sl)?;
        let seq = r.u32()?;
        t.inputs.push(Input {
            source_txid: Some(hex_encode(&reversed(&id))),
            source_output_index: vout,
            unlocking_script: Some(Script::from_binary(&sb)),
            sequence: Some(seq),
            ..Default::default()
        });
    }
    let n = r.varint_strict()?;
    for _ in 0..n {
        let sat = r.u64()?;
        let sl = r.varint_strict()? as usize;
        let sb = r.read(sl)?;
        t.outputs.push(Output::new(sat, Script::from_binary(&sb)));
    }
    t.lock_time = r.u32()?;
    Ok(t)
}

fn require_txid(s: &str) -> Result<Vec<u8>> {
    match hex_decode(s) {
        Some(b) if b.len() == 32 => Ok(b),
        _ => err("sourceTXID must be a 64-character hexadecimal string"),
    }
}

/// sha256(sha256(b)).
pub fn sha256d(b: &[u8]) -> Vec<u8> {
    bsv::primitives::hash::sha256d(b).to_vec()
}

/// A reversed copy.
pub fn reversed(b: &[u8]) -> Vec<u8> {
    b.iter().rev().copied().collect()
}

/// TS Utils.Writer.
#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    pub fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn varint(&mut self, n: u64) {
        self.0.extend_from_slice(&varint_bytes(n));
    }
}

/// TS `writeVarIntNum`.
pub fn varint_bytes(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        vec![0xfd, n as u8, (n >> 8) as u8]
    } else if n <= 0xffff_ffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

/// TS Utils.Reader (strict where the reference reads strictly).
pub struct Reader<'a> {
    pub b: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }
    pub fn eof(&self) -> bool {
        self.pos >= self.b.len()
    }
    pub fn read(&mut self, n: usize) -> Result<Vec<u8>> {
        if self.pos + n > self.b.len() {
            return Err(Error("ReaderUint8Array read exceeds available data".into()));
        }
        let out = self.b[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(out)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.read(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.read(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.read(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn u64(&mut self) -> Result<u64> {
        let b = self.read(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(&b);
        Ok(u64::from_le_bytes(a))
    }
    /// TS `readVarIntNumStrict(false)`: canonical.
    pub fn varint_strict(&mut self) -> Result<u64> {
        match self.u8()? {
            0xfd => {
                let v = self.u16()?;
                if v < 0xfd {
                    return err("Non-canonical varint");
                }
                Ok(v as u64)
            }
            0xfe => {
                let v = self.u32()?;
                if v <= 0xffff {
                    return err("Non-canonical varint");
                }
                Ok(v as u64)
            }
            0xff => {
                let v = self.u64()?;
                if v <= 0xffff_ffff {
                    return err("Non-canonical varint");
                }
                Ok(v)
            }
            f => Ok(f as u64),
        }
    }
    /// TS `readVarIntNum` (non-strict), on the TS array Reader (its own error text).
    pub fn varint(&mut self) -> Result<u64> {
        let r = self.varint_inner();
        r.map_err(|e| if e.0.starts_with("ReaderUint8Array") { Error("Reader read exceeds available data".into()) } else { e })
    }
    fn varint_inner(&mut self) -> Result<u64> {
        match self.u8()? {
            0xfd => Ok(self.u16()? as u64),
            0xfe => Ok(self.u32()? as u64),
            0xff => {
                let v = self.u64()?;
                if v > 1 << 53 {
                    return err("number too large to retain precision - use readVarIntBn");
                }
                Ok(v)
            }
            f => Ok(f as u64),
        }
    }
}
