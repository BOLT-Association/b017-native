//! A port of the @bsv/sdk 2.8.11 `Script` chunk model (src/script/Script.ts) that b017's fingerprints and unlock
//! layouts are written against (see the Go port's script.go):
//! - a script made from bytes serialises back to exactly those bytes until its chunks are replaced;
//! - an OP_RETURN outside a conditional takes the rest of the script as its data;
//! - a truncated push keeps the bytes that are there;
//! - `write_bin` never produces OP_N: [] is OP_0, 1..75 bytes a direct push, then PUSHDATA1/2/4.

use crate::error::{err, Result};

pub const OP_0: u8 = 0x00;
pub const OP_PUSHDATA1: u8 = 0x4c;
pub const OP_PUSHDATA2: u8 = 0x4d;
pub const OP_PUSHDATA4: u8 = 0x4e;
pub const OP_IF: u8 = 0x63;
pub const OP_NOTIF: u8 = 0x64;
pub const OP_VERIF: u8 = 0x65;
pub const OP_VERNOTIF: u8 = 0x66;
pub const OP_ENDIF: u8 = 0x68;
pub const OP_RETURN: u8 = 0x6a;
pub const OP_DUP: u8 = 0x76;
pub const OP_EQUALVERIFY: u8 = 0x88;
pub const OP_HASH160: u8 = 0xa9;
pub const OP_CHECKSIG: u8 = 0xac;
pub const OP_CHECKSIGVERIFY: u8 = 0xad;

/// One script chunk. `data: None` is TS `data: undefined`; `Some(vec![])` is TS `data: []`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub op: u8,
    pub data: Option<Vec<u8>>,
}

impl Chunk {
    pub fn op(op: u8) -> Self {
        Chunk { op, data: None }
    }
    pub fn push(op: u8, data: Vec<u8>) -> Self {
        Chunk { op, data: Some(data) }
    }
    /// `chunk.data?.length ?? 0`.
    pub fn data_len(&self) -> usize {
        self.data.as_ref().map_or(0, |d| d.len())
    }
}

/// A TS Script: parsed chunks plus the raw bytes it was made from (kept until the chunks are replaced).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Script {
    chunks: Vec<Chunk>,
    raw: Option<Vec<u8>>,
}

impl Script {
    /// `new Script(chunks)`.
    pub fn new(chunks: Vec<Chunk>) -> Self {
        Script { chunks, raw: None }
    }

    /// `Script.fromBinary`.
    pub fn from_binary(b: &[u8]) -> Self {
        Script { chunks: parse_chunks(b), raw: Some(b.to_vec()) }
    }

    /// `Script.fromHex`.
    pub fn from_hex(h: &str) -> Result<Self> {
        if h.is_empty() {
            return Ok(Script::from_binary(&[]));
        }
        if h.len() % 2 != 0 {
            return err("There is an uneven number of characters in the string which suggests it is not hex encoded.");
        }
        match hex_decode(h) {
            Some(b) => Ok(Script::from_binary(&b)),
            None => err("Some elements in this string are not hex encoded."),
        }
    }

    /// `script.chunks`.
    pub fn chunks(&self) -> &[Chunk] {
        &self.chunks
    }

    /// `script.chunks = value`.
    pub fn set_chunks(&mut self, c: Vec<Chunk>) {
        self.chunks = c;
        self.raw = None;
    }

    /// `toBinary`.
    pub fn to_binary(&self) -> Vec<u8> {
        match &self.raw {
            Some(r) => r.clone(),
            None => serialize_chunks(&self.chunks),
        }
    }

    /// `toHex`.
    pub fn to_hex(&self) -> String {
        hex_encode(&self.to_binary())
    }

    /// `writeBin`.
    pub fn write_bin(&mut self, bin: &[u8]) -> &mut Self {
        let mut c = self.chunks.clone();
        c.extend(chunks_from_bin(bin));
        self.set_chunks(c);
        self
    }
}

/// boltLib `scriptChunksFromBin`: one push of `data` (OP_0 for empty).
pub fn chunks_from_bin(bin: &[u8]) -> Vec<Chunk> {
    let n = bin.len();
    let c = if n == 0 {
        Chunk::op(OP_0)
    } else if n < OP_PUSHDATA1 as usize {
        Chunk::push(n as u8, bin.to_vec())
    } else if n < 1 << 8 {
        Chunk::push(OP_PUSHDATA1, bin.to_vec())
    } else if n < 1 << 16 {
        Chunk::push(OP_PUSHDATA2, bin.to_vec())
    } else {
        Chunk::push(OP_PUSHDATA4, bin.to_vec())
    };
    vec![c]
}

/// boltLib `scriptChunk`: the data of chunk i, or [].
pub fn chunk_data(s: &Script, i: usize) -> Vec<u8> {
    s.chunks().get(i).and_then(|c| c.data.clone()).unwrap_or_default()
}

fn read_pushdata_length(op: u8, b: &[u8], pos: usize) -> (usize, usize) {
    let at = |i: usize| -> usize { b.get(i).map_or(0, |&x| x as usize) };
    let length = b.len();
    if op > 0 && op < OP_PUSHDATA1 {
        (op as usize, pos)
    } else if op == OP_PUSHDATA1 {
        if pos < length {
            (at(pos), pos + 1)
        } else {
            (0, pos)
        }
    } else if op == OP_PUSHDATA2 {
        (at(pos) | at(pos + 1) << 8, (pos + 2).min(length))
    } else {
        let l = (at(pos) as u32) | (at(pos + 1) as u32) << 8 | (at(pos + 2) as u32) << 16 | (at(pos + 3) as u32) << 24;
        (l as usize, (pos + 4).min(length))
    }
}

fn parse_chunks(b: &[u8]) -> Vec<Chunk> {
    let mut chunks = Vec::new();
    let length = b.len();
    let mut pos = 0usize;
    let mut in_cond: i64 = 0;
    while pos < length {
        let op = b[pos];
        pos += 1;
        if op == OP_RETURN && in_cond == 0 {
            chunks.push(Chunk::push(op, b[pos..length].to_vec()));
            break;
        }
        if op == OP_IF || op == OP_NOTIF || op == OP_VERIF || op == OP_VERNOTIF {
            in_cond += 1;
        } else if op == OP_ENDIF {
            in_cond -= 1;
        }
        if op > 0 && op <= OP_PUSHDATA4 {
            let (n, np) = read_pushdata_length(op, b, pos);
            pos = np;
            let end = pos.saturating_add(n).min(length);
            chunks.push(Chunk::push(op, b[pos..end].to_vec()));
            pos = end;
        } else {
            chunks.push(Chunk::op(op));
        }
    }
    chunks
}

fn serialize_chunks(chunks: &[Chunk]) -> Vec<u8> {
    let mut out = Vec::new();
    for c in chunks {
        out.push(c.op);
        let data = match &c.data {
            None => continue,
            Some(d) => d,
        };
        if c.op == OP_RETURN {
            out.extend_from_slice(data);
            break;
        }
        let n = data.len();
        if c.op < OP_PUSHDATA1 {
            out.extend_from_slice(data);
        } else if c.op == OP_PUSHDATA1 {
            out.push(n as u8);
            out.extend_from_slice(data);
        } else if c.op == OP_PUSHDATA2 {
            out.extend_from_slice(&[n as u8, (n >> 8) as u8]);
            out.extend_from_slice(data);
        } else if c.op == OP_PUSHDATA4 {
            out.extend_from_slice(&[n as u8, (n >> 8) as u8, (n >> 16) as u8, (n >> 24) as u8]);
            out.extend_from_slice(data);
        }
    }
    out
}

/// `OP_CHECKSIGVERIFY OP_ENDIF` (the 2-byte unlock-script-code prefix of the combined checksig subscript).
pub fn ocs_prefix() -> Vec<Chunk> {
    vec![Chunk::op(OP_CHECKSIGVERIFY), Chunk::op(OP_ENDIF)]
}

/// Lowercase hex.
pub fn hex_encode(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

/// Strict hex decode (None on odd length or a non-hex digit).
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let v = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for i in (0..b.len()).step_by(2) {
        out.push(v(b[i])? << 4 | v(b[i + 1])?);
    }
    Some(out)
}

/// `Utils.toArray(str, 'hex')` for a possibly malformed string: odd length gets a leading 0, a bad pair is 0.
pub fn js_hex_to_array(s: &str) -> Vec<u8> {
    let s = if s.len() % 2 != 0 { format!("0{s}") } else { s.to_string() };
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for i in (0..b.len()).step_by(2) {
        out.push(hex_decode(std::str::from_utf8(&b[i..i + 2]).unwrap_or("00")).map_or(0, |v| v[0]));
    }
    out
}
