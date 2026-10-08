//! @bsv/sdk 2.8.11 MerklePath (BUMP, BRC-74): parse with the same validation, serialisation (the txid flag is part
//! of the bytes), computeRoot, combine, trim. See the Go port's merklepath.go.

use std::collections::HashMap;

use crate::error::{err, Error, Result};
use crate::script::{hex_encode, js_hex_to_array};
use crate::tx::{reversed, sha256d, Reader, Writer};

const MAX_SAFE_INTEGER: u64 = (1u64 << 53) - 1;

/// A MerklePath leaf; `hash: None` when the leaf only says "duplicate".
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Leaf {
    pub offset: u64,
    pub hash: Option<String>,
    pub txid: bool,
    pub duplicate: bool,
}

/// A TS MerklePath.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
    pub block_height: u64,
    pub path: Vec<Vec<Leaf>>,
}

fn offset_at_height(offset: u64, height: usize) -> u64 {
    if height >= 64 {
        0
    } else {
        offset >> height
    }
}
fn sibling_of(o: u64) -> u64 {
    if o % 2 == 0 {
        o + 1
    } else {
        o - 1
    }
}
fn offset_tree_height(o: u64) -> usize {
    (64 - o.leading_zeros()) as usize
}

/// The reference's hashPair(left, right) on display-order hex.
pub fn hash_pair(left: &str, right: &str) -> Result<String> {
    let b = js_hex_to_array(&format!("{left}{right}"))?;
    Ok(hex_encode(&reversed(&sha256d(&reversed(&b)))))
}

impl MerklePath {
    /// `MerklePath.fromBinary(bump, legalOffsetsOnly)` (roots always validated).
    pub fn from_binary(b: &[u8], legal_offsets_only: bool) -> Result<MerklePath> {
        MerklePath::from_reader(&mut Reader::new(b), legal_offsets_only)
    }

    /// `MerklePath.fromHex`.
    pub fn from_hex(h: &str) -> Result<MerklePath> {
        MerklePath::from_binary(&js_hex_to_array(h)?, true)
    }

    pub fn from_reader(r: &mut Reader, legal_offsets_only: bool) -> Result<MerklePath> {
        let height = r.varint_strict()?;
        let tree_height = r.u8()? as usize;
        let mut path = vec![Vec::new(); tree_height];
        for level in path.iter_mut() {
            let n = r.varint_strict()?;
            for _ in 0..n {
                let offset = r.varint_strict()?;
                let flags = r.u8()?;
                let mut leaf = Leaf { offset, ..Default::default() };
                if flags & 1 == 1 {
                    leaf.duplicate = true;
                } else {
                    leaf.txid = flags & 2 != 0;
                    leaf.hash = Some(hex_encode(&reversed(&r.read(32)?)));
                }
                level.push(leaf);
            }
            level.sort_by_key(|l| l.offset);
        }
        MerklePath::new(height, path, legal_offsets_only)
    }

    /// The TS constructor with validateRoots = true.
    pub fn new(block_height: u64, path: Vec<Vec<Leaf>>, legal_offsets_only: bool) -> Result<MerklePath> {
        if path.is_empty() || path.len() > 54 {
            return err("Merkle Path must contain between 1 and 54 levels");
        }
        let mp = MerklePath { block_height, path };
        let mut legal: Vec<std::collections::BTreeSet<u64>> = vec![Default::default(); mp.path.len()];
        for (height, leaves) in mp.path.iter().enumerate() {
            if leaves.is_empty() && height == 0 {
                return err(format!("Empty level at height: {height}"));
            }
            let mut seen = std::collections::HashSet::new();
            for leaf in leaves {
                if leaf.offset > MAX_SAFE_INTEGER {
                    return err("Invalid offset");
                }
                if !seen.insert(leaf.offset) {
                    return err(format!("Duplicate offset: {}, at height: {height}", leaf.offset));
                }
                if height == 0 {
                    if !leaf.duplicate {
                        for (h, set) in legal.iter_mut().enumerate().skip(1) {
                            set.insert(sibling_of(offset_at_height(leaf.offset, h)));
                        }
                    }
                } else if legal_offsets_only && !legal[height].contains(&leaf.offset) {
                    let offs: Vec<String> = legal[height].iter().map(|o| o.to_string()).collect();
                    return err(format!(
                        "Invalid offset: {}, at height: {height}, with legal offsets: {}",
                        leaf.offset,
                        offs.join(", ")
                    ));
                }
            }
        }
        let mut root: Option<String> = None;
        for leaf in &mp.path[0] {
            let computed = mp.compute_root_opt(leaf.hash.as_deref())?;
            match &root {
                None => root = Some(computed),
                Some(r) if *r != computed => return err("Mismatched roots"),
                _ => {}
            }
        }
        Ok(mp)
    }

    /// `toBinary`.
    pub fn to_binary(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.varint(self.block_height);
        w.0.push(self.path.len() as u8);
        for level in &self.path {
            w.varint(level.len() as u64);
            for leaf in level {
                w.varint(leaf.offset);
                let mut flags = 0u8;
                if leaf.duplicate {
                    flags |= 1;
                }
                if leaf.txid {
                    flags |= 2;
                }
                w.0.push(flags);
                if flags & 1 == 0 {
                    // a parsed leaf's hash is always hex; a hand-built bad one serialises as zeros
                    w.bytes(&reversed(&js_hex_to_array(leaf.hash.as_deref().unwrap_or("")).unwrap_or_else(|_| vec![0; 32])));
                }
            }
        }
        w.0
    }

    /// `toHex`.
    pub fn to_hex(&self) -> String {
        hex_encode(&self.to_binary())
    }

    fn index_of(&self, txid: &str) -> Result<u64> {
        self.path[0]
            .iter()
            .find(|l| l.hash.as_deref() == Some(txid))
            .map(|l| l.offset)
            .ok_or_else(|| Error(format!("Transaction ID {txid} not found in the Merkle Path")))
    }

    fn max_offset0(&self) -> u64 {
        self.path[0].iter().map(|l| l.offset).max().unwrap_or(0)
    }

    /// `computeRoot(txid)`; an empty txid computes from the first leaf with a hash.
    pub fn compute_root(&self, txid: &str) -> Result<String> {
        if txid.is_empty() {
            self.compute_root_opt(None)
        } else {
            self.compute_root_opt(Some(txid))
        }
    }

    fn compute_root_opt(&self, txid: Option<&str>) -> Result<String> {
        let txid = match txid {
            Some(t) => t.to_string(),
            None => match self.path[0].iter().find(|l| l.hash.as_deref().is_some_and(|h| !h.is_empty())) {
                Some(l) => l.hash.clone().unwrap(),
                None => return err("No valid leaf found in the Merkle Path"),
            },
        };
        let index = self.index_of(&txid)?;
        let mut working = txid;
        if self.path.len() == 1 && self.path[0].len() == 1 {
            return Ok(working);
        }
        let max_off = self.max_offset0();
        let tree_height = self.path.len().max(offset_tree_height(max_off));
        for height in 0..tree_height {
            let offset = sibling_of(offset_at_height(index, height));
            let leaf = self.find_or_compute_leaf(height, offset)?;
            let last_odd = self.path.len() == 1 && offset_at_height(index, height) == offset_at_height(max_off, height);
            working = match leaf {
                None => {
                    if last_odd {
                        hash_pair(&working, &working)?
                    } else {
                        return err(format!("Missing hash for index {index} at height {height}"));
                    }
                }
                Some(l) if l.duplicate => hash_pair(&working, &working)?,
                Some(l) if offset % 2 == 1 => hash_pair(l.hash.as_deref().unwrap_or(""), &working)?,
                Some(l) => hash_pair(&working, l.hash.as_deref().unwrap_or(""))?,
            };
        }
        Ok(working)
    }

    fn find_or_compute_leaf(&self, height: usize, offset: u64) -> Result<Option<Leaf>> {
        if height < self.path.len() {
            if let Some(l) = self.path[height].iter().find(|l| l.offset == offset) {
                return Ok(Some(l.clone()));
            }
        }
        if height == 0 {
            return Ok(None);
        }
        let h = height - 1;
        let l = match offset.checked_mul(2) {
            Some(l) if l <= MAX_SAFE_INTEGER => l,
            _ => return Ok(None),
        };
        let leaf0 = match self.find_or_compute_leaf(h, l)? {
            Some(x) => x,
            None => return Ok(None),
        };
        let h0 = match leaf0.hash.clone().filter(|s| !s.is_empty()) {
            Some(x) => x,
            None => return Ok(None),
        };
        let leaf1 = self.find_or_compute_leaf(h, l + 1)?;
        Ok(match leaf1 {
            Some(ref l1) if l1.hash.is_some() => {
                let w = if l1.duplicate { hash_pair(&h0, &h0)? } else { hash_pair(l1.hash.as_deref().unwrap(), &h0)? };
                Some(Leaf { offset, hash: Some(w), ..Default::default() })
            }
            other => {
                if other.as_ref().is_some_and(|l1| l1.duplicate)
                    || (self.path.len() == 1 && l == offset_at_height(self.max_offset0(), h))
                {
                    Some(Leaf { offset, hash: Some(hash_pair(&h0, &h0)?), ..Default::default() })
                } else {
                    None
                }
            }
        })
    }

    /// `combine(other)`.
    pub fn combine(&mut self, other: &MerklePath) -> Result<()> {
        if self.block_height != other.block_height {
            return err("You cannot combine paths which do not have the same block height.");
        }
        if self.compute_root("")? != other.compute_root("")? {
            return err("You cannot combine paths which do not have the same root.");
        }
        let mut combined = Vec::new();
        for h in 0..self.path.len() {
            let mut level = self.path[h].clone();
            if let Some(ol) = other.path.get(h) {
                for o in ol {
                    match level.iter_mut().find(|l| l.offset == o.offset) {
                        None => level.push(o.clone()),
                        Some(e) => {
                            if o.txid {
                                e.txid = true
                            }
                        }
                    }
                }
            }
            combined.push(level);
        }
        self.path = combined;
        self.trim()
    }

    /// `trim()`.
    pub fn trim(&mut self) -> Result<()> {
        fn push_if_new(v: u64, a: &mut Vec<u64>) {
            if a.last() != Some(&v) {
                a.push(v);
            }
        }
        for level in self.path.iter_mut() {
            level.sort_by_key(|l| l.offset);
        }
        let mut computed = Vec::new();
        let mut drop = Vec::new();
        for l in 0..self.path[0].len() {
            let n = &self.path[0][l];
            if n.txid {
                push_if_new(offset_at_height(n.offset, 1), &mut computed);
            } else {
                let k = if n.offset % 2 == 1 { l.checked_sub(1) } else { Some(l + 1) };
                let peer = match k.and_then(|k| self.path[0].get(k)) {
                    Some(p) => p,
                    None => return err("Cannot read properties of undefined (reading 'txid')"),
                };
                if !peer.txid {
                    push_if_new(peer.offset, &mut drop);
                }
            }
        }
        let drop_from = |path: &mut Vec<Vec<Leaf>>, d: &[u64], level: usize| {
            for o in d.iter().rev() {
                if let Some(i) = path[level].iter().position(|n| n.offset == *o) {
                    path[level].remove(i);
                }
            }
        };
        drop_from(&mut self.path, &drop, 0);
        for h in 1..self.path.len() {
            let d = computed.clone();
            let mut next = Vec::new();
            for o in &computed {
                push_if_new(offset_at_height(*o, 1), &mut next);
            }
            computed = next;
            drop_from(&mut self.path, &d, h);
        }
        Ok(())
    }
}

#[allow(dead_code)]
fn _unused(_: HashMap<u8, u8>) {}
