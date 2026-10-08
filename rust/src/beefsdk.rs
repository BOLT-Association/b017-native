//! The parts of @bsv/sdk 2.8.11 `Beef` / `BeefTx` b017 uses: parse (V1, V2, Atomic), isValid (which SORTS the
//! txs), findAtomicTransaction, mergeTransaction, toBinaryAtomic. See the Go port's beefsdk.go.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use crate::error::{err, Error, Result};
use crate::merklepath::MerklePath;
use crate::script::{hex_encode, js_hex_to_array};
use crate::tx::{reversed, sha256d, tx_ref, Reader, Transaction, TxRef, Writer};

pub const BEEF_V1: u32 = 4022206465;
pub const BEEF_V2: u32 = 4022206466;
pub const ATOMIC_BEEF: u32 = 0x01010101;

/// A shared merkle path (a bump and the tx it proves hold the same object, as in TS).
pub type MpRef = Rc<RefCell<MerklePath>>;

/// A TS BeefTx.
#[derive(Clone)]
pub struct BeefTx {
    bump_index: Option<usize>,
    tx: RefCell<Option<TxRef>>,
    raw: Option<Vec<u8>>,
    txid: RefCell<Option<String>>,
    input_txids: Vec<String>,
}

impl BeefTx {
    fn from_tx(t: TxRef, bump_index: Option<usize>) -> Result<BeefTx> {
        let mut b = BeefTx {
            bump_index,
            tx: RefCell::new(Some(t)),
            raw: None,
            txid: RefCell::new(None),
            input_txids: vec![],
        };
        b.update_input_txids()?;
        Ok(b)
    }
    fn from_raw(
        raw: Vec<u8>,
        bump_index: Option<usize>,
        input_txids: Option<Vec<String>>,
    ) -> Result<BeefTx> {
        let mut b = BeefTx {
            bump_index,
            tx: RefCell::new(None),
            raw: Some(raw),
            txid: RefCell::new(None),
            input_txids: vec![],
        };
        if b.has_proof() {
            b.input_txids = vec![];
        } else if let Some(ids) = input_txids {
            b.input_txids = ids;
        } else {
            b.update_input_txids()?;
        }
        Ok(b)
    }
    fn txid_only(txid: String) -> BeefTx {
        BeefTx {
            bump_index: None,
            tx: RefCell::new(None),
            raw: None,
            txid: RefCell::new(Some(txid)),
            input_txids: vec![],
        }
    }
    pub fn has_proof(&self) -> bool {
        self.bump_index.is_some()
    }
    pub fn is_txid_only(&self) -> bool {
        self.txid.borrow().as_deref().is_some_and(|s| !s.is_empty())
            && self.raw.is_none()
            && self.tx.borrow().is_none()
    }
    pub fn bump_index(&self) -> Option<usize> {
        self.bump_index
    }
    fn set_bump_index(&mut self, i: Option<usize>) -> Result<()> {
        self.bump_index = i;
        self.update_input_txids()
    }
    /// `txid`.
    pub fn txid(&self) -> Result<String> {
        if let Some(t) = self.txid.borrow().as_ref().filter(|s| !s.is_empty()) {
            return Ok(t.clone());
        }
        let id = if let Some(t) = self.tx.borrow().as_ref() {
            t.borrow().id()?
        } else if let Some(r) = &self.raw {
            hex_encode(&reversed(&sha256d(r)))
        } else {
            return err("Internal");
        };
        *self.txid.borrow_mut() = Some(id.clone());
        Ok(id)
    }
    /// `tx`: the parsed transaction (None for a txid-only entry).
    pub fn tx(&self) -> Result<Option<TxRef>> {
        if let Some(t) = self.tx.borrow().as_ref() {
            return Ok(Some(t.clone()));
        }
        if let Some(r) = &self.raw {
            let t = tx_ref(Transaction::from_binary(r)?);
            *self.tx.borrow_mut() = Some(t.clone());
            return Ok(Some(t));
        }
        Ok(None)
    }
    fn raw_bytes(&self) -> Result<Option<Vec<u8>>> {
        if let Some(t) = self.tx.borrow().as_ref() {
            return Ok(Some(t.borrow().to_binary()?));
        }
        Ok(self.raw.clone())
    }
    fn update_input_txids(&mut self) -> Result<()> {
        if self.has_proof() {
            self.input_txids = vec![];
        } else if let Some(t) = self.tx.borrow().as_ref() {
            let mut seen = HashSet::new();
            self.input_txids = vec![];
            for i in &t.borrow().inputs {
                if let Some(id) = i.source_txid.as_ref().filter(|s| !s.is_empty()) {
                    if seen.insert(id.clone()) {
                        self.input_txids.push(id.clone());
                    }
                }
            }
        } else if let Some(r) = &self.raw {
            let (_, ids) = scan_raw_transaction(&mut Reader::new(r))?;
            self.input_txids = ids;
        } else {
            self.input_txids = vec![];
        }
        Ok(())
    }
}

fn skip_bytes(r: &mut Reader, n: u64) -> Result<()> {
    if n > (r.b.len() - r.pos) as u64 {
        return err("Serialized transaction exceeds available BEEF data");
    }
    r.pos += n as usize;
    Ok(())
}

fn scan_raw_transaction(r: &mut Reader) -> Result<(Vec<u8>, Vec<String>)> {
    let start = r.pos;
    skip_bytes(r, 4)?;
    let n = r.varint_strict()?;
    let mut seen = HashSet::new();
    let mut ids = vec![];
    for _ in 0..n {
        let id = hex_encode(&reversed(&r.read(32)?));
        if seen.insert(id.clone()) {
            ids.push(id);
        }
        skip_bytes(r, 4)?;
        let sl = r.varint_strict()?;
        skip_bytes(r, sl.saturating_add(4))?;
    }
    let n = r.varint_strict()?;
    for _ in 0..n {
        skip_bytes(r, 8)?;
        let sl = r.varint_strict()?;
        skip_bytes(r, sl)?;
    }
    skip_bytes(r, 4)?;
    Ok((r.b[start..r.pos].to_vec(), ids))
}

/// A TS Beef.
pub struct Beef {
    pub version: u32,
    pub bumps: Vec<MpRef>,
    pub txs: Vec<BeefTx>,
    pub atomic_txid: Option<String>,
}

/// sortTxs' result.
pub struct SortResult {
    pub missing_inputs: Vec<String>,
    pub not_valid: Vec<String>,
    pub valid: Vec<String>,
    pub with_missing_inputs: Vec<String>,
    pub txid_only: Vec<String>,
}

impl Beef {
    pub fn new(version: u32) -> Beef {
        Beef {
            version,
            bumps: vec![],
            txs: vec![],
            atomic_txid: None,
        }
    }

    /// `Beef.fromBinary` (prefix parser: trailing bytes are ignored).
    pub fn from_binary(b: &[u8]) -> Result<Beef> {
        let mut r = Reader::new(b);
        let mut version = r.u32()?;
        let mut atomic = None;
        if version == ATOMIC_BEEF {
            atomic = Some(hex_encode(&reversed(&r.read(32)?)));
            version = r.u32()?;
        }
        if version != BEEF_V1 && version != BEEF_V2 {
            return err(format!(
                "Serialized BEEF must start with {BEEF_V1} or {BEEF_V2} but starts with {version}"
            ));
        }
        let mut beef = Beef::new(version);
        for _ in 0..r.varint_strict()? {
            beef.bumps
                .push(Rc::new(RefCell::new(MerklePath::from_reader(
                    &mut r, false,
                )?)));
        }
        for _ in 0..r.varint_strict()? {
            beef.txs.push(beef_tx_from_reader(&mut r, version)?);
        }
        beef.atomic_txid = atomic;
        Ok(beef)
    }

    /// `findTxid` (the last entry with that txid).
    pub fn find_txid(&self, txid: &str) -> Result<Option<&BeefTx>> {
        let mut hit = None;
        for t in &self.txs {
            if t.txid()? == txid {
                hit = Some(t);
            }
        }
        Ok(hit)
    }

    fn bump_index_for(&self, txid: &str) -> Option<usize> {
        let mut hit = None;
        for (i, mp) in self.bumps.iter().enumerate() {
            if mp.borrow().path[0]
                .iter()
                .any(|l| l.hash.as_deref() == Some(txid))
            {
                hit = Some(i);
            }
        }
        hit
    }

    /// `findBump`: the LAST bump with a level-0 leaf whose hash is txid.
    pub fn find_bump(&self, txid: &str) -> Option<MpRef> {
        self.bump_index_for(txid).map(|i| self.bumps[i].clone())
    }

    /// `findAtomicTransaction`: the tx with its inputs' sources and merkle paths wired in.
    pub fn find_atomic_transaction(&self, txid: &str) -> Result<Option<TxRef>> {
        let root = match self.find_txid(txid)? {
            Some(bt) => match bt.tx()? {
                Some(t) => t,
                None => return Ok(None),
            },
            None => return Ok(None),
        };
        let mut visited = HashSet::new();
        let mut stack = vec![root.clone()];
        while let Some(cur) = stack.pop() {
            let id = cur.borrow().id()?;
            if !visited.insert(id.clone()) {
                continue;
            }
            if let Some(mp) = self.find_bump(&id) {
                cur.borrow_mut().merkle_path = Some(mp);
                continue;
            }
            let n = cur.borrow().inputs.len();
            for k in 0..n {
                let (has_src, sid) = {
                    let c = cur.borrow();
                    (
                        c.inputs[k].source_transaction.is_some(),
                        c.inputs[k].source_txid.clone(),
                    )
                };
                if !has_src {
                    let sid = sid.ok_or_else(|| Error("sourceTXID must be valid".into()))?;
                    if let Some(it) = self.find_txid(&sid)? {
                        cur.borrow_mut().inputs[k].source_transaction = it.tx()?;
                    }
                }
                if let Some(s) = cur.borrow().inputs[k].source_transaction.clone() {
                    stack.push(s);
                }
            }
        }
        Ok(Some(root))
    }

    /// `sortTxs`: reorders txs (unsortable, txidOnly, then dependency order with proven first).
    pub fn sort_txs(&mut self) -> Result<SortResult> {
        let mut valid: HashSet<String> = HashSet::new();
        let mut valid_order = vec![];
        let mut by_id: HashMap<String, usize> = HashMap::new();
        let (mut result, mut txid_only, mut queue) = (vec![], vec![], vec![]);
        for (i, t) in self.txs.iter().enumerate() {
            let id = t.txid()?;
            by_id.insert(id.clone(), i);
            if t.has_proof() {
                if valid.insert(id.clone()) {
                    valid_order.push(id.clone());
                }
                result.push(i);
            } else if t.is_txid_only() && t.input_txids.is_empty() {
                if valid.insert(id.clone()) {
                    valid_order.push(id.clone());
                }
                txid_only.push(i);
            } else {
                queue.push(i);
            }
        }
        let mut missing = vec![];
        let mut missing_set = HashSet::new();
        let (mut with_missing, mut remaining) = (vec![], vec![]);
        for &i in &queue {
            let mut has = false;
            for id in &self.txs[i].input_txids {
                if !by_id.contains_key(id) {
                    if missing_set.insert(id.clone()) {
                        missing.push(id.clone());
                    }
                    has = true;
                }
            }
            if has {
                with_missing.push(i)
            } else {
                remaining.push(i)
            }
        }
        let queue = remaining;
        let ids: Vec<String> = queue
            .iter()
            .map(|&i| self.txs[i].txid())
            .collect::<Result<_>>()?;
        let candidates: HashSet<&String> = ids.iter().collect();
        let original: HashMap<&String, usize> =
            ids.iter().enumerate().map(|(k, id)| (id, k)).collect();
        let mut indegree: HashMap<String, i64> = HashMap::new();
        let mut dependents: HashMap<String, Vec<usize>> = HashMap::new();
        let mut round: HashMap<String, usize> = HashMap::new();
        for (k, &i) in queue.iter().enumerate() {
            let mut deg = 0;
            for id in &self.txs[i].input_txids {
                if valid.contains(id) {
                    continue;
                }
                deg += 1;
                if candidates.contains(id) {
                    dependents.entry(id.clone()).or_default().push(k);
                }
            }
            indegree.insert(ids[k].clone(), deg);
            round.insert(ids[k].clone(), 0);
        }
        let mut ready: Vec<usize> = (0..queue.len())
            .filter(|&k| indegree[&ids[k]] == 0)
            .collect();
        let mut processed = HashSet::new();
        let mut p = 0;
        while p < ready.len() {
            let k = ready[p];
            p += 1;
            if !processed.insert(ids[k].clone()) {
                continue;
            }
            for &d in dependents.get(&ids[k]).cloned().unwrap_or_default().iter() {
                let mut next = round[&ids[k]];
                if original[&ids[k]] > original[&ids[d]] {
                    next += 1;
                }
                let r = round.get_mut(&ids[d]).unwrap();
                if next > *r {
                    *r = next;
                }
                let deg = indegree.get_mut(&ids[d]).unwrap();
                *deg -= 1;
                if *deg == 0 {
                    ready.push(d);
                }
            }
        }
        let mut by_round: Vec<Vec<usize>> = vec![];
        for (k, &i) in queue.iter().enumerate() {
            if !processed.contains(&ids[k]) {
                continue;
            }
            let r = round[&ids[k]];
            while by_round.len() <= r {
                by_round.push(vec![]);
            }
            by_round[r].push(i);
        }
        for bucket in &by_round {
            for &i in bucket {
                let id = self.txs[i].txid()?;
                if valid.insert(id.clone()) {
                    valid_order.push(id);
                }
                result.push(i);
            }
        }
        let not_valid: Vec<usize> = queue
            .iter()
            .enumerate()
            .filter(|(k, _)| !processed.contains(&ids[*k]))
            .map(|(_, &i)| i)
            .collect();
        let order: Vec<usize> = with_missing
            .iter()
            .chain(&not_valid)
            .chain(&txid_only)
            .chain(&result)
            .copied()
            .collect();
        let names = |l: &[usize], txs: &[BeefTx]| -> Result<Vec<String>> {
            l.iter().map(|&i| txs[i].txid()).collect()
        };
        let sr = SortResult {
            missing_inputs: missing,
            not_valid: names(&not_valid, &self.txs)?,
            valid: valid_order,
            with_missing_inputs: names(&with_missing, &self.txs)?,
            txid_only: names(&txid_only, &self.txs)?,
        };
        let old = std::mem::take(&mut self.txs);
        let mut slots: Vec<Option<BeefTx>> = old.into_iter().map(Some).collect();
        self.txs = order.iter().map(|&i| slots[i].take().unwrap()).collect();
        Ok(sr)
    }

    fn has_matching_bump(&self, t: &BeefTx) -> Result<bool> {
        match t.bump_index {
            Some(i) if i < self.bumps.len() => {
                let id = t.txid()?;
                Ok(self.bumps[i].borrow().path[0]
                    .iter()
                    .any(|l| l.hash.as_deref() == Some(id.as_str())))
            }
            _ => Ok(false),
        }
    }

    fn collect_atomic(
        &self,
        subject: usize,
        by_id: &HashMap<String, usize>,
    ) -> Result<HashSet<usize>> {
        let mut included = HashSet::new();
        let mut stack = vec![subject];
        while let Some(i) = stack.pop() {
            if !included.insert(i) {
                continue;
            }
            let t = &self.txs[i];
            if self.has_matching_bump(t)? || t.is_txid_only() {
                continue;
            }
            for id in &t.input_txids {
                if let Some(&k) = by_id.get(id) {
                    stack.push(k);
                }
            }
        }
        Ok(included)
    }

    fn tx_index(&self) -> Result<HashMap<String, usize>> {
        let mut m = HashMap::new();
        for (i, t) in self.txs.iter().enumerate() {
            m.insert(t.txid()?, i);
        }
        Ok(m)
    }

    /// `isAtomic(txid)`.
    pub fn is_atomic(&self, txid: &str) -> Result<bool> {
        if txid.is_empty() {
            return Ok(false);
        }
        let by_id = self.tx_index()?;
        if by_id.len() != self.txs.len() {
            return Ok(false);
        }
        match by_id.get(txid) {
            None => Ok(false),
            Some(&s) => Ok(self.collect_atomic(s, &by_id)?.len() == self.txs.len()),
        }
    }

    /// `isValid(allowTxidOnly)`: sorts txs, as the TS does; an error where the TS throws.
    pub fn is_valid(&mut self, allow_txid_only: bool) -> Result<bool> {
        if let Some(a) = self.atomic_txid.clone() {
            if !self.is_atomic(&a)? {
                return Ok(false);
            }
        }
        let sr = self.sort_txs()?;
        let mut seen = HashSet::new();
        for t in &self.txs {
            if !seen.insert(t.txid()?) {
                return Ok(false);
            }
        }
        if !sr.missing_inputs.is_empty()
            || !sr.not_valid.is_empty()
            || (!sr.txid_only.is_empty() && !allow_txid_only)
            || !sr.with_missing_inputs.is_empty()
        {
            return Ok(false);
        }
        let mut txids: HashSet<String> = HashSet::new();
        for t in &self.txs {
            if !t.is_txid_only() {
                continue;
            }
            if !allow_txid_only {
                return Ok(false);
            }
            txids.insert(t.txid()?);
        }
        let mut roots: HashMap<u64, String> = HashMap::new();
        for mp in &self.bumps {
            let mp = mp.borrow();
            for n in &mp.path[0] {
                let h = match n.hash.as_deref() {
                    Some(h) if n.txid && !h.is_empty() => h,
                    _ => continue,
                };
                txids.insert(h.to_string());
                let root = mp.compute_root(h)?;
                let e = roots.entry(mp.block_height).or_default();
                if e.is_empty() {
                    *e = root.clone();
                }
                if *e != root {
                    return Ok(false);
                }
            }
        }
        for t in &self.txs {
            if let Some(i) = t.bump_index {
                if i >= self.bumps.len() {
                    return Ok(false);
                }
                let id = t.txid()?;
                if !self.bumps[i].borrow().path[0]
                    .iter()
                    .any(|l| l.hash.as_deref() == Some(id.as_str()))
                {
                    return Ok(false);
                }
            }
        }
        for t in &self.txs {
            for id in &t.input_txids {
                if !txids.contains(id) {
                    return Ok(false);
                }
            }
            txids.insert(t.txid()?);
        }
        Ok(true)
    }

    fn replace_or_append(&mut self, t: BeefTx) -> Result<usize> {
        let id = t.txid()?;
        for (i, e) in self.txs.iter().enumerate() {
            if e.txid()? == id {
                self.txs[i] = t;
                return Ok(i);
            }
        }
        self.txs.push(t);
        Ok(self.txs.len() - 1)
    }

    fn try_to_validate_bump_index(&mut self, k: usize) -> Result<()> {
        if self.txs[k].bump_index.is_some() {
            return Ok(());
        }
        let id = self.txs[k].txid()?;
        if let Some(i) = self.bump_index_for(&id) {
            self.txs[k].set_bump_index(Some(i))?;
            let mut mp = self.bumps[i].borrow_mut();
            if let Some(l) = mp.path[0]
                .iter_mut()
                .find(|l| l.hash.as_deref() == Some(id.as_str()))
            {
                l.txid = true;
            }
        }
        Ok(())
    }

    fn merge_bump_entry(&mut self, bump: MpRef) -> Result<usize> {
        let mut index = None;
        for (i, existing) in self.bumps.iter().enumerate() {
            if existing.borrow().block_height != bump.borrow().block_height {
                continue;
            }
            let root = bump.borrow().compute_root("")?;
            if existing.borrow().compute_root("")? != root {
                continue;
            }
            if !Rc::ptr_eq(existing, &bump) {
                let other = bump.borrow().clone();
                existing.borrow_mut().combine(&other)?;
            } else {
                let other = bump.borrow().clone();
                bump.borrow_mut().combine(&other)?;
            }
            index = Some(i);
            break;
        }
        let index = match index {
            Some(i) => i,
            None => {
                self.bumps.push(bump);
                self.bumps.len() - 1
            }
        };
        let by_id = self.tx_index()?;
        let hashes: Vec<String> = self.bumps[index].borrow().path[0]
            .iter()
            .filter_map(|l| l.hash.clone())
            .collect();
        for h in hashes {
            if let Some(&k) = by_id.get(&h) {
                if self.txs[k].bump_index.is_none() {
                    self.txs[k].set_bump_index(Some(index))?;
                    let mut mp = self.bumps[index].borrow_mut();
                    if let Some(n) = mp.path[0]
                        .iter_mut()
                        .find(|n| n.hash.as_deref() == Some(h.as_str()))
                    {
                        n.txid = true;
                    }
                }
            }
        }
        Ok(index)
    }

    /// `mergeTransaction(tx)`: tx and its attached ancestry (stopping at proven txs).
    pub fn merge_transaction(&mut self, tx: &TxRef) -> Result<()> {
        fill_source_txids(tx, &mut HashSet::new())?;
        let root_id = tx.borrow().id()?;
        let mut visited = HashSet::new();
        let mut stack = vec![tx.clone()];
        let mut root = false;
        while let Some(cur) = stack.pop() {
            let id = cur.borrow().id()?;
            if !visited.insert(id.clone()) {
                continue;
            }
            let mp = cur.borrow().merkle_path.clone();
            let bump_index = match mp {
                Some(mp) => Some(self.merge_bump_entry(mp)?),
                None => None,
            };
            let nt = BeefTx::from_tx(cur.clone(), bump_index)?;
            let k = self.replace_or_append(nt)?;
            self.try_to_validate_bump_index(k)?;
            if id == root_id {
                root = true;
            }
            if self.txs[k].bump_index.is_none() {
                let c = cur.borrow();
                for i in c.inputs.iter().rev() {
                    if let Some(s) = &i.source_transaction {
                        stack.push(s.clone());
                    }
                }
            }
        }
        if !root {
            return err("Failed to merge root transaction");
        }
        Ok(())
    }

    fn to_writer(&self, w: &mut Writer) -> Result<()> {
        w.u32(self.version);
        w.varint(self.bumps.len() as u64);
        for mp in &self.bumps {
            w.bytes(&mp.borrow().to_binary());
        }
        w.varint(self.txs.len() as u64);
        for t in &self.txs {
            let raw = |w: &mut Writer| -> Result<()> {
                match t.raw_bytes()? {
                    Some(b) => {
                        w.bytes(&b);
                        Ok(())
                    }
                    None => err("a valid serialized Transaction is expected"),
                }
            };
            if self.version == BEEF_V2 {
                if t.is_txid_only() {
                    w.0.push(2);
                    w.bytes(&reversed(&js_hex_to_array(&t.txid()?)?));
                } else if let Some(i) = t.bump_index {
                    w.0.push(1);
                    w.varint(i as u64);
                    raw(w)?;
                } else {
                    w.0.push(0);
                    raw(w)?;
                }
            } else {
                raw(w)?;
                match t.bump_index {
                    None => w.0.push(0),
                    Some(i) => {
                        w.0.push(1);
                        w.varint(i as u64);
                    }
                }
            }
        }
        Ok(())
    }

    /// `toBinaryAtomic(txid)`.
    pub fn to_binary_atomic(&self, txid: &str) -> Result<Vec<u8>> {
        let by_id = self.tx_index()?;
        let subject = *by_id
            .get(txid)
            .ok_or_else(|| Error(format!("{txid} does not exist in this Beef")))?;
        let included = self.collect_atomic(subject, &by_id)?;
        let mut nb = Beef::new(self.version);
        let mut bump_map: HashMap<usize, usize> = HashMap::new();
        for (i, t) in self.txs.iter().enumerate() {
            if !included.contains(&i) || !self.has_matching_bump(t)? {
                continue;
            }
            if let Some(b) = t.bump_index {
                if let std::collections::hash_map::Entry::Vacant(e) = bump_map.entry(b) {
                    e.insert(nb.bumps.len());
                    nb.bumps.push(self.bumps[b].clone());
                }
            }
        }
        for (i, t) in self.txs.iter().enumerate() {
            if !included.contains(&i) {
                continue;
            }
            let bi = t.bump_index.and_then(|b| bump_map.get(&b).copied());
            let c = if let Some(r) = &t.raw {
                BeefTx::from_raw(r.clone(), bi, Some(t.input_txids.clone()))?
            } else if let Some(tx) = t.tx.borrow().clone() {
                BeefTx::from_tx(tx, bi)?
            } else {
                let mut b = BeefTx::txid_only(t.txid()?);
                b.bump_index = bi;
                b
            };
            nb.txs.push(c);
        }
        nb.sort_txs()?;
        let mut w = Writer::default();
        nb.to_writer(&mut w)?;
        let mut out = ATOMIC_BEEF.to_le_bytes().to_vec();
        out.extend(reversed(&js_hex_to_array(txid)?));
        out.extend(w.0);
        Ok(out)
    }

    /// The txs' parsed transactions and bump presence, for b017's checks after isValid.
    pub fn entries(&self) -> Result<Vec<(String, Option<TxRef>, bool)>> {
        self.txs
            .iter()
            .map(|t| Ok((t.txid()?, t.tx()?, t.bump_index.is_some())))
            .collect()
    }
}

fn beef_tx_from_reader(r: &mut Reader, version: u32) -> Result<BeefTx> {
    if version == BEEF_V2 {
        let format = r.u8()?;
        if format == 2 {
            return Ok(BeefTx::txid_only(hex_encode(&reversed(&r.read(32)?))));
        }
        let bump = if format == 1 {
            Some(r.varint_strict()? as usize)
        } else {
            None
        };
        let (raw, ids) = scan_raw_transaction(r)?;
        return BeefTx::from_raw(raw, bump, Some(ids));
    }
    let (raw, ids) = scan_raw_transaction(r)?;
    let bump = if r.u8()? != 0 {
        Some(r.varint_strict()? as usize)
    } else {
        None
    };
    BeefTx::from_raw(raw, bump, Some(ids))
}

/// Fill every input's sourceTXID from its attached source, across the attached graph.
pub fn fill_source_txids(
    tx: &TxRef,
    seen: &mut HashSet<*const RefCell<Transaction>>,
) -> Result<()> {
    if !seen.insert(Rc::as_ptr(tx)) {
        return Ok(());
    }
    let n = tx.borrow().inputs.len();
    for k in 0..n {
        let src = tx.borrow().inputs[k].source_transaction.clone();
        if let Some(s) = src {
            if tx.borrow().inputs[k].source_txid.is_none() {
                let id = s.borrow().id()?;
                tx.borrow_mut().inputs[k].source_txid = Some(id);
            }
            fill_source_txids(&s, seen)?;
        }
    }
    Ok(())
}
