package b017

// beefsdk.go - the parts of @bsv/sdk 2.8.11 `Beef` / `BeefTx` (src/transaction/Beef.ts, BeefTx.ts) b017 uses:
// parse (V1, V2, Atomic), isValid (which SORTS the txs, so order-dependent checks after it see the sorted order),
// findAtomicTransaction, mergeTransaction, toBinaryAtomic. Order matters to b017 (its BEEF errors name the first
// offending tx; the bytes it emits must match), so this follows the reference instead of go-sdk's map-based Beef.

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	BEEF_V1     = 4022206465
	BEEF_V2     = 4022206466
	ATOMIC_BEEF = 0x01010101

	txFormatRaw         = 0
	txFormatRawAndBump  = 1
	txFormatTxidOnly    = 2
)

// BeefTx is a TS BeefTx.
type BeefTx struct {
	bumpIndex  *int
	tx         *Transaction
	rawTx      []byte
	txid       string
	inputTxids []string
}

func newBeefTxFromTx(t *Transaction, bumpIndex *int) *BeefTx {
	b := &BeefTx{tx: t, bumpIndex: bumpIndex}
	b.updateInputTxids()
	return b
}

func newBeefTxFromRaw(raw []byte, bumpIndex *int, inputTxids []string) *BeefTx {
	b := &BeefTx{rawTx: raw, bumpIndex: bumpIndex}
	if b.HasProof() {
		b.inputTxids = []string{}
	} else if inputTxids != nil {
		b.inputTxids = append([]string{}, inputTxids...)
	} else {
		b.updateInputTxids()
	}
	return b
}

// HasProof is `hasProof`.
func (b *BeefTx) HasProof() bool { return b.bumpIndex != nil }

// IsTxidOnly is `isTxidOnly`.
func (b *BeefTx) IsTxidOnly() bool { return b.txid != "" && b.rawTx == nil && b.tx == nil }

// BumpIndex returns the bump index (TS `bumpIndex`, undefined = nil).
func (b *BeefTx) BumpIndex() *int { return b.bumpIndex }

func (b *BeefTx) setBumpIndex(i *int) {
	b.bumpIndex = i
	b.updateInputTxids()
}

// Txid is `txid`.
func (b *BeefTx) Txid() string {
	if b.txid != "" {
		return b.txid
	}
	if b.tx != nil {
		b.txid = b.tx.MustID()
		return b.txid
	}
	if b.rawTx != nil {
		b.txid = hex.EncodeToString(reverse(sha256d(b.rawTx)))
		return b.txid
	}
	panic(errors.New("Internal"))
}

// Tx is `tx`: the parsed transaction (nil for a txid-only entry).
func (b *BeefTx) Tx() *Transaction {
	if b.tx != nil {
		return b.tx
	}
	if b.rawTx != nil {
		t, err := TransactionFromBinary(b.rawTx)
		if err != nil {
			panic(err)
		}
		b.tx = t
		return t
	}
	return nil
}

func (b *BeefTx) rawBytes() ([]byte, error) {
	if b.tx != nil {
		return b.tx.ToBinary()
	}
	return b.rawTx, nil
}

func (b *BeefTx) updateInputTxids() {
	switch {
	case b.HasProof():
		b.inputTxids = []string{}
	case b.tx != nil:
		seen := map[string]bool{}
		b.inputTxids = []string{}
		for _, in := range b.tx.Inputs {
			if in.SourceTXID != "" && !seen[in.SourceTXID] {
				seen[in.SourceTXID] = true
				b.inputTxids = append(b.inputTxids, in.SourceTXID)
			}
		}
	case b.rawTx != nil:
		_, ids, err := scanRawTransaction(&reader{b: b.rawTx})
		if err != nil {
			panic(err)
		}
		b.inputTxids = ids
	default:
		b.inputTxids = []string{}
	}
}

func skipBytes(r *reader, n uint64) error {
	if n > uint64(len(r.b)-r.pos) {
		return errors.New("Serialized transaction exceeds available BEEF data")
	}
	r.pos += int(n)
	return nil
}

func scanRawTransaction(r *reader) ([]byte, []string, error) {
	start := r.pos
	if err := skipBytes(r, 4); err != nil {
		return nil, nil, err
	}
	n, err := r.varintStrict()
	if err != nil {
		return nil, nil, err
	}
	seen := map[string]bool{}
	ids := []string{}
	for i := uint64(0); i < n; i++ {
		id, err := r.read(32)
		if err != nil {
			return nil, nil, err
		}
		s := hex.EncodeToString(reverse(id))
		if !seen[s] {
			seen[s] = true
			ids = append(ids, s)
		}
		if err := skipBytes(r, 4); err != nil {
			return nil, nil, err
		}
		sl, err := r.varintStrict()
		if err != nil {
			return nil, nil, err
		}
		if err := skipBytes(r, sl+4); err != nil {
			return nil, nil, err
		}
	}
	n, err = r.varintStrict()
	if err != nil {
		return nil, nil, err
	}
	for i := uint64(0); i < n; i++ {
		if err := skipBytes(r, 8); err != nil {
			return nil, nil, err
		}
		sl, err := r.varintStrict()
		if err != nil {
			return nil, nil, err
		}
		if err := skipBytes(r, sl); err != nil {
			return nil, nil, err
		}
	}
	if err := skipBytes(r, 4); err != nil {
		return nil, nil, err
	}
	return clone(r.b[start:r.pos]), ids, nil
}

// Beef is a TS Beef.
type Beef struct {
	Version    uint32
	Bumps      []*MerklePath
	Txs        []*BeefTx
	AtomicTxid string
}

// NewBeef is `new Beef(version)`.
func NewBeef(version uint32) *Beef { return &Beef{Version: version} }

// BeefFromBinary is `Beef.fromBinary` (prefix parser: trailing bytes are ignored).
func BeefFromBinary(b []byte) (*Beef, error) {
	r := &reader{b: b}
	version, err := r.u32()
	if err != nil {
		return nil, err
	}
	atomic := ""
	if version == ATOMIC_BEEF {
		id, err := r.read(32)
		if err != nil {
			return nil, err
		}
		atomic = hex.EncodeToString(reverse(id))
		if version, err = r.u32(); err != nil {
			return nil, err
		}
	}
	if version != BEEF_V1 && version != BEEF_V2 {
		return nil, fmt.Errorf("Serialized BEEF must start with %d or %d but starts with %d", BEEF_V1, BEEF_V2, version)
	}
	beef := NewBeef(version)
	nb, err := r.varintStrict()
	if err != nil {
		return nil, err
	}
	for i := uint64(0); i < nb; i++ {
		mp, err := merklePathFromReader(r, false)
		if err != nil {
			return nil, err
		}
		beef.Bumps = append(beef.Bumps, mp)
	}
	nt, err := r.varintStrict()
	if err != nil {
		return nil, err
	}
	for i := uint64(0); i < nt; i++ {
		bt, err := beefTxFromReader(r, version)
		if err != nil {
			return nil, err
		}
		beef.Txs = append(beef.Txs, bt)
	}
	beef.AtomicTxid = atomic
	return beef, nil
}

func beefTxFromReader(r *reader, version uint32) (*BeefTx, error) {
	if version == BEEF_V2 {
		format, err := r.u8()
		if err != nil {
			return nil, err
		}
		if format == txFormatTxidOnly {
			id, err := r.read(32)
			if err != nil {
				return nil, err
			}
			return &BeefTx{txid: hex.EncodeToString(reverse(id)), inputTxids: []string{}}, nil
		}
		var bump *int
		if format == txFormatRawAndBump {
			v, err := r.varintStrict()
			if err != nil {
				return nil, err
			}
			iv := int(v)
			bump = &iv
		}
		raw, ids, err := scanRawTransaction(r)
		if err != nil {
			return nil, err
		}
		return newBeefTxFromRaw(raw, bump, ids), nil
	}
	raw, ids, err := scanRawTransaction(r)
	if err != nil {
		return nil, err
	}
	has, err := r.u8()
	if err != nil {
		return nil, err
	}
	var bump *int
	if has != 0 {
		v, err := r.varintStrict()
		if err != nil {
			return nil, err
		}
		iv := int(v)
		bump = &iv
	}
	return newBeefTxFromRaw(raw, bump, ids), nil
}

// FindTxid is `findTxid` (the last entry with that txid, as the TS index keeps the last).
func (b *Beef) FindTxid(txid string) *BeefTx {
	var hit *BeefTx
	for _, t := range b.Txs {
		if t.Txid() == txid {
			hit = t
		}
	}
	return hit
}

// FindBump is `findBump`: the LAST bump with any level-0 leaf whose hash is txid.
func (b *Beef) FindBump(txid string) *MerklePath {
	var hit *MerklePath
	for _, mp := range b.Bumps {
		for _, l := range mp.Path[0] {
			if l.HasHash && l.Hash == txid {
				hit = mp
			}
		}
	}
	return hit
}

func (b *Beef) bumpIndexFor(txid string) *int {
	var hit *int
	for i, mp := range b.Bumps {
		for _, l := range mp.Path[0] {
			if l.HasHash && l.Hash == txid {
				iv := i
				hit = &iv
			}
		}
	}
	return hit
}

// FindAtomicTransaction is `findAtomicTransaction`: the tx with its inputs' sources and merkle paths wired in.
func (b *Beef) FindAtomicTransaction(txid string) *Transaction {
	bt := b.FindTxid(txid)
	if bt == nil || bt.Tx() == nil {
		return nil
	}
	visited := map[string]bool{}
	stack := []*Transaction{bt.Tx()}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		id := cur.MustID()
		if visited[id] {
			continue
		}
		visited[id] = true
		if mp := b.FindBump(id); mp != nil {
			cur.MerklePath = mp
			continue
		}
		for _, in := range cur.Inputs {
			if in.SourceTransaction == nil {
				if in.SourceTXID == "" {
					panic(errors.New("sourceTXID must be valid"))
				}
				if it := b.FindTxid(in.SourceTXID); it != nil {
					in.SourceTransaction = it.Tx()
				}
			}
			if in.SourceTransaction != nil {
				stack = append(stack, in.SourceTransaction)
			}
		}
	}
	return bt.Tx()
}

// SortResult is sortTxs' result.
type SortResult struct {
	MissingInputs, NotValid, Valid, WithMissingInputs, TxidOnly []string
}

// SortTxs is `sortTxs`: reorders Txs (unsortable, txidOnly, then dependency order with proven first).
func (b *Beef) SortTxs() SortResult {
	valid := map[string]bool{}
	validOrder := []string{}
	markValid := func(id string) {
		if !valid[id] {
			valid[id] = true
			validOrder = append(validOrder, id)
		}
	}
	byID := map[string]*BeefTx{}
	var result, txidOnly, queue []*BeefTx
	for _, t := range b.Txs {
		byID[t.Txid()] = t
		if t.HasProof() {
			markValid(t.Txid())
			result = append(result, t)
		} else if t.IsTxidOnly() && len(t.inputTxids) == 0 {
			markValid(t.Txid())
			txidOnly = append(txidOnly, t)
		} else {
			queue = append(queue, t)
		}
	}
	missing := map[string]bool{}
	missingOrder := []string{}
	var withMissing, remaining []*BeefTx
	for _, t := range queue {
		has := false
		for _, id := range t.inputTxids {
			if byID[id] == nil {
				if !missing[id] {
					missing[id] = true
					missingOrder = append(missingOrder, id)
				}
				has = true
			}
		}
		if has {
			withMissing = append(withMissing, t)
		} else {
			remaining = append(remaining, t)
		}
	}
	queue = remaining
	// topoSort
	candidates := map[string]bool{}
	originalIndex := map[string]int{}
	for i, t := range queue {
		candidates[t.Txid()] = true
		originalIndex[t.Txid()] = i
	}
	indegree := map[string]int{}
	dependents := map[string][]*BeefTx{}
	round := map[string]int{}
	for _, t := range queue {
		deg := 0
		for _, id := range t.inputTxids {
			if valid[id] {
				continue
			}
			deg++
			if candidates[id] {
				dependents[id] = append(dependents[id], t)
			}
		}
		indegree[t.Txid()] = deg
		round[t.Txid()] = 0
	}
	var ready []*BeefTx
	for _, t := range queue {
		if indegree[t.Txid()] == 0 {
			ready = append(ready, t)
		}
	}
	processed := map[string]bool{}
	for k := 0; k < len(ready); k++ {
		t := ready[k]
		if processed[t.Txid()] {
			continue
		}
		processed[t.Txid()] = true
		for _, d := range dependents[t.Txid()] {
			next := round[t.Txid()]
			if originalIndex[t.Txid()] > originalIndex[d.Txid()] {
				next++
			}
			if next > round[d.Txid()] {
				round[d.Txid()] = next
			}
			indegree[d.Txid()]--
			if indegree[d.Txid()] == 0 {
				ready = append(ready, d)
			}
		}
	}
	var byRound [][]*BeefTx
	for _, t := range queue {
		if !processed[t.Txid()] {
			continue
		}
		r := round[t.Txid()]
		for len(byRound) <= r {
			byRound = append(byRound, nil)
		}
		byRound[r] = append(byRound[r], t)
	}
	for _, bucket := range byRound {
		for _, t := range bucket {
			markValid(t.Txid())
			result = append(result, t)
		}
	}
	var notValid []*BeefTx
	for _, t := range queue {
		if !processed[t.Txid()] {
			notValid = append(notValid, t)
		}
	}
	b.Txs = append(append(append(append([]*BeefTx{}, withMissing...), notValid...), txidOnly...), result...)
	ids := func(l []*BeefTx) []string {
		out := []string{}
		for _, t := range l {
			out = append(out, t.Txid())
		}
		return out
	}
	return SortResult{MissingInputs: missingOrder, NotValid: ids(notValid), Valid: validOrder,
		WithMissingInputs: ids(withMissing), TxidOnly: ids(txidOnly)}
}

func (b *Beef) hasMatchingBump(t *BeefTx) bool {
	if t.bumpIndex == nil || *t.bumpIndex < 0 || *t.bumpIndex >= len(b.Bumps) {
		return false
	}
	for _, l := range b.Bumps[*t.bumpIndex].Path[0] {
		if l.HasHash && l.Hash == t.Txid() {
			return true
		}
	}
	return false
}

func (b *Beef) collectAtomic(subject *BeefTx, byID map[string]*BeefTx) map[*BeefTx]bool {
	included := map[*BeefTx]bool{}
	stack := []*BeefTx{subject}
	for len(stack) > 0 {
		t := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if t == nil || included[t] {
			continue
		}
		included[t] = true
		if b.hasMatchingBump(t) || t.IsTxidOnly() {
			continue
		}
		for _, id := range t.inputTxids {
			if in := byID[id]; in != nil {
				stack = append(stack, in)
			}
		}
	}
	return included
}

func (b *Beef) txIndex() map[string]*BeefTx {
	m := map[string]*BeefTx{}
	for _, t := range b.Txs {
		m[t.Txid()] = t
	}
	return m
}

// IsAtomic is `isAtomic(txid)`.
func (b *Beef) IsAtomic(txid string) bool {
	if txid == "" {
		return false
	}
	byID := b.txIndex()
	if len(byID) != len(b.Txs) {
		return false
	}
	subject := byID[txid]
	if subject == nil {
		return false
	}
	return len(b.collectAtomic(subject, byID)) == len(b.Txs)
}

// IsValid is `isValid(allowTxidOnly)` (verifyValid(...).valid). It sorts Txs, as the TS does. It returns an
// error where the TS throws (a merkle path that cannot compute its root).
func (b *Beef) IsValid(allowTxidOnly bool) (bool, error) {
	if b.AtomicTxid != "" && !b.IsAtomic(b.AtomicTxid) {
		return false, nil
	}
	sr := b.SortTxs()
	seen := map[string]bool{}
	for _, t := range b.Txs {
		if seen[t.Txid()] {
			return false, nil
		}
		seen[t.Txid()] = true
	}
	if len(sr.MissingInputs) > 0 || len(sr.NotValid) > 0 || (len(sr.TxidOnly) > 0 && !allowTxidOnly) || len(sr.WithMissingInputs) > 0 {
		return false, nil
	}
	txids := map[string]bool{}
	for _, t := range b.Txs {
		if !t.IsTxidOnly() {
			continue
		}
		if !allowTxidOnly {
			return false, nil
		}
		txids[t.Txid()] = true
	}
	roots := map[uint64]string{}
	for _, mp := range b.Bumps {
		for _, n := range mp.Path[0] {
			if !n.Txid || !n.HasHash || n.Hash == "" {
				continue
			}
			txids[n.Hash] = true
			root, err := mp.ComputeRoot(n.Hash)
			if err != nil {
				return false, err
			}
			if r, ok := roots[mp.BlockHeight]; !ok || r == "" {
				roots[mp.BlockHeight] = root
			}
			if roots[mp.BlockHeight] != root {
				return false, nil
			}
		}
	}
	for _, t := range b.Txs {
		if t.bumpIndex == nil {
			continue
		}
		if *t.bumpIndex < 0 || *t.bumpIndex >= len(b.Bumps) {
			return false, nil
		}
		found := false
		for _, l := range b.Bumps[*t.bumpIndex].Path[0] {
			if l.HasHash && l.Hash == t.Txid() {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}
	for _, t := range b.Txs {
		for _, id := range t.inputTxids {
			if !txids[id] {
				return false, nil
			}
		}
		txids[t.Txid()] = true
	}
	return true, nil
}

// replaceOrAppend is #replaceOrAppendTx.
func (b *Beef) replaceOrAppend(t *BeefTx) {
	for i, e := range b.Txs {
		if e.Txid() == t.Txid() {
			b.Txs[i] = t
			return
		}
	}
	b.Txs = append(b.Txs, t)
}

func (b *Beef) tryToValidateBumpIndex(t *BeefTx) {
	if t.bumpIndex != nil {
		return
	}
	i := b.bumpIndexFor(t.Txid())
	if i == nil {
		return
	}
	t.setBumpIndex(i)
	for _, l := range b.Bumps[*i].Path[0] {
		if l.HasHash && l.Hash == t.Txid() {
			l.Txid = true
			break
		}
	}
}

// mergeBumpEntry is #mergeBumpEntry (with #findOrInsertBump).
func (b *Beef) mergeBumpEntry(bump *MerklePath) (int, error) {
	index := -1
	for i, existing := range b.Bumps {
		if existing.BlockHeight != bump.BlockHeight {
			continue
		}
		root, err := bump.ComputeRoot("")
		if err != nil {
			return 0, err
		}
		er, err := existing.ComputeRoot("")
		if err != nil {
			return 0, err
		}
		if er != root {
			continue
		}
		if err := existing.Combine(bump); err != nil {
			return 0, err
		}
		index = i
		break
	}
	if index < 0 {
		b.Bumps = append(b.Bumps, bump)
		index = len(b.Bumps) - 1
	}
	mp := b.Bumps[index]
	byID := b.txIndex()
	for _, leaf := range mp.Path[0] {
		if !leaf.HasHash {
			continue
		}
		if t := byID[leaf.Hash]; t != nil && t.bumpIndex == nil {
			for _, n := range mp.Path[0] {
				if n.HasHash && n.Hash == t.Txid() {
					iv := index
					t.setBumpIndex(&iv)
					n.Txid = true
					break
				}
			}
		}
	}
	return index, nil
}

// MergeTransaction is `mergeTransaction(tx)`: tx and its attached ancestry (stopping at proven txs).
func (b *Beef) MergeTransaction(tx *Transaction) (*BeefTx, error) {
	fillSourceTxids(tx, map[*Transaction]bool{})
	rootID, err := tx.ID()
	if err != nil {
		return nil, err
	}
	visited := map[string]bool{}
	stack := []*Transaction{tx}
	var root *BeefTx
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		id, err := cur.ID()
		if err != nil {
			return nil, err
		}
		if visited[id] {
			continue
		}
		visited[id] = true
		var bumpIndex *int
		if cur.MerklePath != nil {
			i, err := b.mergeBumpEntry(cur.MerklePath)
			if err != nil {
				return nil, err
			}
			bumpIndex = &i
		}
		nt := newBeefTxFromTx(cur, bumpIndex)
		b.replaceOrAppend(nt)
		b.tryToValidateBumpIndex(nt)
		if id == rootID {
			root = nt
		}
		if nt.bumpIndex == nil {
			for i := len(cur.Inputs) - 1; i >= 0; i-- {
				if s := cur.Inputs[i].SourceTransaction; s != nil {
					stack = append(stack, s)
				}
			}
		}
	}
	if root == nil {
		return nil, errors.New("Failed to merge root transaction")
	}
	return root, nil
}

func (b *Beef) toWriter(w *writer) error {
	w.u32(b.Version)
	w.varint(uint64(len(b.Bumps)))
	for _, mp := range b.Bumps {
		w.bytes(mp.ToBinary())
	}
	w.varint(uint64(len(b.Txs)))
	for _, t := range b.Txs {
		raw := func() error {
			bs, err := t.rawBytes()
			if err != nil {
				return err
			}
			if bs == nil {
				return errors.New("a valid serialized Transaction is expected")
			}
			w.bytes(bs)
			return nil
		}
		if b.Version == BEEF_V2 {
			switch {
			case t.IsTxidOnly():
				w.b = append(w.b, txFormatTxidOnly)
				w.bytes(reverse(jsHexToArray(t.txid)))
			case t.bumpIndex != nil:
				w.b = append(w.b, txFormatRawAndBump)
				w.varint(uint64(*t.bumpIndex))
				if err := raw(); err != nil {
					return err
				}
			default:
				w.b = append(w.b, txFormatRaw)
				if err := raw(); err != nil {
					return err
				}
			}
		} else {
			if err := raw(); err != nil {
				return err
			}
			if t.bumpIndex == nil {
				w.b = append(w.b, 0)
			} else {
				w.b = append(w.b, 1)
				w.varint(uint64(*t.bumpIndex))
			}
		}
	}
	return nil
}

// ToBinaryAtomic is `toBinaryAtomic(txid)`: the subject and its dependency closure, sorted, Atomic prefix.
func (b *Beef) ToBinaryAtomic(txid string) ([]byte, error) {
	byID := b.txIndex()
	subject := byID[txid]
	if subject == nil {
		return nil, fmt.Errorf("%s does not exist in this Beef", txid)
	}
	included := b.collectAtomic(subject, byID)
	nb := NewBeef(b.Version)
	bumpMap := map[int]int{}
	for _, t := range b.Txs {
		if !included[t] || !b.hasMatchingBump(t) || t.bumpIndex == nil {
			continue
		}
		if _, ok := bumpMap[*t.bumpIndex]; !ok {
			bumpMap[*t.bumpIndex] = len(nb.Bumps)
			nb.Bumps = append(nb.Bumps, b.Bumps[*t.bumpIndex])
		}
	}
	for _, t := range b.Txs {
		if !included[t] {
			continue
		}
		var bi *int
		if t.bumpIndex != nil {
			if v, ok := bumpMap[*t.bumpIndex]; ok {
				vv := v
				bi = &vv
			}
		}
		var c *BeefTx
		switch {
		case t.rawTx != nil:
			c = newBeefTxFromRaw(t.rawTx, bi, t.inputTxids)
		case t.tx != nil:
			c = newBeefTxFromTx(t.tx, bi)
		default:
			c = &BeefTx{txid: t.Txid(), bumpIndex: bi, inputTxids: []string{}}
		}
		nb.Txs = append(nb.Txs, c)
	}
	nb.SortTxs()
	w := &writer{}
	if err := nb.toWriter(w); err != nil {
		return nil, err
	}
	out := binary.LittleEndian.AppendUint32(nil, ATOMIC_BEEF)
	out = append(out, reverse(jsHexToArray(txid))...)
	return append(out, w.b...), nil
}

func fillSourceTxids(tx *Transaction, seen map[*Transaction]bool) {
	if seen[tx] {
		return
	}
	seen[tx] = true
	for _, in := range tx.Inputs {
		if in.SourceTransaction == nil {
			continue
		}
		if in.SourceTXID == "" {
			in.SourceTXID = in.SourceTransaction.MustID()
		}
		fillSourceTxids(in.SourceTransaction, seen)
	}
}
