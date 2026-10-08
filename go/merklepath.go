package b017

// merklepath.go - @bsv/sdk 2.8.11 MerklePath (src/transaction/MerklePath.ts): BUMP (BRC-74) parse with the same
// validation, serialisation (the txid flag is part of the bytes), computeRoot, combine and trim. BEEF bytes and
// the anchors' header proofs depend on these, so they follow the reference rather than go-sdk.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"strings"
)

const maxSafeInteger = 1<<53 - 1

// Leaf is a MerklePath leaf. Hash is display-order hex ("" with HasHash false when the leaf only says
// "duplicate"). Txid is the txid flag (TS `txid: true` / absent).
type Leaf struct {
	Offset    uint64
	Hash      string
	HasHash   bool
	Txid      bool
	Duplicate bool
}

// MerklePath is a TS MerklePath.
type MerklePath struct {
	BlockHeight uint64
	Path        [][]*Leaf
}

func offsetAtHeight(offset uint64, height int) uint64 {
	if height >= 64 {
		return 0
	}
	return offset >> uint(height)
}
func siblingOf(offset uint64) uint64 {
	if offset%2 == 0 {
		return offset + 1
	}
	return offset - 1
}
func sameNodeAtHeight(index, maxOffset uint64, height int) bool {
	return offsetAtHeight(index, height) == offsetAtHeight(maxOffset, height)
}
func offsetTreeHeight(offset uint64) int {
	if offset == 0 {
		return 0
	}
	return bits.Len64(offset)
}

// hashPair is the reference's hashPair(left, right) on display-order hex.
func hashPair(left, right string) string {
	b := mustJSHex(left + right)
	return hex.EncodeToString(reverse(sha256d(reverse(b))))
}

// MerklePathFromBinary is `MerklePath.fromBinary(bump, legalOffsetsOnly)` (roots always validated).
func MerklePathFromBinary(b []byte, legalOffsetsOnly bool) (*MerklePath, error) {
	return merklePathFromReader(&reader{b: b}, legalOffsetsOnly)
}

// MerklePathFromHex is `MerklePath.fromHex`.
func MerklePathFromHex(h string) (*MerklePath, error) {
	b, err := jsHexToArray(h)
	if err != nil {
		return nil, err
	}
	return MerklePathFromBinary(b, true)
}

func merklePathFromReader(r *reader, legalOffsetsOnly bool) (*MerklePath, error) {
	height, err := r.varintStrict()
	if err != nil {
		return nil, err
	}
	treeHeight, err := r.u8()
	if err != nil {
		return nil, err
	}
	path := make([][]*Leaf, treeHeight)
	for level := 0; level < int(treeHeight); level++ {
		n, err := r.varintStrict()
		if err != nil {
			return nil, err
		}
		path[level] = []*Leaf{}
		for ; n > 0; n-- {
			off, err := r.varintStrict()
			if err != nil {
				return nil, err
			}
			flags, err := r.u8()
			if err != nil {
				return nil, err
			}
			leaf := &Leaf{Offset: off}
			if flags&1 == 1 {
				leaf.Duplicate = true
			} else {
				if flags&2 != 0 {
					leaf.Txid = true
				}
				h, err := r.read(32)
				if err != nil {
					return nil, err
				}
				leaf.Hash, leaf.HasHash = hex.EncodeToString(reverse(h)), true
			}
			path[level] = append(path[level], leaf)
		}
		sort.SliceStable(path[level], func(i, j int) bool { return path[level][i].Offset < path[level][j].Offset })
	}
	return NewMerklePath(height, path, legalOffsetsOnly)
}

// NewMerklePath is the TS constructor with validateRoots = true.
func NewMerklePath(blockHeight uint64, path [][]*Leaf, legalOffsetsOnly bool) (out *MerklePath, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, panicError(r)
		}
	}()
	if len(path) == 0 || len(path) > 54 {
		return nil, errors.New("Merkle Path must contain between 1 and 54 levels")
	}
	mp := &MerklePath{BlockHeight: blockHeight, Path: make([][]*Leaf, len(path))}
	for h, level := range path {
		mp.Path[h] = make([]*Leaf, len(level))
		for i, l := range level {
			c := *l
			mp.Path[h][i] = &c
		}
	}
	legal := make([]map[uint64]bool, len(mp.Path))
	for h := range legal {
		legal[h] = map[uint64]bool{}
	}
	for height, leaves := range mp.Path {
		if len(leaves) == 0 && height == 0 {
			return nil, fmt.Errorf("Empty level at height: %d", height)
		}
		seen := map[uint64]bool{}
		for _, leaf := range leaves {
			if leaf.Offset > maxSafeInteger {
				return nil, errors.New("Invalid offset")
			}
			if seen[leaf.Offset] {
				return nil, fmt.Errorf("Duplicate offset: %d, at height: %d", leaf.Offset, height)
			}
			seen[leaf.Offset] = true
			if height == 0 {
				if !leaf.Duplicate {
					for h := 1; h < len(mp.Path); h++ {
						legal[h][siblingOf(offsetAtHeight(leaf.Offset, h))] = true
					}
				}
			} else if legalOffsetsOnly && !legal[height][leaf.Offset] {
				var offs []string
				for o := range legal[height] {
					offs = append(offs, fmt.Sprint(o))
				}
				return nil, fmt.Errorf("Invalid offset: %d, at height: %d, with legal offsets: %s", leaf.Offset, height, strings.Join(offs, ", "))
			}
		}
	}
	// validateRoots: every level-0 leaf must compute the same root.
	var root string
	for idx, leaf := range mp.Path[0] {
		var txid *string
		if leaf.HasHash {
			s := leaf.Hash
			txid = &s
		}
		computed, err := mp.computeRoot(txid)
		if err != nil {
			return nil, err
		}
		if idx == 0 {
			root = computed
		}
		if root != computed {
			return nil, errors.New("Mismatched roots")
		}
	}
	return mp, nil
}

// ToBinary is `toBinary`.
func (mp *MerklePath) ToBinary() []byte {
	w := &writer{}
	w.varint(mp.BlockHeight)
	w.b = append(w.b, byte(len(mp.Path)))
	for _, level := range mp.Path {
		w.varint(uint64(len(level)))
		for _, leaf := range level {
			w.varint(leaf.Offset)
			var flags byte
			if leaf.Duplicate {
				flags |= 1
			}
			if leaf.Txid {
				flags |= 2
			}
			w.b = append(w.b, flags)
			if flags&1 == 0 {
				w.bytes(reverse(mustJSHex(leaf.Hash)))
			}
		}
	}
	return w.b
}

// ToHex is `toHex`.
func (mp *MerklePath) ToHex() string { return hex.EncodeToString(mp.ToBinary()) }

func (mp *MerklePath) indexOf(txid string) (uint64, error) {
	for _, l := range mp.Path[0] {
		if l.HasHash && l.Hash == txid {
			return l.Offset, nil
		}
	}
	return 0, fmt.Errorf("Transaction ID %s not found in the Merkle Path", txid)
}

func (mp *MerklePath) maxOffset0() uint64 {
	var m uint64
	for _, l := range mp.Path[0] {
		if l.Offset > m {
			m = l.Offset
		}
	}
	return m
}

// ComputeRoot is `computeRoot(txid)`; an empty txid computes from the first leaf with a hash.
func (mp *MerklePath) ComputeRoot(txid string) (root string, err error) {
	defer func() {
		if r := recover(); r != nil {
			root, err = "", panicError(r)
		}
	}()
	if txid == "" {
		return mp.computeRoot(nil)
	}
	return mp.computeRoot(&txid)
}

func (mp *MerklePath) computeRoot(txidp *string) (string, error) {
	var txid string
	if txidp == nil {
		found := false
		for _, l := range mp.Path[0] {
			if l.HasHash && l.Hash != "" {
				txid, found = l.Hash, true
				break
			}
		}
		if !found {
			return "", errors.New("No valid leaf found in the Merkle Path")
		}
	} else {
		txid = *txidp
	}
	index, err := mp.indexOf(txid)
	if err != nil {
		return "", err
	}
	working := txid
	if len(mp.Path) == 1 && len(mp.Path[0]) == 1 {
		return working, nil
	}
	maxOff := mp.maxOffset0()
	treeHeight := len(mp.Path)
	if t := offsetTreeHeight(maxOff); t > treeHeight {
		treeHeight = t
	}
	for height := 0; height < treeHeight; height++ {
		offset := siblingOf(offsetAtHeight(index, height))
		leaf := mp.findOrComputeLeaf(height, offset)
		isLastOdd := len(mp.Path) == 1 && sameNodeAtHeight(index, maxOff, height)
		switch {
		case leaf == nil:
			if isLastOdd {
				working = hashPair(working, working)
			} else {
				return "", fmt.Errorf("Missing hash for index %d at height %d", index, height)
			}
		case leaf.Duplicate:
			working = hashPair(working, working)
		case offset%2 == 1:
			working = hashPair(leaf.Hash, working)
		default:
			working = hashPair(working, leaf.Hash)
		}
	}
	return working, nil
}

func (mp *MerklePath) findOrComputeLeaf(height int, offset uint64) *Leaf {
	if height < len(mp.Path) {
		for _, l := range mp.Path[height] {
			if l.Offset == offset {
				return l
			}
		}
	}
	if height == 0 {
		return nil
	}
	h := height - 1
	l := offset * 2
	if l > maxSafeInteger {
		return nil
	}
	leaf0 := mp.findOrComputeLeaf(h, l)
	if leaf0 == nil || !leaf0.HasHash || leaf0.Hash == "" {
		return nil
	}
	leaf1 := mp.findOrComputeLeaf(h, l+1)
	if leaf1 == nil || !leaf1.HasHash {
		if leaf1 != nil && leaf1.Duplicate {
			return &Leaf{Offset: offset, Hash: hashPair(leaf0.Hash, leaf0.Hash), HasHash: true}
		}
		if len(mp.Path) == 1 && l == offsetAtHeight(mp.maxOffset0(), h) {
			return &Leaf{Offset: offset, Hash: hashPair(leaf0.Hash, leaf0.Hash), HasHash: true}
		}
		return nil
	}
	var w string
	if leaf1.Duplicate {
		w = hashPair(leaf0.Hash, leaf0.Hash)
	} else {
		w = hashPair(leaf1.Hash, leaf0.Hash)
	}
	return &Leaf{Offset: offset, Hash: w, HasHash: true}
}

// Combine is `combine(other)`.
func (mp *MerklePath) Combine(other *MerklePath) error {
	if mp.BlockHeight != other.BlockHeight {
		return errors.New("You cannot combine paths which do not have the same block height.")
	}
	r1, err := mp.ComputeRoot("")
	if err != nil {
		return err
	}
	r2, err := other.ComputeRoot("")
	if err != nil {
		return err
	}
	if r1 != r2 {
		return errors.New("You cannot combine paths which do not have the same root.")
	}
	combined := make([][]*Leaf, 0, len(mp.Path))
	for h := range mp.Path {
		level := []*Leaf{}
		for _, l := range mp.Path[h] {
			c := *l
			level = append(level, &c)
		}
		if h < len(other.Path) {
			for _, ol := range other.Path[h] {
				var existing *Leaf
				for _, l := range level {
					if l.Offset == ol.Offset {
						existing = l
						break
					}
				}
				if existing == nil {
					c := *ol
					level = append(level, &c)
				} else if ol.Txid {
					existing.Txid = true
				}
			}
		}
		combined = append(combined, level)
	}
	mp.Path = combined
	return mp.Trim()
}

// Trim is `trim()`.
func (mp *MerklePath) Trim() error {
	pushIfNew := func(v uint64, a []uint64) []uint64 {
		if len(a) == 0 || a[len(a)-1] != v {
			return append(a, v)
		}
		return a
	}
	dropOffsetsFromLevel := func(drop []uint64, level int) {
		for i := len(drop); i >= 0; i-- {
			if i >= len(drop) {
				continue // drop[length] is undefined: matches no leaf
			}
			for k, n := range mp.Path[level] {
				if n.Offset == drop[i] {
					mp.Path[level] = append(mp.Path[level][:k], mp.Path[level][k+1:]...)
					break
				}
			}
		}
	}
	for _, level := range mp.Path {
		sort.SliceStable(level, func(i, j int) bool { return level[i].Offset < level[j].Offset })
	}
	var computed, drop []uint64
	for l := 0; l < len(mp.Path[0]); l++ {
		n := mp.Path[0][l]
		if n.Txid {
			computed = pushIfNew(offsetAtHeight(n.Offset, 1), computed)
		} else {
			k := l + 1
			if n.Offset%2 == 1 {
				k = l - 1
			}
			if k < 0 || k >= len(mp.Path[0]) {
				return errors.New("Cannot read properties of undefined (reading 'txid')")
			}
			peer := mp.Path[0][k]
			if !peer.Txid {
				drop = pushIfNew(peer.Offset, drop)
			}
		}
	}
	dropOffsetsFromLevel(drop, 0)
	for h := 1; h < len(mp.Path); h++ {
		drop = computed
		var next []uint64
		for _, o := range computed {
			next = pushIfNew(offsetAtHeight(o, 1), next)
		}
		computed = next
		dropOffsetsFromLevel(drop, h)
	}
	return nil
}
