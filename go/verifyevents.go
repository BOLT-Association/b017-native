package b017

// verifyevents.go - src/lib/scanner/verifyEvents.ts: the shared off-chain BOLT validator (the scanner).
// verifyEvent (one event), verifyEvents (a batch), verifyAndBroadcast (a batch, then its anchors broadcast).
// See the reference's header comment for the protocol; this is a line-by-line transcription. The scanner never
// throws: anything that panics inside becomes `unverifiable input: …`, as the TS catch does.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type fieldName int

const (
	fPubKeyHash fieldName = iota
	fCommitment
	fTxoType
	fParent
	fGrandparent
)

var fields = map[TokenType][5]int{
	TypeMinSimple:   {0, 1, 2, 3, 4},
	TypeAuth:        {0, 1, 2, 3, 4},
	TypeSimpleMulti: {2, 3, 6, 8, 9},
}

func field(lock *Script, t TokenType, f fieldName) []byte {
	return ChunkData(lock, fields[t][f])
}
func fieldHex(lock *Script, t TokenType, f fieldName) string { return hex.EncodeToString(field(lock, t, f)) }

func parseOutpoint(op []byte) (string, uint32) {
	n := len(op)
	if n > 32 {
		n = 32
	}
	txidHex := hex.EncodeToString(reverse(op[:n]))
	var v [4]byte
	if len(op) > 32 {
		copy(v[:], op[32:minInt(36, len(op))])
	}
	return txidHex, uint32(v[0]) | uint32(v[1])<<8 | uint32(v[2])<<16 | uint32(v[3])<<24
}

// ScanOpts are the scanner options. IsKnownBlockRoot nil = not supplied. TrustedIssuerPubKey is a hex string or
// bytes (nil / "" = none).
type ScanOpts struct {
	ExpectedType         TokenType
	TrustedIssuerPubKey  any
	IsKnownBlockRoot     func(merkleRoot string, height uint64) bool
	RequireBroadcastable bool
}

// OffChainOnlyTx is an event tx whose outputs exceed its inputs.
type OffChainOnlyTx struct {
	Txid       string `json:"txid"`
	InputSats  uint64 `json:"inputSats"`
	OutputSats uint64 `json:"outputSats"`
}

// SourceTx is a tx an event spends that is not itself part of the event.
type SourceTx struct {
	Txid   string `json:"txid"`
	Proven bool   `json:"proven"`
}

// Event is one event of a batch.
type Event struct {
	Kind  string   `json:"kind"`
	Txids []string `json:"txids"`
}

// AnchorRef is an anchor: the token tx a batch stands on. Status / Detail are filled by VerifyAndBroadcast.
type AnchorRef struct {
	Txid   string  `json:"txid"`
	Kind   string  `json:"kind"`
	Status string  `json:"status,omitempty"`
	Detail *string `json:"detail,omitempty"`
}

// ScanResult is verifyEvents' result. Empty strings and nil slices are absent fields (TS `undefined`).
type ScanResult struct {
	OK              bool
	Reason          string
	Type            TokenType
	IssuerPubKeyHex string
	Sources         []SourceTx
	Unauthenticated bool
	Events          []Event
	Anchors         []AnchorRef
	OffChainOnly    []OffChainOnlyTx
}

// EventResult is verifyEvent's result. Kind may be a tx category ("commit", "settle") on an arrangement failure,
// as in the reference.
type EventResult struct {
	OK              bool
	Reason          string
	Type            TokenType
	Kind            string
	Sources         []SourceTx
	Unauthenticated bool
	Anchors         []AnchorRef
	OffChainOnly    []OffChainOnlyTx
}

// MarshalJSON emits the fields the reference sets, and only those.
func (r ScanResult) MarshalJSON() ([]byte, error) {
	m := map[string]any{"ok": r.OK}
	if r.Reason != "" {
		m["reason"] = r.Reason
	}
	if r.Type != "" {
		m["type"] = r.Type
	}
	if r.IssuerPubKeyHex != "" {
		m["issuerPubKeyHex"] = r.IssuerPubKeyHex
	}
	if r.Sources != nil {
		m["sources"] = r.Sources
	}
	if r.Unauthenticated {
		m["unauthenticated"] = true
	}
	if r.Events != nil {
		m["events"] = r.Events
	}
	if r.Anchors != nil {
		m["anchors"] = r.Anchors
	}
	if r.OffChainOnly != nil {
		m["offChainOnly"] = r.OffChainOnly
	}
	return json.Marshal(m)
}

// MarshalJSON emits the fields the reference sets, and only those.
func (r EventResult) MarshalJSON() ([]byte, error) {
	m := map[string]any{"ok": r.OK}
	if r.Reason != "" {
		m["reason"] = r.Reason
	}
	if r.Type != "" {
		m["type"] = r.Type
	}
	if r.Kind != "" {
		m["kind"] = r.Kind
	}
	if r.Sources != nil {
		m["sources"] = r.Sources
	}
	if r.Unauthenticated {
		m["unauthenticated"] = true
	}
	if r.Anchors != nil {
		m["anchors"] = r.Anchors
	}
	if r.OffChainOnly != nil {
		m["offChainOnly"] = r.OffChainOnly
	}
	return json.Marshal(m)
}

// HeaderSource is an async source of block headers (the ChainTracker shape).
type HeaderSource interface {
	IsValidRootForHeight(ctx context.Context, root string, height uint64) (bool, error)
}

// AnchorBroadcastResult is what the network said about a broadcast anchor. Detail nil = absent.
type AnchorBroadcastResult struct {
	Status string
	Detail *string
}

// AnchorBroadcaster sends ONE anchor tx and reports accepted / already-seen / rejected.
type AnchorBroadcaster func(ctx context.Context, anchor *Transaction) (AnchorBroadcastResult, error)

// errText is the first line of an error's message.
func errText(e any) string {
	var s string
	switch v := e.(type) {
	case error:
		s = v.Error()
	default:
		s = fmt.Sprint(v)
	}
	return strings.SplitN(s, "\n", 2)[0]
}

type parseError struct{ msg string }

func (p parseError) Error() string { return p.msg }

// toTx parses one event tx: a *Transaction, raw tx hex, or BEEF (hex / bytes).
func toTx(t any) (*Transaction, error) {
	switch v := t.(type) {
	case *Transaction:
		if v == nil {
			return nil, parseError{"not a transaction: expected a Transaction, raw tx hex, or BEEF hex / bytes"}
		}
		return v, nil
	case string, []byte:
		if IsBeef(v) {
			tx, err := FromBeef(v)
			if err != nil {
				return nil, parseError{"invalid BEEF: " + errText(err)}
			}
			return tx, nil
		}
		var tx *Transaction
		var err error
		if s, ok := v.(string); ok {
			tx, err = TransactionFromHex(s)
		} else {
			tx, err = TransactionFromBinary(v.([]byte))
		}
		if err != nil {
			return nil, parseError{"malformed transaction hex: " + errText(err)}
		}
		return tx, nil
	default:
		return nil, parseError{"not a transaction: expected a Transaction, raw tx hex, or BEEF hex / bytes"}
	}
}

func optHex(b any) string {
	switch v := b.(type) {
	case nil:
		return ""
	case string:
		return strings.ToLower(v)
	case []byte:
		return hex.EncodeToString(v)
	}
	return ""
}

// ---- interface fingerprinting ----

type cls string

const (
	clsToken    cls = "token"
	clsP2P      cls = "p2p"
	clsP2PKH    cls = "p2pkh"
	clsExternal cls = "external"
	clsOther    cls = "other"
)

// byID is the batch's txid -> tx map (a JS Map: later entries replace earlier ones).
type byID map[string]*Transaction

func sourceOf(in *Input, ids byID) *Transaction {
	if in.SourceTransaction != nil {
		return in.SourceTransaction
	}
	if in.SourceTXID != "" {
		return ids[in.SourceTXID]
	}
	return nil
}

func spentTxid(in *Input) string {
	if in.SourceTXID != "" {
		return in.SourceTXID
	}
	if in.SourceTransaction != nil {
		return in.SourceTransaction.MustID()
	}
	return ""
}

func outAt(t *Transaction, i uint32) *Output {
	if t == nil || int(i) >= len(t.Outputs) {
		return nil
	}
	return t.Outputs[i]
}

func classifyOut(lock *Script, t TokenType) cls {
	if RecognizeType(lock, t) != "" {
		return clsToken
	}
	if RecognizeP2P(lock) {
		return clsP2P
	}
	var c []Chunk
	if lock != nil {
		c = lock.Chunks()
	}
	if len(c) == 5 && c[0].Op == OP_DUP && c[1].Op == OP_HASH160 && c[2].Data != nil && len(c[2].Data) == 20 &&
		c[3].Op == OP_EQUALVERIFY && c[4].Op == OP_CHECKSIG {
		return clsP2PKH
	}
	return clsOther
}

func classifyIn(in *Input, t TokenType, ids byID) cls {
	o := outAt(sourceOf(in, ids), in.SourceOutputIndex)
	if o == nil || o.LockingScript == nil {
		return clsExternal
	}
	return classifyOut(o.LockingScript, t)
}

type shape struct {
	kind                       string
	tokenIn, tokenOut, proofOut int
}

type category struct {
	shape       shape
	tokenOutIdx int
}

func tokenOutIndex(tx *Transaction, t TokenType) int {
	for i, o := range tx.Outputs {
		if RecognizeType(o.LockingScript, t) != "" {
			return i
		}
	}
	return -1
}

func categorise(tx *Transaction, t TokenType, ids byID) *category {
	idx := tokenOutIndex(tx, t)
	if idx >= 0 {
		lock := tx.Outputs[idx].LockingScript
		zero := true
		for _, b := range field(lock, t, fParent) {
			if b != 0 {
				zero = false
			}
		}
		if zero {
			return &category{shape{"mint", 0, 1, 0}, idx}
		}
		s := func(k string, a, b, c int) *category { return &category{shape{k, a, b, c}, idx} }
		switch fieldHex(lock, t, fTxoType) {
		case "21":
			return s("commit", 1, 1, 1)
		case "23":
			return s("commit", 1, 1, 2)
		case "25":
			return s("commit", 2, 1, 1)
		case "22":
			return s("settle", 1, 2, 0)
		case "24":
			return s("settle", 1, 1, 0)
		default:
			return s("settle", 1, 1, 0)
		}
	}
	for _, in := range tx.Inputs {
		if classifyIn(in, t, ids) == clsToken {
			return &category{shape{"melt", 1, 0, 0}, -1}
		}
	}
	return nil
}

func unauthenticatedMint(txs []*Transaction, t TokenType, ids byID) *Transaction {
	type c struct {
		tx  *Transaction
		cat *category
	}
	var cats []c
	var commits []*Transaction
	for _, tx := range txs {
		cat := categorise(tx, t, ids)
		cats = append(cats, c{tx, cat})
		if cat != nil && cat.shape.kind == "commit" {
			commits = append(commits, tx)
		}
	}
	for _, e := range cats {
		if e.cat == nil || e.cat.shape.kind != "mint" {
			continue
		}
		txid := e.tx.MustID()
		spent := false
		for _, cm := range commits {
			for _, in := range cm.Inputs {
				if spentTxid(in) == txid && int(in.SourceOutputIndex) == e.cat.tokenOutIdx {
					spent = true
				}
			}
		}
		if !spent {
			return e.tx
		}
	}
	return nil
}

func id8(tx *Transaction) string { return tx.MustID()[:8] }

func first8(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func executeInputs(txs []*Transaction, ids byID) string {
	ref := func(in *Input) OutpointRef {
		return OutpointRef{SourceTXID: spentTxid(in), SourceOutputIndex: in.SourceOutputIndex, Sequence: U32(in.Seq())}
	}
	for _, tx := range txs {
		id := id8(tx)
		for vin, input := range tx.Inputs {
			out := outAt(sourceOf(input, ids), input.SourceOutputIndex)
			if out == nil {
				return fmt.Sprintf("script execution failed: tx %s input %d: its source tx was not supplied", id, vin)
			}
			failure := func() (f string) {
				defer func() {
					if r := recover(); r != nil {
						f = errText(r)
					}
				}()
				if input.UnlockingScript == nil {
					return "no unlocking script"
				}
				var others []OutpointRef
				for k, o := range tx.Inputs {
					if k != vin {
						others = append(others, ref(o))
					}
				}
				if err := Validate(SpendParams{
					SourceTXID: spentTxid(input), SourceOutputIndex: input.SourceOutputIndex, LockingScript: out.LockingScript,
					SourceSatoshis: out.Sats(), TransactionVersion: tx.Version, OtherInputs: others,
					UnlockingScript: input.UnlockingScript, InputSequence: input.Seq(), InputIndex: vin, Outputs: tx.Outputs,
					LockTime: tx.LockTime,
				}); err != nil {
					return errText(err)
				}
				return ""
			}()
			if failure != "" {
				return fmt.Sprintf("script execution failed: tx %s input %d: %s", id, vin, failure)
			}
		}
	}
	return ""
}

func requireSources(txs []*Transaction, ids byID) (string, []SourceTx) {
	seen := map[string]bool{}
	sources := []SourceTx{}
	for _, tx := range txs {
		id := id8(tx)
		for vin, input := range tx.Inputs {
			src := sourceOf(input, ids)
			if src == nil || outAt(src, input.SourceOutputIndex) == nil {
				name := input.SourceTXID
				if name == "" {
					name = "?"
				}
				return fmt.Sprintf("source tx %s of tx %s input %d was not supplied (send the package as BEEF)", first8(name), id, vin), []SourceTx{}
			}
			sid := src.MustID()
			if input.SourceTXID != "" && input.SourceTXID != sid {
				return fmt.Sprintf("attached source %s of tx %s input %d is not the tx its outpoint names (%s)", sid[:8], id, vin, first8(input.SourceTXID)), []SourceTx{}
			}
			if _, inBatch := ids[sid]; !inBatch && !seen[sid] {
				seen[sid] = true
				sources = append(sources, SourceTx{Txid: sid, Proven: src.MerklePath != nil})
			}
		}
	}
	return "", sources
}

type proof struct {
	proven bool
	why    string
}

func headerProof(tx *Transaction, opts ScanOpts) proof {
	path := tx.MerklePath
	if path == nil {
		return proof{false, "it is accepted only with an SPV proof (a merkle path) to a known block header"}
	}
	if opts.IsKnownBlockRoot == nil {
		return proof{false, "it carries a merkle path, but no block headers were supplied to check it against (isKnownBlockRoot)"}
	}
	root, err := path.ComputeRoot(tx.MustID())
	if err != nil {
		return proof{false, fmt.Sprintf("its merkle path does not prove it (%s)", errText(err))}
	}
	known := func() (k bool) {
		defer func() {
			if recover() != nil {
				k = false
			}
		}()
		return opts.IsKnownBlockRoot(root, path.BlockHeight)
	}()
	if known {
		return proof{true, ""}
	}
	return proof{false, fmt.Sprintf("its merkle root is not a known block header at height %d", path.BlockHeight)}
}

func valueOf(tx *Transaction, ids byID) (uint64, uint64) {
	var in, out uint64
	for _, i := range tx.Inputs {
		if o := outAt(sourceOf(i, ids), i.SourceOutputIndex); o != nil {
			in += o.Sats()
		}
	}
	for _, o := range tx.Outputs {
		out += o.Sats()
	}
	return in, out
}

func anchorNotMinable(tx *Transaction, t TokenType, ids byID, why string) string {
	id := id8(tx)
	inSats, outSats := valueOf(tx, ids)
	if outSats > inSats {
		return fmt.Sprintf("anchor %s creates value (inputs %d sat, outputs %d sat): the network will never accept it; %s", id, inSats, outSats, why)
	}
	funded := false
	for _, in := range tx.Inputs {
		c := classifyIn(in, t, ids)
		if c == clsP2PKH || c == clsExternal {
			funded = true
		}
	}
	if !funded {
		note := ""
		if tx.MerklePath == nil {
			note = "it pays no fee, so the network will not mine it on sight; "
		}
		return fmt.Sprintf("unfunded anchor %s: %s%s", id, note, why)
	}
	return ""
}

func unauthenticatedReason(tx *Transaction) string {
	return fmt.Sprintf("unauthenticated mint %s: no commit in the event spends it, so nothing shows the sender holds the issuer key", id8(tx))
}

func actionKind(txoTypeHex string) string {
	switch txoTypeHex {
	case "23":
		return "split"
	case "25":
		return "merge"
	}
	return "transfer"
}

func joinCls(c []cls) string {
	s := make([]string, len(c))
	for i, x := range c {
		s[i] = string(x)
	}
	return strings.Join(s, ",")
}

func clsAt(c []cls, k int) (cls, bool) {
	if k >= 0 && k < len(c) {
		return c[k], true
	}
	return "", false
}

func checkArrangement(tx *Transaction, t TokenType, sh shape, ids byID, outputsOnly bool) string {
	id := id8(tx)
	outs := make([]cls, len(tx.Outputs))
	for i, o := range tx.Outputs {
		outs[i] = classifyOut(o.LockingScript, t)
	}
	ins := make([]cls, len(tx.Inputs))
	for i, in := range tx.Inputs {
		ins[i] = classifyIn(in, t, ids)
	}
	has := func(c []cls, x cls) bool {
		for _, y := range c {
			if y == x {
				return true
			}
		}
		return false
	}
	if has(outs, clsOther) {
		return fmt.Sprintf("uninspected output in %s [%s]", id, joinCls(outs))
	}
	if !outputsOnly && has(ins, clsOther) {
		return fmt.Sprintf("uninspected input in %s [%s]", id, joinCls(ins))
	}
	for k := 0; k < sh.tokenOut; k++ {
		if c, ok := clsAt(outs, k); !ok || c != clsToken {
			got := "none"
			if ok {
				got = string(c)
			}
			return fmt.Sprintf("%s %s: token output @%d (got %s) [%s]", sh.kind, id, k, got, joinCls(outs))
		}
	}
	for k := 0; k < sh.proofOut; k++ {
		if c, ok := clsAt(outs, sh.tokenOut+k); !ok || c != clsP2P {
			return fmt.Sprintf("%s %s: p2p output @%d [%s]", sh.kind, id, sh.tokenOut+k, joinCls(outs))
		}
	}
	for k := sh.tokenOut + sh.proofOut; k < len(outs); k++ {
		if outs[k] != clsP2PKH {
			return fmt.Sprintf("%s %s: change p2pkh @%d (got %s) [%s]", sh.kind, id, k, outs[k], joinCls(outs))
		}
	}
	if outputsOnly {
		return ""
	}
	for k := 0; k < sh.tokenIn; k++ {
		if c, ok := clsAt(ins, k); !ok || c != clsToken {
			got := "none"
			if ok {
				got = string(c)
			}
			return fmt.Sprintf("%s %s: token input @%d (got %s) [%s]", sh.kind, id, k, got, joinCls(ins))
		}
	}
	k := sh.tokenIn
	if sh.kind == "settle" {
		for k < len(ins) && ins[k] == clsP2P {
			k++
		}
	}
	for ; k < len(ins); k++ {
		if !(ins[k] == clsExternal || ins[k] == clsP2PKH) {
			return fmt.Sprintf("%s %s: unexpected input @%d: %s (a p2Proof input is only valid on a settle, immediately after the token input) [%s]", sh.kind, id, k, ins[k], joinCls(ins))
		}
	}
	return ""
}

func eventType(txs []*Transaction, ids byID, expected TokenType) TokenType {
	for _, tx := range txs {
		for _, o := range tx.Outputs {
			if t := RecognizeType(o.LockingScript, expected); t != "" {
				return t
			}
		}
	}
	for _, tx := range txs {
		for _, in := range tx.Inputs {
			if s := sourceOf(in, ids); s != nil {
				if o := outAt(s, in.SourceOutputIndex); o != nil && o.LockingScript != nil {
					if t := RecognizeType(o.LockingScript, expected); t != "" {
						return t
					}
				}
			}
		}
	}
	return ""
}

func idMap(txs []*Transaction) byID {
	m := byID{}
	for _, t := range txs {
		m[t.MustID()] = t
	}
	return m
}

// VerifyEvent is `verifyEvent`: verify ONE token event (a commit->settle pair or a melt; a mint only with the
// commit that spends it).
func VerifyEvent(eventTxs []any, opts ScanOpts) (res EventResult) {
	defer func() {
		if r := recover(); r != nil {
			res = EventResult{OK: false, Reason: "unverifiable input: " + errText(r)}
		}
	}()
	return verifyOneEvent(eventTxs, opts)
}

func verifyOneEvent(eventTxs []any, opts ScanOpts) EventResult {
	txs := make([]*Transaction, 0, len(eventTxs))
	for _, x := range eventTxs {
		t, err := toTx(x)
		if err != nil {
			return EventResult{Reason: err.Error()}
		}
		txs = append(txs, t)
	}
	if len(txs) == 0 {
		return EventResult{Reason: "empty event"}
	}
	ids := idMap(txs)
	t := eventType(txs, ids, opts.ExpectedType)
	if t == "" {
		return EventResult{Reason: "no BOLT token recognised in event"}
	}
	if opts.ExpectedType != "" && t != opts.ExpectedType {
		return EventResult{Reason: fmt.Sprintf("expected %s, got %s", opts.ExpectedType, t), Type: t}
	}
	for _, tx := range txs {
		cat := categorise(tx, t, ids)
		if cat == nil {
			return EventResult{Reason: fmt.Sprintf("tx %s is not a token tx", id8(tx)), Type: t}
		}
		if reason := checkArrangement(tx, t, cat.shape, ids, false); reason != "" {
			return EventResult{Reason: reason, Type: t, Kind: cat.shape.kind}
		}
	}
	if stray := unauthenticatedMint(txs, t, ids); stray != nil {
		return EventResult{Reason: unauthenticatedReason(stray), Type: t, Kind: "mint", Unauthenticated: true}
	}
	if failure, _ := requireSources(txs, ids); failure != "" {
		return EventResult{Reason: failure, Type: t}
	}
	var commitTx *Transaction
	var settleTxs []*Transaction
	for _, tx := range txs {
		cat := categorise(tx, t, ids)
		if cat != nil && cat.shape.kind == "commit" && commitTx == nil {
			commitTx = tx
		}
		if cat != nil && cat.shape.kind == "settle" {
			settleTxs = append(settleTxs, tx)
		}
	}
	if commitTx != nil && len(settleTxs) > 0 {
		cIdx := tokenOutIndex(commitTx, t)
		linked := false
		for _, s := range settleTxs {
			sIdx := tokenOutIndex(s, t)
			pid, pv := parseOutpoint(field(s.Outputs[sIdx].LockingScript, t, fParent))
			if pid == commitTx.MustID() && int(pv) == cIdx {
				linked = true
			}
		}
		if !linked {
			return EventResult{Reason: "settle.parent does not link to the commit token", Type: t}
		}
	}
	r := scan(txs2any(txs), opts, nil)
	if !r.OK {
		return EventResult{Reason: r.Reason, Type: t, Unauthenticated: r.Unauthenticated, OffChainOnly: r.OffChainOnly}
	}
	var actions []Event
	for _, e := range r.Events {
		if e.Kind != "mint" {
			actions = append(actions, e)
		}
	}
	if len(actions) != 1 {
		return EventResult{Reason: fmt.Sprintf("expected exactly one event, got %d (use verifyEvents for a batch)", len(actions)), Type: t}
	}
	return EventResult{OK: true, Type: t, Kind: actions[0].Kind, Sources: r.Sources, Anchors: r.Anchors, OffChainOnly: r.OffChainOnly}
}

func txs2any(txs []*Transaction) []any {
	out := make([]any, len(txs))
	for i, t := range txs {
		out[i] = t
	}
	return out
}

// VerifyEvents is `verifyEvents`: verify a BATCH of events end to end (offline; the caller still has to
// broadcast the anchors, or call VerifyAndBroadcast).
func VerifyEvents(txsIn []any, opts ScanOpts) ScanResult { return scan(txsIn, opts, nil) }

// VerifyAndBroadcast is `verifyAndBroadcast`: verifyEvents, then broadcast every anchor; accepted only when the
// network accepted (or had already seen) each one. tracker is used when opts.IsKnownBlockRoot is nil.
func VerifyAndBroadcast(ctx context.Context, txsIn []any, broadcast AnchorBroadcaster, opts ScanOpts, tracker HeaderSource) ScanResult {
	if broadcast == nil {
		return ScanResult{Reason: "an anchor broadcaster is required"}
	}
	var anchorTxs []*Transaction
	scanOpts := opts
	if opts.IsKnownBlockRoot == nil && tracker != nil {
		type rh struct {
			root   string
			height uint64
		}
		var order []string
		offered := map[string]rh{}
		pre := opts
		pre.IsKnownBlockRoot = func(root string, height uint64) bool {
			k := fmt.Sprintf("%d:%s", height, root)
			if _, ok := offered[k]; !ok {
				order = append(order, k)
			}
			offered[k] = rh{root, height}
			return false
		}
		scan(txsIn, pre, nil)
		known := map[string]bool{}
		for _, k := range order {
			v := offered[k]
			ok, err := func() (ok bool, err error) {
				defer func() {
					if recover() != nil {
						ok, err = false, nil
					}
				}()
				return tracker.IsValidRootForHeight(ctx, v.root, v.height)
			}()
			if err == nil && ok {
				known[k] = true
			}
		}
		scanOpts.IsKnownBlockRoot = func(root string, height uint64) bool { return known[fmt.Sprintf("%d:%s", height, root)] }
	}
	result := scan(txsIn, scanOpts, &anchorTxs)
	if !result.OK {
		return result
	}
	anchors := []AnchorRef{}
	for k, tx := range anchorTxs {
		ref := result.Anchors[k]
		sent, err := func() (s AnchorBroadcastResult, err error) {
			defer func() {
				if r := recover(); r != nil {
					err = panicError(r)
				}
			}()
			return broadcast(ctx, tx)
		}()
		if err != nil {
			d := "broadcast failed: " + errText(err)
			sent = AnchorBroadcastResult{Status: "rejected", Detail: &d}
		}
		known := sent.Status == "accepted" || sent.Status == "already-seen"
		detail := sent.Detail
		if detail == nil && !(known || sent.Status == "rejected") {
			st := sent.Status
			if st == "" {
				st = "undefined"
			}
			d := "unknown broadcast status " + st
			detail = &d
		}
		status := "rejected"
		if known {
			status = sent.Status
		}
		anchors = append(anchors, AnchorRef{Txid: ref.Txid, Kind: ref.Kind, Status: status, Detail: detail})
		if !known {
			reason := fmt.Sprintf("anchor %s %s was not accepted by the network", ref.Kind, ref.Txid[:8])
			if detail != nil && *detail != "" {
				reason += ": " + *detail
			}
			return ScanResult{Reason: reason, Type: result.Type, IssuerPubKeyHex: result.IssuerPubKeyHex, Anchors: anchors}
		}
	}
	result.Anchors = anchors
	return result
}

func scan(txsIn []any, opts ScanOpts, anchorOut *[]*Transaction) (res ScanResult) {
	defer func() {
		if r := recover(); r != nil {
			res = ScanResult{OK: false, Reason: "unverifiable input: " + errText(r)}
		}
	}()
	return scanBatch(txsIn, opts, anchorOut)
}

type tokenRef struct {
	txid string
	vout int
	t    TokenType
	lock *Script
}

func scanBatch(txsIn []any, opts ScanOpts, anchorOut *[]*Transaction) ScanResult {
	txs := make([]*Transaction, 0, len(txsIn))
	for _, x := range txsIn {
		t, err := toTx(x)
		if err != nil {
			return ScanResult{Reason: err.Error()}
		}
		txs = append(txs, t)
	}
	if len(txs) == 0 {
		return ScanResult{Reason: "empty batch"}
	}
	ids := idMap(txs)
	tokensOf := func(list []*Transaction) []tokenRef {
		var found []tokenRef
		for _, tx := range list {
			txid := tx.MustID()
			for vout, o := range tx.Outputs {
				if t := RecognizeType(o.LockingScript, opts.ExpectedType); t != "" {
					found = append(found, tokenRef{txid, vout, t, o.LockingScript})
				}
			}
		}
		return found
	}
	tokens := tokensOf(txs)
	var t TokenType
	if len(tokens) > 0 {
		t = tokens[0].t
	}
	for _, tx := range txs {
		if t != "" {
			break
		}
		for _, in := range tx.Inputs {
			if o := in.SourceOutput(); o != nil && o.LockingScript != nil {
				t = RecognizeType(o.LockingScript, opts.ExpectedType)
			} else {
				t = ""
			}
			if t != "" {
				break
			}
		}
	}
	if t == "" {
		return ScanResult{Reason: "no BOLT token output recognised"}
	}

	// THE ANCHOR STEP: pull a token source spent by a commit / melt into the batch.
	promoted := map[string]bool{}
	snapshot := append([]*Transaction{}, txs...)
	for _, tx := range snapshot {
		cat := categorise(tx, t, ids)
		if cat == nil || (cat.shape.kind != "commit" && cat.shape.kind != "melt") {
			continue
		}
		for _, in := range tx.Inputs {
			src := in.SourceTransaction
			if src == nil || classifyIn(in, t, ids) != clsToken {
				continue
			}
			sid := src.MustID()
			if _, ok := ids[sid]; ok {
				continue
			}
			ids[sid] = src
			promoted[sid] = true
			txs = append([]*Transaction{src}, txs...)
		}
	}
	if len(promoted) > 0 {
		tokens = tokensOf(txs)
	}
	for _, tk := range tokens {
		if tk.t != t {
			return ScanResult{Reason: "mixed token types in batch"}
		}
	}
	if opts.ExpectedType != "" && t != opts.ExpectedType {
		return ScanResult{Reason: fmt.Sprintf("expected %s, got %s", opts.ExpectedType, t)}
	}

	var issuers []string
	seenIssuer := map[string]bool{}
	for _, tk := range tokens {
		h := hex.EncodeToString(IssuerPubKeyOf(tk.lock, t))
		if !seenIssuer[h] {
			seenIssuer[h] = true
			issuers = append(issuers, h)
		}
	}
	if len(issuers) != 1 {
		return ScanResult{Reason: "inconsistent issuerPubKey across batch"}
	}
	issuerHex := issuers[0]
	if len(issuerHex) != 66 {
		return ScanResult{Reason: "issuerPubKey is not a 33-byte compressed public key", Type: t}
	}
	if trusted := optHex(opts.TrustedIssuerPubKey); trusted != "" && trusted != issuerHex {
		return ScanResult{Reason: "issuerPubKey != trusted issuer"}
	}

	type entry struct {
		tx  *Transaction
		cat *category
	}
	cats := make([]entry, len(txs))
	for i, tx := range txs {
		cats[i] = entry{tx, categorise(tx, t, ids)}
	}
	for _, e := range cats {
		if e.cat == nil {
			return ScanResult{Reason: fmt.Sprintf("tx %s is not a BOLT token tx", id8(e.tx)), Type: t}
		}
	}

	var commits []entry
	for _, e := range cats {
		if e.cat.shape.kind == "commit" {
			commits = append(commits, e)
		}
	}
	settled := map[string]bool{}
	events := []Event{}
	anchors := []AnchorRef{}
	var anchorTxs []*Transaction
	addAnchor := func(tx *Transaction, kind string) {
		anchors = append(anchors, AnchorRef{Txid: tx.MustID(), Kind: kind})
		anchorTxs = append(anchorTxs, tx)
	}
	spentAsToken := func(tt *Transaction) bool {
		id := tt.MustID()
		for _, c := range cats {
			if c.cat.shape.kind != "commit" && c.cat.shape.kind != "melt" {
				continue
			}
			for _, in := range c.tx.Inputs {
				o := outAt(tt, in.SourceOutputIndex)
				if spentTxid(in) == id && o != nil && o.LockingScript != nil && RecognizeType(o.LockingScript, t) != "" {
					return true
				}
			}
		}
		return false
	}
	for _, e := range cats {
		if promoted[e.tx.MustID()] && e.cat.shape.kind != "settle" && e.cat.shape.kind != "mint" {
			return ScanResult{Reason: fmt.Sprintf("anchor %s is not a settled token or a mint (it is a %s)", id8(e.tx), e.cat.shape.kind), Type: t}
		}
	}
	for _, s := range cats {
		if s.cat.shape.kind != "settle" {
			continue
		}
		sLock := s.tx.Outputs[s.cat.tokenOutIdx].LockingScript
		pid, pv := parseOutpoint(field(sLock, t, fParent))
		var commit *entry
		for k := range commits {
			if commits[k].tx.MustID() == pid && commits[k].cat.tokenOutIdx == int(pv) {
				commit = &commits[k]
				break
			}
		}
		if commit == nil {
			if spentAsToken(s.tx) {
				addAnchor(s.tx, "settle")
				continue
			}
			return ScanResult{Reason: fmt.Sprintf("settle %s links to no commit in the batch (orphan settle)", id8(s.tx)), Type: t}
		}
		settled[fmt.Sprintf("%s:%d", commit.tx.MustID(), commit.cat.tokenOutIdx)] = true
		cLock := commit.tx.Outputs[commit.cat.tokenOutIdx].LockingScript
		events = append(events, Event{Kind: actionKind(fieldHex(cLock, t, fTxoType)), Txids: []string{commit.tx.MustID(), s.tx.MustID()}})
	}
	for _, c := range commits {
		if !settled[fmt.Sprintf("%s:%d", c.tx.MustID(), c.cat.tokenOutIdx)] {
			return ScanResult{Reason: fmt.Sprintf("commit %s has no settle in the batch (unsettled commit)", id8(c.tx)), Type: t}
		}
	}

	isAnchor := func(tx *Transaction) bool {
		for _, a := range anchorTxs {
			if a == tx {
				return true
			}
		}
		return false
	}
	proofs := map[*Transaction]proof{}
	for _, e := range cats {
		if e.cat.shape.kind == "mint" || isAnchor(e.tx) {
			proofs[e.tx] = headerProof(e.tx, opts)
		}
	}
	headerProven := func(tx *Transaction) bool { p, ok := proofs[tx]; return ok && p.proven }
	var toExecute []*Transaction
	for _, tx := range txs {
		if !headerProven(tx) {
			toExecute = append(toExecute, tx)
		}
	}

	for _, e := range cats {
		if reason := checkArrangement(e.tx, t, e.cat.shape, ids, headerProven(e.tx)); reason != "" {
			return ScanResult{Reason: reason, Type: t}
		}
	}
	if stray := unauthenticatedMint(txs, t, ids); stray != nil {
		return ScanResult{Reason: unauthenticatedReason(stray), Type: t, IssuerPubKeyHex: issuerHex, Unauthenticated: true}
	}
	failure, sources := requireSources(toExecute, ids)
	if failure != "" {
		return ScanResult{Reason: failure, Type: t, IssuerPubKeyHex: issuerHex}
	}
	for _, e := range cats {
		if e.cat.shape.kind == "mint" {
			addAnchor(e.tx, "mint")
		}
		if (e.cat.shape.kind == "mint" || e.cat.shape.kind == "melt") && !promoted[e.tx.MustID()] {
			events = append(events, Event{Kind: e.cat.shape.kind, Txids: []string{e.tx.MustID()}})
		}
	}
	if f := executeInputs(toExecute, ids); f != "" {
		return ScanResult{Reason: f, Type: t, IssuerPubKeyHex: issuerHex}
	}
	for _, a := range anchorTxs {
		if headerProven(a) {
			continue
		}
		if refused := anchorNotMinable(a, t, ids, proofs[a].why); refused != "" {
			return ScanResult{Reason: refused, Type: t, IssuerPubKeyHex: issuerHex}
		}
	}
	var offChainOnly []OffChainOnlyTx
	for _, tx := range toExecute {
		if isAnchor(tx) {
			continue
		}
		in, out := valueOf(tx, ids)
		if out > in {
			offChainOnly = append(offChainOnly, OffChainOnlyTx{Txid: tx.MustID(), InputSats: in, OutputSats: out})
		}
	}
	if opts.RequireBroadcastable && len(offChainOnly) > 0 {
		o := offChainOnly[0]
		return ScanResult{Type: t, IssuerPubKeyHex: issuerHex, OffChainOnly: offChainOnly,
			Reason: fmt.Sprintf("tx %s creates value (inputs %d sat, outputs %d sat): it cannot be broadcast as built", o.Txid[:8], o.InputSats, o.OutputSats)}
	}
	if anchorOut != nil {
		*anchorOut = append(*anchorOut, anchorTxs...)
	}
	return ScanResult{OK: true, Type: t, IssuerPubKeyHex: issuerHex, Events: events, Sources: sources, Anchors: anchors, OffChainOnly: offChainOnly}
}
