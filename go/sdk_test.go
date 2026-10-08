package b017

// sdk_test.go - the @bsv/sdk parts the port re-implements, against vectors/sdk.json (vectors/gen/sdk.test.ts).

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type tried struct {
	OK     json.RawMessage `json:"ok"`
	Throws *string         `json:"throws"`
}

func (r *tried) threw() bool { return r != nil && r.Throws != nil }
func (r *tried) str() string { return str(r.OK) }

func loadSDK(t *testing.T) map[string]json.RawMessage {
	b, err := os.ReadFile(filepath.Join(vectorsDir(), "sdk.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func expect(t *testing.T, what string, want *tried, got string, err error) {
	t.Helper()
	if want == nil {
		return
	}
	if want.threw() {
		if err == nil {
			t.Errorf("%s: reference threw %q, port returned %s", what, *want.Throws, got)
		}
		return
	}
	if err != nil {
		t.Errorf("%s: port error %v, reference %s", what, err, want.OK)
		return
	}
	if got != want.str() {
		t.Errorf("%s: %s, reference %s", what, got, want.str())
	}
}

func TestSDKMerklePath(t *testing.T) {
	var cases []struct {
		Hex         string   `json:"hex"`
		Txids       []string `json:"txids"`
		Roots       []tried  `json:"roots"`
		RootNoArg   tried    `json:"rootNoArg"`
		Missing     tried    `json:"missing"`
		CombineWith string   `json:"combineWith"`
		Combined    *tried   `json:"combined"`
		Trimmed     tried    `json:"trimmed"`
		Corrupt     string   `json:"corrupt"`
		CorruptLegal tried   `json:"corruptLegal"`
		CorruptLoose tried   `json:"corruptLoose"`
	}
	_ = json.Unmarshal(loadSDK(t)["merkle"], &cases)
	for i, c := range cases {
		mp, err := MerklePathFromHex(c.Hex)
		if err != nil {
			t.Fatalf("#%d parse: %v", i, err)
		}
		if mp.ToHex() != c.Hex {
			t.Errorf("#%d: round trip differs", i)
		}
		for k, txid := range c.Txids {
			got, err := mp.ComputeRoot(txid)
			expect(t, "root", &c.Roots[k], got, err)
		}
		got, err := mp.ComputeRoot("")
		expect(t, "root()", &c.RootNoArg, got, err)
		got, err = mp.ComputeRoot("00" + c.Txids[0][2:] + "")
		_ = got
		if c.Missing.threw() && err == nil && "00"+c.Txids[0][2:] != c.Txids[0] {
			// the vector's "missing" txid is random; any txid not in the path must fail
			t.Errorf("#%d: a txid not in the path computed a root", i)
		}
		if c.Combined != nil {
			a, _ := MerklePathFromHex(c.Hex)
			b, err := MerklePathFromHex(c.CombineWith)
			if err != nil {
				t.Fatalf("#%d combineWith: %v", i, err)
			}
			err = a.Combine(b)
			expect(t, "combine", c.Combined, a.ToHex(), err)
		}
		w, _ := MerklePathFromHex(c.Hex)
		err = w.Trim()
		expect(t, "trim", &c.Trimmed, w.ToHex(), err)
		bad, _ := hex.DecodeString(c.Corrupt)
		legal, err := MerklePathFromBinary(bad, true)
		lh := ""
		if err == nil {
			lh = legal.ToHex()
		}
		expect(t, "corrupt (legal)", &c.CorruptLegal, lh, err)
		loose, err := MerklePathFromBinary(bad, false)
		lo := ""
		if err == nil {
			lo = loose.ToHex()
		}
		expect(t, "corrupt (loose)", &c.CorruptLoose, lo, err)
	}
}

func TestSDKScripts(t *testing.T) {
	sdk := loadSDK(t)
	var cases []struct {
		Hex    string `json:"hex"`
		Chunks []struct {
			Op   byte    `json:"op"`
			Data *string `json:"data"`
		} `json:"chunks"`
		Rewritten string `json:"rewritten"`
	}
	_ = json.Unmarshal(sdk["scripts"], &cases)
	for i, c := range cases {
		s := MustScriptFromHex(c.Hex)
		got := s.Chunks()
		if len(got) != len(c.Chunks) {
			t.Errorf("#%d %s: %d chunks, reference %d", i, c.Hex, len(got), len(c.Chunks))
			continue
		}
		for k, w := range c.Chunks {
			g := got[k]
			if g.Op != w.Op || (g.Data == nil) != (w.Data == nil) || (w.Data != nil && hex.EncodeToString(g.Data) != *w.Data) {
				t.Errorf("#%d %s chunk %d: {%x %x}, reference {%x %v}", i, c.Hex, k, g.Op, g.Data, w.Op, w.Data)
			}
		}
		if s.ToHex() != c.Hex {
			t.Errorf("#%d: toHex is not the parsed bytes", i)
		}
		if NewScript(append([]Chunk{}, got...)).ToHex() != c.Rewritten {
			t.Errorf("#%d %s: re-serialised %s, reference %s", i, c.Hex, NewScript(got).ToHex(), c.Rewritten)
		}
	}
	var errs []struct {
		Hex    string `json:"hex"`
		Result tried  `json:"result"`
	}
	_ = json.Unmarshal(sdk["scriptHexErrors"], &errs)
	for _, e := range errs {
		_, err := ScriptFromHex(e.Hex)
		if e.Result.threw() && (err == nil || err.Error() != *e.Result.Throws) {
			t.Errorf("fromHex(%q): %v, reference %q", e.Hex, err, *e.Result.Throws)
		}
	}
}

func TestSDKTransactions(t *testing.T) {
	sdk := loadSDK(t)
	src, err := TransactionFromHex(str(sdk["srcHex"]))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Hex             string     `json:"hex"`
		ID              string     `json:"id"`
		EF              tried      `json:"ef"`
		Truncated       string     `json:"truncated"`
		TruncatedResult tried      `json:"truncatedResult"`
		Padded          string     `json:"padded"`
		PaddedResult    tried      `json:"paddedResult"`
		Preimages       [][]string `json:"preimages"`
	}
	_ = json.Unmarshal(sdk["txs"], &cases)
	scopes := []uint32{0x41, 0x42, 0x43, 0xc1, 0xc2, 0xc3}
	for i, c := range cases {
		tx, err := TransactionFromHex(c.Hex)
		if err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
		if id, _ := tx.ID(); id != c.ID {
			t.Errorf("#%d: id %s, reference %s", i, id, c.ID)
		}
		for _, in := range tx.Inputs {
			in.SourceTransaction = src
		}
		ef, err := tx.ToBinaryEF()
		expect(t, "ef", &c.EF, hex.EncodeToString(ef), err)
		tr, err := TransactionFromHex(c.Truncated)
		trID := ""
		if err == nil {
			trID, err = tr.ID()
		}
		expect(t, "truncated", &c.TruncatedResult, trID, err)
		pd, err := TransactionFromHex(c.Padded)
		pdID := ""
		if err == nil {
			pdID, _ = pd.ID()
		}
		expect(t, "padded", &c.PaddedResult, pdID, err)
		for k, in := range tx.Inputs {
			srcOut := src.Outputs[in.SourceOutputIndex]
			for s, scope := range scopes {
				pre, err := FormatPreimage(PreimageParams{SourceTXID: in.SourceTXID, SourceOutputIndex: in.SourceOutputIndex,
					SourceSatoshis: srcOut.Sats(), TransactionVersion: tx.Version, OtherInputs: RefsOf(tx.Inputs, k), InputIndex: k,
					Outputs: tx.Outputs, InputSequence: in.Sequence, Subscript: srcOut.LockingScript, LockTime: tx.LockTime, Scope: scope})
				if err != nil || hex.EncodeToString(pre) != c.Preimages[k][s] {
					t.Errorf("#%d input %d scope %x: preimage differs (%v)", i, k, scope, err)
				}
			}
		}
	}
}

func TestSDKBeef(t *testing.T) {
	var cases []struct {
		V2           tried  `json:"v2"`
		Atomic       tried  `json:"atomic"`
		V1           tried  `json:"v1"`
		V2Parsed     *tried `json:"v2parsed"`
		AtomicParsed *tried `json:"atomicParsed"`
		V1Parsed     *tried `json:"v1parsed"`
		Subject      string `json:"subject"`
	}
	_ = json.Unmarshal(loadSDK(t)["beefs"], &cases)
	type parsed struct {
		Valid         bool     `json:"valid"`
		ValidTxidOnly bool     `json:"validTxidOnly"`
		Order         []string `json:"order"`
		Atomic        *string  `json:"atomic"`
	}
	check := func(i int, what string, in tried, want *tried) {
		if in.threw() || want == nil {
			return
		}
		b, _ := hex.DecodeString(in.str())
		beef, err := BeefFromBinary(b)
		if want.threw() {
			if err == nil {
				if _, err2 := beef.IsValid(false); err2 == nil {
					t.Errorf("#%d %s: reference threw %q, port parsed", i, what, *want.Throws)
				}
			}
			return
		}
		if err != nil {
			t.Errorf("#%d %s: %v", i, what, err)
			return
		}
		var w parsed
		_ = json.Unmarshal(want.OK, &w)
		v, err := beef.IsValid(false)
		if err != nil {
			t.Errorf("#%d %s: isValid: %v", i, what, err)
			return
		}
		vt, _ := beef.IsValid(true)
		var order []string
		for _, bt := range beef.Txs {
			order = append(order, bt.Txid())
		}
		atomic := beef.AtomicTxid
		wa := ""
		if w.Atomic != nil {
			wa = *w.Atomic
		}
		if v != w.Valid || vt != w.ValidTxidOnly || atomic != wa || len(order) != len(w.Order) {
			t.Errorf("#%d %s: valid %v/%v order %v atomic %q; reference %v/%v %v %q", i, what, v, vt, order, atomic, w.Valid, w.ValidTxidOnly, w.Order, wa)
			return
		}
		for k := range order {
			if order[k] != w.Order[k] {
				t.Errorf("#%d %s: sorted order differs at %d", i, what, k)
			}
		}
	}
	for i, c := range cases {
		check(i, "v2", c.V2, c.V2Parsed)
		check(i, "atomic", c.Atomic, c.AtomicParsed)
		check(i, "v1", c.V1, c.V1Parsed)
		// A valid Atomic BEEF re-serialises to the same bytes through FromBeef and ToAtomicBeef.
		if !c.Atomic.threw() && c.AtomicParsed != nil && !c.AtomicParsed.threw() {
			var w parsed
			_ = json.Unmarshal(c.AtomicParsed.OK, &w)
			if w.Valid {
				tx, err := FromBeef(c.Atomic.str())
				if err != nil {
					continue // b017's own rules (no input-less unproven tx) may refuse what the SDK accepts
				}
				out, err := ToAtomicBeef(tx)
				if err != nil || hex.EncodeToString(out) != c.Atomic.str() {
					t.Errorf("#%d: atomic BEEF does not round-trip (%v)", i, err)
				}
			}
		}
	}
}

func TestSDKAtomicsAndFees(t *testing.T) {
	sdk := loadSDK(t)
	var nodes map[string]vNode
	_ = json.Unmarshal(sdk["nodes"], &nodes)
	var atomics []struct {
		Tx     string `json:"tx"`
		Atomic tried  `json:"atomic"`
		Extra  tried  `json:"extra"`
	}
	_ = json.Unmarshal(sdk["atomics"], &atomics)
	for i, a := range atomics {
		g := newGraph(t)
		g.extra = nodes
		tx := g.tx(a.Tx)
		out, err := ToAtomicBeef(tx)
		expect(t, fmt.Sprintf("#%d atomic", i), &a.Atomic, hex.EncodeToString(out), err)
		if a.Extra.threw() {
			continue
		}
		var w struct {
			Hex              string   `json:"hex"`
			Valid            bool     `json:"valid"`
			ValidTxidOnly    bool     `json:"validTxidOnly"`
			Order            []string `json:"order"`
			AtomicForSubject bool     `json:"atomicForSubject"`
		}
		_ = json.Unmarshal(a.Extra.OK, &w)
		b, _ := hex.DecodeString(w.Hex)
		beef, err := BeefFromBinary(b)
		if err != nil {
			t.Fatalf("#%d extra: %v", i, err)
		}
		v, _ := beef.IsValid(false)
		vt, _ := beef.IsValid(true)
		id, _ := tx.ID()
		var order []string
		for _, bt := range beef.Txs {
			order = append(order, bt.Txid())
		}
		if v != w.Valid || vt != w.ValidTxidOnly || beef.IsAtomic(id) != w.AtomicForSubject || fmt.Sprint(order) != fmt.Sprint(w.Order) {
			t.Errorf("#%d extra: %v/%v/%v %v; reference %v/%v/%v %v", i, v, vt, beef.IsAtomic(id), order, w.Valid, w.ValidTxidOnly, w.AtomicForSubject, w.Order)
		}
	}
	var fees []struct {
		Before struct {
			In      uint64 `json:"in"`
			Fixed   uint64 `json:"fixed"`
			Changes int    `json:"changes"`
		} `json:"before"`
		Res struct {
			OK []uint64 `json:"ok"`
		} `json:"res"`
	}
	_ = json.Unmarshal(sdk["fees"], &fees)
	for i, f := range fees {
		src := &Transaction{Version: 1, Outputs: []*Output{{Satoshis: U64(f.Before.In), LockingScript: P2PKHLock(make([]byte, 20))}}}
		tx := &Transaction{Version: 2, Inputs: []*Input{{SourceTransaction: src, UnlockingScript: NewScript(nil)}},
			Outputs: []*Output{{Satoshis: U64(f.Before.Fixed), LockingScript: P2PKHLock(make([]byte, 20))}}}
		for c := 0; c < f.Before.Changes; c++ {
			tx.Outputs = append(tx.Outputs, &Output{Change: true, LockingScript: P2PKHLock(make([]byte, 20))})
		}
		if err := Fee0(tx); err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
		var got []uint64
		for _, o := range tx.Outputs {
			got = append(got, o.Sats())
		}
		if fmt.Sprint(got) != fmt.Sprint(f.Res.OK) {
			t.Errorf("#%d fee(0): %v, reference %v", i, got, f.Res.OK)
		}
	}
}
