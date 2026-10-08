package b017

// fuzz_native_test.go - Go native fuzzing for crash-freedom and round trips (the differential corpus in
// fuzz_test.go checks agreement with the reference; these check that nothing panics on arbitrary bytes).
//   go test -run XXX -fuzz FuzzVerifyEvents -fuzztime 60s

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func seedBeefs(f *testing.F) {
	b, err := os.ReadFile(filepath.Join(vectorsDir(), "calls", "toAtomicBeef.json"))
	if err != nil {
		return
	}
	var recs []struct {
		Result string `json:"result"`
	}
	_ = json.Unmarshal(b, &recs)
	for i, r := range recs {
		if i%4 == 0 && r.Result != "" {
			raw, _ := hex.DecodeString(r.Result)
			f.Add(raw)
		}
	}
}

func FuzzScript(f *testing.F) {
	f.Add([]byte{0x4c})
	f.Add([]byte{0x6a, 0x01, 0x02})
	f.Add([]byte{0x63, 0x6a, 0x68, 0x6a, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		s := ScriptFromBinary(b)
		if !bytes.Equal(s.ToBinary(), b) {
			t.Fatal("a parsed script does not serialise to its bytes")
		}
		re := NewScript(append([]Chunk{}, s.Chunks()...))
		again := ScriptFromBinary(re.ToBinary())
		if !bytes.Equal(again.ToBinary(), re.ToBinary()) {
			t.Fatal("re-serialised chunks are not stable")
		}
	})
}

func FuzzTransaction(f *testing.F) {
	seedBeefs(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		tx, err := TransactionFromBinary(b)
		if err != nil {
			return
		}
		out, err := tx.ToBinary()
		if err != nil || !bytes.Equal(out, b) {
			t.Fatalf("a parsed tx does not serialise to its bytes (%v)", err)
		}
	})
}

func FuzzFromBeef(f *testing.F) {
	seedBeefs(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		tx, err := FromBeef(b)
		if err == nil {
			if _, err := ToAtomicBeef(tx); err != nil {
				t.Fatalf("a parsed BEEF's subject cannot be re-serialised: %v", err)
			}
		}
	})
}

func FuzzVerifyEvents(f *testing.F) {
	seedBeefs(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		// one package entry, and the same bytes split in two: the scanner must answer, never panic
		r := VerifyEvents([]any{b}, ScanOpts{})
		if r.OK && r.Type == "" {
			t.Fatal("an accepted batch has no type")
		}
		half := len(b) / 2
		_ = VerifyEvent([]any{b[:half], b[half:]}, ScanOpts{RequireBroadcastable: true})
	})
}
