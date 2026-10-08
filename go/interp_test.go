package b017

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestVectorsInterpreter: random script pairs through the reference's Spend (vectors/interp.json); the port's
// Spend wrapper (go-sdk's interpreter) must reach the same verdict on each.
func TestVectorsInterpreter(t *testing.T) {
	path := filepath.Join(vectorsDir(), "interp.json")
	if p := os.Getenv("B017_INTERP_FILE"); p != "" {
		path = p
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skip("no interp.json")
	}
	var cases []struct {
		U, L string
		V    uint32
		OK   bool
		Err  string
	}
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	diff := map[string]int{}
	var first []string
	for i, c := range cases {
		err := Validate(SpendParams{SourceTXID: "abababababababababababababababababababababababababababababababab", SourceSatoshis: 1000,
			LockingScript: MustScriptFromHex(c.L), UnlockingScript: MustScriptFromHex(c.U), TransactionVersion: c.V,
			OtherInputs: []OutpointRef{}, InputSequence: 0xffffffff})
		if (err == nil) != c.OK {
			key := c.Err
			if c.OK {
				key = "reference valid; port: " + err.Error()
			}
			diff[key]++
			if len(first) < 15 {
				first = append(first, "#"+itoa(i)+" v"+itoa(int(c.V))+" u="+c.U+" l="+c.L+" | "+key)
			}
		}
	}
	if len(diff) > 0 {
		var keys []string
		for k := range diff {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			t.Errorf("%5d  %s", diff[k], k)
		}
		for _, f := range first {
			t.Log(f)
		}
	}
	t.Logf("interpreter: %d cases", len(cases))
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }
