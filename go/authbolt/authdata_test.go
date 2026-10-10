package authbolt

import (
	"encoding/json"
	"os"
	"testing"
)

// The shared auth-data contract (vectors/auth-data.json, computed with Python; p2p
// testdata/contract/authdata/authdata.json): register, rotate and reissue carry the holder count after
// the challenge hash (70 bytes); signin, refresh and write do not (66).
func TestAuthDataContract(t *testing.T) {
	b, err := os.ReadFile("../../vectors/auth-data.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Cases []struct {
			Purpose, AppPubKey, ChallengeHash, Hex string
			Count                                  *uint32
		}
		Invalid []struct{ Why, Hex string }
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Cases {
		got, err := DecodeAuthData(c.Hex)
		if err != nil {
			t.Errorf("%s: %v", c.Purpose, err)
			continue
		}
		var count uint32
		if c.Count != nil {
			count = *c.Count
		}
		if got != (AuthData{Purpose: c.Purpose, AppPubKey: c.AppPubKey, ChallengeHash: c.ChallengeHash, Count: count}) {
			t.Errorf("%s: %+v", c.Purpose, got)
		}
	}
	for _, c := range v.Invalid {
		if _, err := DecodeAuthData(c.Hex); err == nil {
			t.Errorf("accepted: %s", c.Why)
		}
	}
}
