// Package authbolt is the relying party's check of an AuthBOLT identity presentation, in process, for p2pd
// (PeerLoop). It transcribes what the bolt-verify sidecar runs today (ChainBrowsers packages/bolt:
// identity.js verifyIdentity, handler.js BoltHandler.verify, nft.js readToken, core.js arcadeBroadcaster) on top
// of the Go b017 port, and has the shape of p2p's internal/authbolt.Verifier:
//
//	Verify(ctx, pkg []string, appKey, data string) (Result, error)
//
// A refusal is a Result with OK false and a Reason (what the sidecar answers with 200 {ok:false}); an error means
// no verdict could be reached, which this in-process verifier never has (the network is consulted only through
// the AnchorBroadcaster, whose failures are refusals, as in the reference).
package authbolt

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	b017 "github.com/BOLT-Association/b017-native/go"
)

// Result is p2p's authbolt.Result (the sidecar's verdict).
type Result struct {
	OK      bool   `json:"ok"`
	Reason  string `json:"reason"`
	Issuer  string `json:"issuer"`
	Holder  string `json:"holder"`
	TokenID string `json:"tokenId"`
	Purpose string `json:"purpose"`
}

// AuthDataBytes is AUTH_DATA_BYTES: [tag 1][app public key 33][SHA-256 of the challenge statement 32].
const AuthDataBytes = 66

var purposeOf = map[int]string{1: "register", 2: "signin", 3: "refresh", 4: "write"}

func isHex(s string, chars int) bool {
	if len(s) != chars {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// CheckAppKey is identity.js checkAppKey: a 33-byte compressed public key in hex, returned lowercased.
func CheckAppKey(appPubKey string) (string, error) {
	if !isHex(appPubKey, 66) || !(strings.EqualFold(appPubKey[:2], "02") || strings.EqualFold(appPubKey[:2], "03")) {
		return "", fmt.Errorf("the app key must be a 33-byte compressed public key (hex)")
	}
	return strings.ToLower(appPubKey), nil
}

// AuthData is a decoded presentation's auth data.
type AuthData struct {
	Purpose       string
	AppPubKey     string
	ChallengeHash string
}

// DecodeAuthData is identity.js decodeAuthData.
func DecodeAuthData(data string) (AuthData, error) {
	s := strings.ToLower(data)
	if !isHex(s, AuthDataBytes*2) {
		return AuthData{}, fmt.Errorf("auth data must be exactly %d bytes (hex)", AuthDataBytes)
	}
	tag, _ := strconv.ParseUint(s[:2], 16, 8)
	purpose, ok := purposeOf[int(tag)]
	if !ok {
		return AuthData{}, fmt.Errorf("unknown purpose tag 0x%s", s[:2])
	}
	app, err := CheckAppKey(s[2:68])
	if err != nil {
		return AuthData{}, fmt.Errorf("the auth data does not carry a valid app key")
	}
	return AuthData{Purpose: purpose, AppPubKey: app, ChallengeHash: s[68:]}, nil
}

// Token is nft.js readToken's result for the NFT family.
type Token struct {
	Type   b017.TokenType
	Owner  []byte
	Parent []byte
	Issuer []byte
	IsMint bool
}

// ReadToken is nft.js readToken(tx, vout) for the types a presentation can carry: (nil, false) for anything else.
func ReadToken(tx *b017.Transaction, vout int) (*Token, bool) {
	if vout < 0 || vout >= len(tx.Outputs) || tx.Outputs[vout].LockingScript == nil {
		return nil, false
	}
	lock := tx.Outputs[vout].LockingScript
	t := b017.RecognizeType(lock, "")
	if t == "" {
		return nil, false
	}
	owner, parent := 0, 3
	if t == b017.TypeSimpleMulti {
		owner, parent = 2, 8
	}
	p := b017.ChunkData(lock, parent)
	zero := true
	for _, b := range p {
		if b != 0 {
			zero = false
		}
	}
	return &Token{Type: t, Owner: b017.ChunkData(lock, owner), Parent: p, Issuer: b017.IssuerPubKeyOf(lock, t), IsMint: zero}, true
}

// Verifier verifies AuthBOLT presentations for one app.
type Verifier struct {
	// Broadcast reports whether the network has (or now accepts) an anchor. ArcadeBroadcaster is the reference's.
	Broadcast b017.AnchorBroadcaster
	// Headers judges a merkle path's root (the wallet's / p2pd's own verified header chain); nil = none.
	Headers b017.HeaderSource
}

// checked is handler.js verify's result.
type checked struct {
	kind, data, owner, holder, issuer, tokenID string
	t                                          b017.TokenType
}

// verify is handler.js BoltHandler.verify(pkg, { issuer }).
func (v *Verifier) verify(ctx context.Context, pkg []string, issuer string) (*checked, string) {
	txs := make([]*b017.Transaction, 0, len(pkg))
	for _, entry := range pkg {
		tx, err := b017.FromBeef(entry)
		if err != nil {
			return nil, "invalid package: " + err.Error()
		}
		txs = append(txs, tx)
	}
	trusted := strings.ToLower(issuer)
	if trusted == "" {
		return nil, "no trusted issuer: pass one, or configure trustedIssuers"
	}
	var named *Token
	for _, tx := range txs {
		if tk, ok := ReadToken(tx, 0); ok {
			named = tk
			break
		}
	}
	if named == nil {
		return nil, "no BOLT token in the package"
	}
	if hex.EncodeToString(named.Issuer) != trusted {
		return nil, fmt.Sprintf("issuer %s is not trusted", hex.EncodeToString(named.Issuer))
	}
	batch := make([]any, len(txs))
	for i, tx := range txs {
		batch[i] = tx
	}
	result := b017.VerifyAndBroadcast(ctx, batch, v.Broadcast, b017.ScanOpts{TrustedIssuerPubKey: named.Issuer}, v.Headers)
	if !result.OK {
		return nil, result.Reason
	}
	var events []b017.Event
	for _, e := range result.Events {
		if e.Kind != "mint" {
			events = append(events, e)
		}
	}
	if len(events) != 1 || (events[0].Kind != "transfer" && events[0].Kind != "split") {
		return nil, "a package holds exactly one transfer or split (commit and settle)"
	}
	find := func(id string) *b017.Transaction {
		for _, tx := range txs {
			if tid, err := tx.ID(); err == nil && tid == id {
				return tx
			}
		}
		return nil
	}
	commit, settle := find(events[0].Txids[0]), find(events[0].Txids[1])
	if commit == nil || settle == nil {
		return nil, "unverifiable input: the event's txs are not in the package"
	}
	settled, _ := ReadToken(settle, 0)
	spent, _ := ReadToken(commit, 0)
	if settled == nil || spent == nil {
		return nil, "no BOLT token in the package"
	}
	c := &checked{kind: events[0].Kind, t: result.Type, issuer: result.IssuerPubKeyHex,
		owner: hex.EncodeToString(settled.Owner), holder: hex.EncodeToString(spent.Owner)}
	if result.OffChainOnly != nil {
		c.kind = "presentation"
	}
	if result.Type == b017.TypeAuth && commit.Inputs[0].UnlockingScript != nil {
		c.data = hex.EncodeToString(b017.ChunkData(commit.Inputs[0].UnlockingScript, 0))
	}
	sid, err := settle.ID()
	if err != nil {
		return nil, "unverifiable input: " + err.Error()
	}
	c.tokenID = sid + ".0"
	return c, ""
}

// Verify is identity.js verifyIdentity({ handler, package, appPubKey, data }) with p2p's Verifier signature.
func (v *Verifier) Verify(ctx context.Context, pkg []string, appKey, data string) (Result, error) {
	app, err := CheckAppKey(appKey)
	if err != nil {
		return Result{Reason: err.Error()}, nil
	}
	decoded, err := DecodeAuthData(data)
	if err != nil {
		return Result{Reason: err.Error()}, nil
	}
	if decoded.AppPubKey != app {
		return Result{Reason: "the auth data names another app"}, nil
	}
	var issuer string
	for _, entry := range pkg {
		tx, err := b017.FromBeef(entry)
		if err != nil {
			return Result{Reason: "invalid package: " + err.Error()}, nil
		}
		if tk, ok := ReadToken(tx, 0); ok {
			issuer = hex.EncodeToString(tk.Issuer)
			break
		}
	}
	if issuer == "" {
		return Result{Reason: "no BOLT token in the package"}, nil
	}
	r, reason := v.verify(ctx, pkg, issuer)
	if r == nil {
		return Result{Reason: reason}, nil
	}
	if r.kind != "presentation" || r.t != b017.TypeAuth {
		return Result{Reason: "not an AuthBOLT presentation"}, nil
	}
	if r.data != strings.ToLower(data) {
		return Result{Reason: "the presentation carries other data than this challenge"}, nil
	}
	if r.owner != r.holder {
		return Result{Reason: "a presentation must be a self-transfer: it moves the token to another key"}, nil
	}
	return Result{OK: true, Issuer: r.issuer, Holder: r.holder, TokenID: r.tokenID, Purpose: decoded.Purpose}, nil
}
