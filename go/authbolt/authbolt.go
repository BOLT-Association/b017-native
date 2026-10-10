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
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	b017 "github.com/BOLT-Association/b017-native/go"
)

// Result is p2p's authbolt.Result (the sidecar's verdict). MintTxid is the genuine mint the presented commit
// spends, and HolderPubKey the key that signed the commit (the mint's owner), as verifyIdentity answers them.
type Result struct {
	OK           bool   `json:"ok"`
	Reason       string `json:"reason"`
	Issuer       string `json:"issuer"`
	Holder       string `json:"holder"`
	TokenID      string `json:"tokenId"`
	Purpose      string `json:"purpose"`
	MintTxid     string `json:"mintTxid,omitempty"`
	HolderPubKey string `json:"holderPubKey,omitempty"` // no longer set: the holder key's hash is Holder
	Count        uint32 `json:"count,omitempty"`        // the holder count a registration names
}

// AuthDataBytes is AUTH_DATA_BYTES: [tag 1][app public key 33][SHA-256 of the challenge statement 32].
const AuthDataBytes = 66

// CountedAuthDataBytes is COUNTED_AUTH_DATA_BYTES: register, rotate and reissue add the holder count
// [4, big-endian, at least 1].
const CountedAuthDataBytes = 70

var purposeOf = map[int]string{1: "register", 2: "signin", 3: "refresh", 4: "write", 5: "rotate", 6: "reissue"}

var counted = map[string]bool{"register": true, "rotate": true, "reissue": true}

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

// AuthData is a decoded presentation's auth data. Count is the holder count (0 for the uncounted purposes).
type AuthData struct {
	Purpose       string
	AppPubKey     string
	ChallengeHash string
	Count         uint32
}

// DecodeAuthData is identity.js decodeAuthData.
func DecodeAuthData(data string) (AuthData, error) {
	s := strings.ToLower(data)
	if len(s) < 2 || !isHex(s, len(s)) {
		return AuthData{}, fmt.Errorf("auth data must be hex")
	}
	tag, _ := strconv.ParseUint(s[:2], 16, 8)
	purpose, ok := purposeOf[int(tag)]
	if !ok {
		return AuthData{}, fmt.Errorf("unknown purpose tag 0x%s", s[:2])
	}
	bytes := AuthDataBytes
	if counted[purpose] {
		bytes = CountedAuthDataBytes
	}
	if len(s) != bytes*2 {
		return AuthData{}, fmt.Errorf("%s auth data must be exactly %d bytes (hex)", purpose, bytes)
	}
	app, err := CheckAppKey(s[2:68])
	if err != nil {
		return AuthData{}, fmt.Errorf("the auth data does not carry a valid app key")
	}
	out := AuthData{Purpose: purpose, AppPubKey: app, ChallengeHash: s[68:132]}
	if counted[purpose] {
		n, _ := strconv.ParseUint(s[132:], 16, 32)
		if n < 1 {
			return AuthData{}, fmt.Errorf("the holder count must be at least 1")
		}
		out.Count = uint32(n)
	}
	return out, nil
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

// Verify is identity.js verifyIdentity({ handler, package, appPubKey, data }) with p2p's Verifier signature: a
// registration (or reissue) must move the token out of its own mint to the identity's next holder, in a commit
// and settle that are funded and seen by the network. Holder is the new holder key's hash; Count the holder count.
func (v *Verifier) Verify(ctx context.Context, pkg []string, appKey, data string) (Result, error) {
	return v.VerifyAt(ctx, pkg, appKey, data, "")
}

// VerifyAt is verifyIdentity with its outpoint: a rotation (rotate data) is checked like a registration, except
// that its commit must spend `outpoint`, the token's outpoint the app recorded (the last verdict's TokenID),
// instead of a mint. For register and reissue data the outpoint is not used.
func (v *Verifier) VerifyAt(ctx context.Context, pkg []string, appKey, data, outpoint string) (Result, error) {
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
	rotating := decoded.Purpose == "rotate"
	if !rotating && decoded.Purpose != "register" && decoded.Purpose != "reissue" {
		return Result{Reason: decoded.Purpose + " data does not register an identity"}, nil
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
	var mint minted
	var reason string
	if rotating {
		reason = spendsOutpoint(pkg, strings.ToLower(data), outpoint)
	} else {
		mint, reason = mintProvenance(pkg, strings.ToLower(data))
	}
	if reason != "" {
		return Result{Reason: reason}, nil
	}
	r, reason := v.verify(ctx, pkg, issuer)
	if r == nil {
		return Result{Reason: reason}, nil
	}
	if r.t != b017.TypeAuth {
		return Result{Reason: "not an AuthBOLT"}, nil
	}
	if r.kind == "presentation" {
		return Result{Reason: "a registration must be on chain: this move was never funded or broadcast"}, nil
	}
	if r.kind != "transfer" {
		return Result{Reason: "a registration moves the token once (a commit and a settle)"}, nil
	}
	if r.data != strings.ToLower(data) {
		return Result{Reason: "the presentation carries other data than this challenge"}, nil
	}
	if !rotating && r.issuer != mint.issuer {
		return Result{Reason: "the presented token's issuer is not its mint's"}, nil
	}
	return Result{OK: true, Issuer: r.issuer, Holder: r.owner, TokenID: r.tokenID, Purpose: decoded.Purpose,
		MintTxid: mint.txid, Count: decoded.Count}, nil
}

// spendsOutpoint is identity.js spendsOutpoint: a rotation's commit (the transaction whose first input carries
// this auth data) must spend the token's recorded outpoint ("txid.vout"). "" or a refusal; no network call.
func spendsOutpoint(pkg []string, data, outpoint string) string {
	if !outpointRE.MatchString(outpoint) {
		return "a rotation needs the token's recorded outpoint"
	}
	want, err := hex.DecodeString(data)
	if err != nil {
		return "the presentation carries other data than this challenge"
	}
	for _, entry := range pkg {
		tx, err := b017.FromBeef(entry)
		if err != nil || len(tx.Inputs) == 0 || tx.Inputs[0].UnlockingScript == nil {
			continue
		}
		in := tx.Inputs[0]
		if !bytes.Equal(b017.ChunkData(in.UnlockingScript, 0), want) {
			continue // not the commit
		}
		src := in.SourceTXID
		if src == "" && in.SourceTransaction != nil {
			src, _ = in.SourceTransaction.ID()
		}
		if fmt.Sprintf("%s.%d", src, in.SourceOutputIndex) != strings.ToLower(outpoint) {
			return "the rotation does not spend the token's recorded outpoint"
		}
		return ""
	}
	return "the presentation carries other data than this challenge" // no commit carries it
}

var outpointRE = regexp.MustCompile(`^[0-9a-fA-F]{64}\.[0-9]+$`)

// minted is what mintProvenance found: the mint the commit spends, its issuer, and the key that signed the commit.
type minted struct{ txid, issuer, signer string }

// mintProvenance is identity.js mintProvenance: the presented commit (the transaction whose first input carries
// this auth data) must spend a mint the package carries. A mint transaction alone does not show its sender holds
// the issuer key, and a token whose lineage did not pass through a genuine mint proves no ownership (audit V1);
// a commit that spends the mint does, because spending a mint needs the issuer key under the covenant's genesis
// guard, which the full verify then executes. No network call is made.
func mintProvenance(pkg []string, data string) (minted, string) {
	want, err := hex.DecodeString(data)
	if err != nil {
		return minted{}, "the presentation carries other data than this challenge"
	}
	for _, entry := range pkg {
		tx, err := b017.FromBeef(entry)
		if err != nil || len(tx.Inputs) == 0 || tx.Inputs[0].UnlockingScript == nil {
			continue
		}
		in := tx.Inputs[0]
		if !bytes.Equal(b017.ChunkData(in.UnlockingScript, 0), want) {
			continue // not the commit
		}
		src := in.SourceTransaction
		if src == nil {
			return minted{}, "the presentation does not carry the mint its token was spent from"
		}
		id, err := src.ID()
		if err != nil || (in.SourceTXID != "" && in.SourceTXID != id) {
			return minted{}, "the presentation's mint does not match the outpoint its commit spends"
		}
		tok, ok := ReadToken(src, int(in.SourceOutputIndex))
		if !ok || !tok.IsMint {
			return minted{}, "the presented token does not come straight from its mint: no proof of ownership"
		}
		m := minted{txid: id, issuer: hex.EncodeToString(tok.Issuer)}
		for _, c := range in.UnlockingScript.Chunks() {
			if len(c.Data) == 33 && (c.Data[0] == 2 || c.Data[0] == 3) && bytes.Equal(b017.Hash160(c.Data), tok.Owner) {
				m.signer = hex.EncodeToString(c.Data)
				break
			}
		}
		return m, ""
	}
	return minted{}, "the presentation carries other data than this challenge" // no commit carries it
}
