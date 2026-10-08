package b017

// nfttemplates.go - src/tokens/templates/MinSimple.sx.template.ts and AuthBolt.sx.template.ts.
// A nil byte-slice argument is an omitted TS argument (its default applies); an empty non-nil slice is `[]`.

import "fmt"

// AuthDataMaxBytes is AUTH_DATA_MAX_BYTES: authOrMiscData is a direct push.
const AuthDataMaxBytes = 75

var (
	minSimpleLockSuffix   = MustScriptFromHex(MinSimpleLockSuffixHex)
	minSimpleUnlockSuffix = MustScriptFromHex(MinSimpleUnlockSuffixHex)
	authBoltLockSuffix    = MustScriptFromHex(AuthBoltLockSuffixHex)
	authBoltUnlockSuffix  = MustScriptFromHex(AuthBoltUnlockSuffixHex)
)

func orDefault(b []byte, def []byte) []byte {
	if b == nil {
		return def
	}
	return b
}

func nftLock(suffix *Script, pubKeyHash, issuerPubKey, commitment, txoType, parent, grandparent []byte) *Script {
	s := NewScript(nil)
	for _, b := range [][]byte{pubKeyHash, orDefault(commitment, make([]byte, 20)), orDefault(txoType, []byte{0x00}),
		orDefault(parent, make([]byte, 36)), orDefault(grandparent, make([]byte, 36)), issuerPubKey} {
		s.WriteBin(b)
	}
	return NewScript(append(append([]Chunk{}, s.Chunks()...), suffix.Chunks()...))
}

// MinSimpleTemplate is the MinSimpleBolt identity NFT template.
type MinSimpleTemplate struct{}

// Lock builds the lock from its 6 contract args (commitment, txoType, parent, grandparent default as in TS).
func (MinSimpleTemplate) Lock(pubKeyHash, issuerPubKey, commitment, txoType, parent, grandparent []byte) *Script {
	return nftLock(minSimpleLockSuffix, pubKeyHash, issuerPubKey, commitment, txoType, parent, grandparent)
}

// StaticSuffix is the static contract suffix.
func (MinSimpleTemplate) StaticSuffix() *Script { return MustScriptFromHex(MinSimpleLockSuffixHex) }

// Unlock is `unlock(privateKey, beneficiaryPubKeyHash, prevTxs = [], forceNoChange, forceNoFund)`.
func (MinSimpleTemplate) Unlock(signer Signer, beneficiaryPubKeyHash []byte, prevTxs []*Transaction, forceNoChange, forceNoFund bool) UnlockTemplate {
	return SingleSpendUnlock(SingleUnlockParams{Signer: signer, BeneficiaryPubKeyHash: beneficiaryPubKeyHash,
		UnlockSuffix: minSimpleUnlockSuffix, PrevTxs: prevTxs, ForceNoChange: forceNoChange, ForceNoFund: forceNoFund})
}

// Melt is `melt(privateKey)`.
func (MinSimpleTemplate) Melt(signer Signer) UnlockTemplate {
	return SingleSpendUnlock(SingleUnlockParams{Signer: signer, BeneficiaryPubKeyHash: []byte{}, UnlockSuffix: minSimpleUnlockSuffix, Melt: true})
}

// AuthBoltTemplate is the AuthBolt identity NFT template (MinSimple + authOrMiscData).
type AuthBoltTemplate struct{}

// Lock builds the lock (identical layout to MinSimple; a different suffix).
func (AuthBoltTemplate) Lock(pubKeyHash, issuerPubKey, commitment, txoType, parent, grandparent []byte) *Script {
	return nftLock(authBoltLockSuffix, pubKeyHash, issuerPubKey, commitment, txoType, parent, grandparent)
}

// StaticSuffix is the static contract suffix.
func (AuthBoltTemplate) StaticSuffix() *Script { return MustScriptFromHex(AuthBoltLockSuffixHex) }

// Unlock is `unlock(privateKey, beneficiaryPubKeyHash, prevTxs = [], authOrMiscData = [], forceNoChange, forceNoFund)`;
// it fails when authOrMiscData is longer than 75 bytes.
func (AuthBoltTemplate) Unlock(signer Signer, beneficiaryPubKeyHash []byte, prevTxs []*Transaction, authOrMiscData []byte, forceNoChange, forceNoFund bool) (UnlockTemplate, error) {
	if len(authOrMiscData) > AuthDataMaxBytes {
		return nil, fmt.Errorf("authOrMiscData is %d bytes; the maximum is %d (a direct push)", len(authOrMiscData), AuthDataMaxBytes)
	}
	l := AuthBoltLayout
	return SingleSpendUnlock(SingleUnlockParams{Signer: signer, BeneficiaryPubKeyHash: beneficiaryPubKeyHash,
		UnlockSuffix: authBoltUnlockSuffix, PrevTxs: prevTxs, ForceNoChange: forceNoChange, ForceNoFund: forceNoFund,
		Layout: &l, AuthOrMiscData: orDefault(authOrMiscData, []byte{})}), nil
}

// Melt is `melt(privateKey)`.
func (AuthBoltTemplate) Melt(signer Signer) UnlockTemplate {
	l := AuthBoltLayout
	return SingleSpendUnlock(SingleUnlockParams{Signer: signer, BeneficiaryPubKeyHash: []byte{}, UnlockSuffix: authBoltUnlockSuffix, Melt: true, Layout: &l})
}
