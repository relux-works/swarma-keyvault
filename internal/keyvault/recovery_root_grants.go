package keyvault

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/pbkdf2"
)

const (
	rootGrantsProfile    = "namecoin-landlord-root/1"
	rootGrantsDerivation = "bip85-hdseed-wif/1"
	rootGrantsPath       = "m/83696968h/2h/7h"
)

// RootGrantsPublic contains public preparation data only. It conveys no native
// qualification, storage, owner enrollment, presence or signing capability.
type RootGrantsPublic struct {
	Profile       string `json:"profile"`
	Derivation    string `json:"derivation"`
	Path          string `json:"path"`
	Algorithm     string `json:"algorithm"`
	PublicKey     string `json:"public_key"`
	SealPublicKey string `json:"seal_public_key"`
	SealScript    string `json:"seal_script"`
}

// RootGrantsPairBinding is the complete public retained-pair reference. Expected
// bindings must come from authenticated retained records, independently of the
// mnemonic. Equality alone cannot authenticate their source.
type RootGrantsPairBinding struct {
	Schema           string `json:"schema"`
	Service          string `json:"service"`
	Version          int    `json:"version"`
	GroupID          string `json:"group_id"`
	MetadataSHA256   string `json:"metadata_sha256"`
	NostrIdentity    string `json:"nostr_identity"`
	NostrVersion     int    `json:"nostr_version"`
	NostrPublicKey   string `json:"nostr_public_key"`
	NostrNPub        string `json:"nostr_npub"`
	NamecoinIdentity string `json:"namecoin_identity"`
	NamecoinVersion  int    `json:"namecoin_version"`
	NamecoinXPub     string `json:"namecoin_xpub"`
	NamecoinOrigin   string `json:"namecoin_origin"`
}

// RootGrantsPreparationPublic is a snapshot, never a stored-success receipt.
type RootGrantsPreparationPublic struct {
	Root RootGrantsPublic      `json:"root"`
	Pair RootGrantsPairBinding `json:"pair"`
}

// rootGrantsPrepared is an unwired, package-private engine seam. Copies alias
// ONE state so clearing one handle invalidates all copies. No scalar accessor,
// serialization, seal callback or signer is provided. Only the final qualified
// helper/linked engine may acquire words and use this seam; the parent CLI must
// never call it. Native transport/ABI admission remains a separate boundary.
type rootGrantsPrepared struct{ state *rootGrantsState }

type rootGrantsState struct {
	mu     *sync.Mutex
	scalar *[32]byte
	public RootGrantsPreparationPublic
	ready  bool
}

func newRootGrantsPrepared() *rootGrantsPrepared {
	return &rootGrantsPrepared{state: &rootGrantsState{mu: &sync.Mutex{}, scalar: new([32]byte)}}
}

// Both value and pointer formatting use fixed text, including nested %#v.
// Reflection/unsafe and Go runtime/compiler copies are outside this protection;
// explicit clearing of owned buffers is not guaranteed physical memory erasure.
func (rootGrantsPrepared) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "<private-root-grants>")
}
func (rootGrantsState) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "<private-root-grants>") }
func (rootGrantsPrepared) MarshalJSON() ([]byte, error) {
	return nil, recoveryRefuse("private_protocol_error")
}
func (rootGrantsState) MarshalJSON() ([]byte, error) {
	return nil, recoveryRefuse("private_protocol_error")
}

func (p *rootGrantsPrepared) clear() {
	if p == nil || p.state == nil {
		return
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	clear(p.state.scalar[:])
	p.state.public = RootGrantsPreparationPublic{}
	p.state.ready = false
}

func (p *rootGrantsPrepared) publicView() (RootGrantsPreparationPublic, error) {
	if p == nil || p.state == nil {
		return RootGrantsPreparationPublic{}, recoveryRefuse("private_protocol_error")
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	if !p.state.ready {
		return RootGrantsPreparationPublic{}, recoveryRefuse("private_protocol_error")
	}
	return p.state.public, nil
}

func rootGrantsPairBinding(raw []byte, r RecoveryRecord) RootGrantsPairBinding {
	return RootGrantsPairBinding{
		Schema: r.Schema, Service: r.Service, Version: r.Version, GroupID: r.GroupID,
		MetadataSHA256: recoveryMetadataSHA256(raw),
		NostrIdentity:  r.purposeService(r.Nostr), NostrVersion: r.Nostr.Version,
		NostrPublicKey: r.Nostr.PublicKey, NostrNPub: r.Nostr.NPub,
		NamecoinIdentity: r.purposeService(r.Namecoin), NamecoinVersion: r.Namecoin.Version,
		NamecoinXPub: r.Namecoin.XPub, NamecoinOrigin: r.Namecoin.Origin,
	}
}

// prepareRootGrantsAttach CONSUMES exclusively owned phrase bytes, clearing them
// on EVERY return. The future helper assembles these from its numbered tty input;
// this function does not implement or qualify a terminal input route. rawRecord
// is public canonical metadata only, never ciphertext or an old private value.
// No I/O, wrapping, store, ACL, installation or caller callback exists here.
func prepareRootGrantsAttach(ctx context.Context, phrase, rawRecord []byte, expected RootGrantsPairBinding) (*rootGrantsPrepared, error) {
	defer clear(phrase)
	if ctx == nil {
		return nil, recoveryRefuse("invalid_arguments")
	}
	if ctx.Err() != nil {
		return nil, recoveryRefuse("canceled")
	}
	// Bound before copying/parsing. A public snapshot prevents later mutations of
	// the caller's record from changing this preparation's binding.
	if len(rawRecord) == 0 || len(rawRecord) > recoveryMaxMetadata {
		return nil, recoveryRefuse("retained_record_mismatch")
	}
	raw := bytes.Clone(rawRecord)
	r, err := parseRecoveryRecord(raw)
	if err != nil {
		return nil, recoveryRefuse("retained_record_mismatch")
	}
	bound := rootGrantsPairBinding(raw, r)
	if bound != expected {
		return nil, recoveryRefuse("retained_record_mismatch")
	}
	if len(phrase) == 0 || len(phrase) > 512 || bytes.Count(phrase, []byte{' '}) != 23 {
		return nil, recoveryRefuse("invalid_word_count")
	}
	pair, err := deriveRecovery(phrase)
	if err != nil {
		return nil, err
	}
	// BOTH leaves and origin must match the validated record AND external pins.
	// Clear all old-purpose private material immediately, including chaincode;
	// attach never needs an old-purpose envelope. Fresh all3 is a separate flow
	// and must retain Namecoin chaincode until its own envelope is sealed.
	match := pair.publicKey == bound.NostrPublicKey && pair.npub == bound.NostrNPub &&
		pair.xpub == bound.NamecoinXPub && pair.origin == bound.NamecoinOrigin
	pair.clear()
	if !match {
		return nil, recoveryRefuse("public_pin_mismatch")
	}
	if ctx.Err() != nil {
		return nil, recoveryRefuse("canceled")
	}
	// Deliberately AFTER both pin checks. The earlier pair seed/ancestors are
	// already cleared; rederive a transient root without changing legacy code.
	seed := pbkdf2.Key(phrase, []byte("mnemonic"), 2048, 64, sha512.New)
	defer clear(seed)
	root, err := masterRecoveryNode(seed)
	clear(seed)
	if err != nil {
		return nil, err
	}
	defer root.clear()
	p, err := prepareRootGrantsFromMaster(&root)
	root.clear()
	if err != nil {
		return nil, err
	}
	returned := false
	defer func() {
		if !returned {
			p.clear()
		}
	}()
	if ctx.Err() != nil {
		return nil, recoveryRefuse("canceled")
	}
	p.state.public.Pair = bound
	returned = true
	return p, nil
}

// prepareRootGrantsFromMaster never accepts a path/index. All three edges are
// hardened, with application2/index7 permanently bound to this profile. This
// private primitive is not a parent/helper response or an import operation.
func prepareRootGrantsFromMaster(root *recoveryNode) (*rootGrantsPrepared, error) {
	if root == nil || root.depth != 0 || root.child != 0 || root.parent != [4]byte{} {
		return nil, recoveryRefuse("invalid_derivation")
	}
	child, err := root.path([]uint32{0x80000000 | 83696968, 0x80000002, 0x80000007})
	if err != nil {
		return nil, err // no index skip or alternate path
	}
	defer child.clear()
	entropy, err := rootGrantsBIP85Entropy(child.key[:])
	if err != nil {
		return nil, err
	}
	defer clear(entropy[:])
	p := newRootGrantsPrepared()
	if err := p.state.setBIP85Entropy(&entropy); err != nil {
		p.clear()
		return nil, err
	}
	return p, nil
}

// rootGrantsBIP85Entropy implements BIP85 v2.1.0 specification lines52-62:
// https://github.com/bitcoin/bips/blob/b34d9f751791d4feb22feff4f2ed00bcac83961b/bip-0085.mediawiki
// Private scalar bytes are exactly 32-byte big endian, not text or WIF.
func rootGrantsBIP85Entropy(child []byte) ([64]byte, error) {
	var out [64]byte
	defer clear(out[:])
	key, err := nostrPrivate(child)
	if err != nil {
		return out, recoveryRefuse("invalid_derivation")
	}
	key.Zero()
	h := hmac.New(sha512.New, []byte("bip-entropy-from-k"))
	_, _ = h.Write(child)
	h.Sum(out[:0])
	return out, nil
}

// setBIP85Entropy is private to preparation, not a general key constructor. The
// first32 bytes are range-checked BEFORE any reduction; an invalid exponent
// refuses, never retries/index-skips. Normalize dG to even Y only afterwards.
func (s *rootGrantsState) setBIP85Entropy(entropy *[64]byte) error {
	clear(s.scalar[:])
	s.public = RootGrantsPreparationPublic{}
	s.ready = false
	if entropy == nil {
		return recoveryRefuse("invalid_derivation")
	}
	key, err := nostrPrivate(entropy[:32])
	if err != nil {
		return recoveryRefuse("invalid_derivation")
	}
	defer key.Zero()
	if key.PubKey().SerializeCompressed()[0] == 3 {
		key.Key.Negate()
	}
	public := key.PubKey().SerializeCompressed()
	if public[0] != 2 {
		return recoveryRefuse("invalid_derivation")
	}
	key.Key.PutBytes(s.scalar)
	s.public.Root = RootGrantsPublic{
		Profile: rootGrantsProfile, Derivation: rootGrantsDerivation, Path: rootGrantsPath,
		Algorithm: "secp256k1-bip340+ecdsa", PublicKey: hex.EncodeToString(public[1:]),
		SealPublicKey: hex.EncodeToString(public),
		SealScript:    "76a914" + hex.EncodeToString(recoveryHash160(public)) + "88ac",
	}
	s.ready = true
	return nil
}
