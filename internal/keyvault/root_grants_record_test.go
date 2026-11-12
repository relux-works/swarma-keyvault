package keyvault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/crypto/ripemd160"
)

var rootGrantsRecordOrder13 = []string{"schema", "service", "purpose", "version", "created", "profile", "derivation", "path", "algorithm", "presence", "public_key", "seal_public_key", "seal_script", "pair", "wrapping_point", "wrapping_fingerprint"}
var rootGrantsPairOrder13 = []string{"schema", "service", "version", "group_id", "metadata_sha256", "nostr_identity", "nostr_version", "nostr_public_key", "nostr_npub", "namecoin_identity", "namecoin_version", "namecoin_xpub", "namecoin_origin"}

// Public fixture authority: BIP340 published scalar3/K, retained published
// recovery pair, and deliberately public synthetic P256 scalar3. These are NOT
// owner keys, enrollment, fresh native wraps or authenticated sealing evidence.
func rootGrantsRecordFixture13(t *testing.T, schema string) (RootGrantsRecord, []byte) {
	t.Helper()
	pair, pins := rootGrantsTestPair(t, schema)
	x := "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
	compressed, _ := hex.DecodeString("02" + x)
	h := sha256.Sum256(compressed)
	ripe := ripemd160.New()
	_, _ = ripe.Write(h[:])
	public := RootGrantsPreparationPublic{Root: RootGrantsPublic{Profile: "namecoin-landlord-root/1", Derivation: "bip85-hdseed-wif/1", Path: "m/83696968h/2h/7h",
		Algorithm: "secp256k1-bip340+ecdsa", PublicKey: x, SealPublicKey: "02" + x, SealScript: "76a914" + hex.EncodeToString(ripe.Sum(nil)) + "88ac"}, Pair: pins}
	var scalar [32]byte
	scalar[31] = 3
	key, err := ecdh.P256().NewPrivateKey(scalar[:])
	clear(scalar[:])
	if err != nil {
		t.Fatal("public synthetic P256 fixture unavailable")
	}
	r, err := NewRootGrantsRecord(RootGrantsAddress{Service: "example-root", Version: 1}, "2026-01-02T03:04:05Z", public, key.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return r, pair
}

func rootGrantsRaw13(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("fixture JSON failed")
	}
	return raw
}

func rootGrantsCloneRecord13(t *testing.T, r RootGrantsRecord) RootGrantsRecord {
	t.Helper()
	var out RootGrantsRecord
	if json.Unmarshal(rootGrantsRaw13(t, r), &out) != nil {
		t.Fatal("record fixture copy failed")
	}
	return out
}

// The order list is a literal contract expectation, separate from Go fields.
func rootGrantsOrderedJSON13(t *testing.T, raw []byte, order []string) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || len(object) != len(order) {
		t.Fatal("invalid ordered fixture")
	}
	var out bytes.Buffer
	out.WriteByte('{')
	for i, name := range order {
		if i > 0 {
			out.WriteByte(',')
		}
		out.Write(rootGrantsRaw13(t, name))
		out.WriteByte(':')
		value, ok := object[name]
		if !ok {
			t.Fatal("missing ordered fixture field")
		}
		out.Write(value)
	}
	out.WriteByte('}')
	return out.Bytes()
}

func rootGrantsNullVariants13(t *testing.T, raw []byte) [][]byte {
	t.Helper()
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("invalid null fixture")
	}
	var variants [][]byte
	for name, value := range fields {
		prefix := append(rootGrantsRaw13(t, name), ':')
		old := append(bytes.Clone(prefix), value...)
		replacement := append(bytes.Clone(prefix), []byte("null")...)
		variants = append(variants, bytes.Replace(raw, old, replacement, 1))
	}
	return variants
}

// Claim: exact field order and both legitimate retained v1/v2 bindings pass;
// explicit destination boundaries pass without defaulting, migration or native
// calls. Public export is exact compact S/K bytes+hash, omitting all envelopes.
// Limits: public constructors authenticate neither enrollment nor a private seal.
func TestRootGrantsRecord13CanonicalAndExport(t *testing.T) {
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		t.Run(schema, func(t *testing.T) {
			r, pair := rootGrantsRecordFixture13(t, schema)
			raw, err := CanonicalRootGrantsRecord(r)
			if err != nil || !bytes.Equal(raw, rootGrantsOrderedJSON13(t, raw, rootGrantsRecordOrder13)) {
				t.Fatal("top-level frozen order mismatch")
			}
			pairRaw := rootGrantsRaw13(t, r.Pair)
			if !bytes.Equal(pairRaw, rootGrantsOrderedJSON13(t, pairRaw, rootGrantsPairOrder13)) {
				t.Fatal("nested frozen order mismatch")
			}
			parsed, err := ParseRootGrantsRecord(raw)
			if err != nil || !bytes.Equal(rootGrantsRaw13(t, parsed), raw) {
				t.Fatal("canonical record round trip failed")
			}
			for _, address := range []RootGrantsAddress{{Service: "a", Version: 1}, {Service: strings.Repeat("a", 40), Version: 2147483647}} {
				p := RootGrantsPreparationPublic{Root: r.publicRoot(), Pair: r.Pair}
				if _, err := NewRootGrantsRecord(address, r.Created, p, r.WrappingPoint); err != nil {
					t.Fatal("legitimate address boundary rejected")
				}
			}
			// Both equal and split v2 identities are legitimate. Group/purpose
			// generations may independently reach the exact supported upper bound.
			oldPair, err := parseRecoveryRecord(pair)
			if err != nil {
				t.Fatal(err)
			}
			oldPair.Version, oldPair.Nostr.Version, oldPair.Namecoin.Version = 2147483647, 2147483647, 2147483647
			if schema == "keyvault-recovery/2" {
				oldPair.Namecoin.Service = oldPair.Nostr.Service
			}
			compatiblePair := rootGrantsRaw13(t, oldPair)
			compatible := rootGrantsCloneRecord13(t, r)
			compatible.Pair = rootGrantsPairBinding(compatiblePair, oldPair)
			if _, err := CanonicalRootGrantsRecord(compatible); err != nil {
				t.Fatal("valid pair identity/version compatibility rejected")
			}
			if _, err := ExportRootGrants(compatible, compatiblePair, compatible.Pair); err != nil {
				t.Fatal("valid pair compatibility not exported")
			}
			exported, err := ExportRootGrants(r, pair, r.Pair)
			want := `{"nostr":{"names":{"_":"` + r.Pair.NostrPublicKey + `"}},"swarma":{"landlord":{"grant":"` + r.PublicKey + `"}}}`
			h := sha256.Sum256([]byte(want))
			if err != nil || exported.IDValueUTF8 != want || exported.IDValueByteLength != len(want) || exported.IDValueSHA256 != hex.EncodeToString(h[:]) ||
				exported.Root.Namespace != "works.relux.mac-keyvault.root-grants.v1" || exported.Root.Account != "example-root/root-grants@1" {
				t.Fatal("exact public id-value projection mismatch")
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(rootGrantsRaw13(t, exported.Root), &fields) != nil || len(fields) != 9 {
				t.Fatal("public projection field set mismatch")
			}
			for _, name := range []string{"namespace", "account", "profile", "derivation", "path", "public_key", "seal_public_key", "seal_script", "pair"} {
				if fields[name] == nil {
					t.Fatal("public projection missing allowed field")
				}
			}
			changed := bytes.Replace(pair, []byte("2026-01-02"), []byte("2026-01-03"), 1)
			if _, err := ExportRootGrants(r, changed, r.Pair); err == nil {
				t.Fatal("export accepted stale complete metadata digest")
			}
			pins := r.Pair
			pins.NostrNPub = ""
			if _, err := ExportRootGrants(r, pair, pins); err == nil {
				t.Fatal("export accepted mismatched external social pin")
			}
		})
	}
}

// Claim: every root/pair/address/policy/point/script invariant is positive-list
// validated; malformed values never return an accepted record or public export.
// Limits: does not prove hardware freshness, seal authenticity or stored ACL.
func TestRootGrantsRecord13InvariantRefusals(t *testing.T) {
	r, pair := rootGrantsRecordFixture13(t, "keyvault-recovery/2")
	for i, mutate := range []func(*RootGrantsRecord){
		func(r *RootGrantsRecord) { r.Schema = "keyvault-root-grants/2" },
		func(r *RootGrantsRecord) { r.Service = "" },
		func(r *RootGrantsRecord) { r.Service = "UPPER" },
		func(r *RootGrantsRecord) { r.Service = strings.Repeat("a", 41) },
		func(r *RootGrantsRecord) { r.Purpose = "namecoin" },
		func(r *RootGrantsRecord) { r.Version = 0 },
		func(r *RootGrantsRecord) { r.Version = 2147483648 },
		func(r *RootGrantsRecord) { r.Created = "2026-01-02T03:04:05.1Z" },
		func(r *RootGrantsRecord) { r.Created = "2026-01-02T03:04:05+00:00" },
		func(r *RootGrantsRecord) { r.Created = "2026-13-02T03:04:05Z" },
		func(r *RootGrantsRecord) { r.Profile = "other/1" },
		func(r *RootGrantsRecord) { r.Derivation = "raw-bip32/1" },
		func(r *RootGrantsRecord) { r.Path = "m/83696968h/2h/0h" },
		func(r *RootGrantsRecord) { r.Algorithm = "secp256k1-bip340" },
		func(r *RootGrantsRecord) { r.Presence = "none" },
		func(r *RootGrantsRecord) { r.PublicKey = strings.ToUpper(r.PublicKey) },
		func(r *RootGrantsRecord) { r.PublicKey = strings.Repeat("f", 64); r.SealPublicKey = "02" + r.PublicKey },
		func(r *RootGrantsRecord) { r.SealPublicKey = "03" + r.PublicKey },
		func(r *RootGrantsRecord) { r.SealScript = "76a914" + strings.Repeat("0", 40) + "88ac" },
		func(r *RootGrantsRecord) { r.Pair.Schema = "keyvault-recovery/3" },
		func(r *RootGrantsRecord) { r.Pair.Schema = "keyvault-recovery/1" },
		func(r *RootGrantsRecord) { r.Pair.Service = "other" },
		func(r *RootGrantsRecord) { r.Pair.Version = 0 },
		func(r *RootGrantsRecord) { r.Pair.GroupID = "00" },
		func(r *RootGrantsRecord) { r.Pair.MetadataSHA256 = "A" + r.Pair.MetadataSHA256[1:] },
		func(r *RootGrantsRecord) { r.Pair.NostrIdentity = "other" },
		func(r *RootGrantsRecord) { r.Pair.NostrVersion = 0 },
		func(r *RootGrantsRecord) { r.Pair.NostrPublicKey = strings.Repeat("f", 64) },
		func(r *RootGrantsRecord) { r.Pair.NostrNPub = "" },
		func(r *RootGrantsRecord) { r.Pair.NamecoinIdentity = "" },
		func(r *RootGrantsRecord) { r.Pair.NamecoinVersion = 0 },
		func(r *RootGrantsRecord) { r.Pair.NamecoinXPub = "xpub" },
		func(r *RootGrantsRecord) { r.Pair.NamecoinOrigin = "[57471a66/84h/7h/1h]" },
		func(r *RootGrantsRecord) { r.WrappingPoint = r.WrappingPoint[:33] },
		func(r *RootGrantsRecord) { r.WrappingPoint = make([]byte, 65) },
		func(r *RootGrantsRecord) {
			r.WrappingPoint = make([]byte, 65)
			r.WrappingPoint[0] = 4
			h := sha256.Sum256(r.WrappingPoint)
			r.WrappingFingerprint = hex.EncodeToString(h[:])
		},
		func(r *RootGrantsRecord) { r.WrappingFingerprint = strings.Repeat("0", 64) },
	} {
		bad := rootGrantsCloneRecord13(t, r)
		mutate(&bad)
		if _, err := CanonicalRootGrantsRecord(bad); err == nil {
			t.Fatalf("invalid record invariant %d accepted", i)
		}
		if _, err := ParseRootGrantsRecord(rootGrantsRaw13(t, bad)); err == nil {
			t.Fatalf("invalid serialized invariant %d accepted", i)
		}
		if _, err := ExportRootGrants(bad, pair, bad.Pair); err == nil {
			t.Fatalf("invalid record exported at invariant %d", i)
		}
	}
}

// Claim: exact ordered canonical JSON rejects NULL in EVERY top/nested field,
// unknown/duplicate/escaped aliases, case aliases, reordered fields, alternate
// base64/hex spellings, trailing bytes and oversize input. No decoding I/O.
// Limits: bounded parser tests only; native metadata transport remains unqualified.
func TestRootGrantsRecord13EncodingRefusals(t *testing.T) {
	r, _ := rootGrantsRecordFixture13(t, "keyvault-recovery/1")
	raw, err := CanonicalRootGrantsRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	variants := rootGrantsNullVariants13(t, raw)
	pairRaw := rootGrantsRaw13(t, r.Pair)
	for _, nullPair := range rootGrantsNullVariants13(t, pairRaw) {
		variants = append(variants, bytes.Replace(raw, pairRaw, nullPair, 1))
	}
	order := append([]string(nil), rootGrantsRecordOrder13...)
	order[0], order[1] = order[1], order[0]
	pairOrder := append([]string(nil), rootGrantsPairOrder13...)
	pairOrder[0], pairOrder[1] = pairOrder[1], pairOrder[0]
	point := base64.StdEncoding.EncodeToString(r.WrappingPoint)
	variants = append(variants,
		nil, make([]byte, recoveryMaxMetadata+1), append(bytes.Clone(raw), '\n'), append([]byte{' '}, raw...), append(bytes.Clone(raw), []byte("{}")...),
		rootGrantsOrderedJSON13(t, raw, order),
		bytes.Replace(raw, pairRaw, rootGrantsOrderedJSON13(t, pairRaw, pairOrder), 1),
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":0,"schema":`), 1),
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"keyvault-root-grants/1","schema":`), 1),
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"Schema":`), 1),
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"\u0073chema":`), 1),
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"\u0073chema":"keyvault-root-grants/1","schema":`), 1),
		bytes.Replace(raw, []byte(`"group_id":`), []byte(`"alias":0,"group_id":`), 1),
		bytes.Replace(raw, []byte(point), []byte(strings.TrimRight(point, "=")), 1),
		bytes.Replace(raw, []byte(point), []byte(point+`\n`), 1),
	)
	for i, bad := range variants {
		if _, err := ParseRootGrantsRecord(bad); err == nil {
			t.Fatalf("noncanonical record encoding %d accepted", i)
		}
	}
}
