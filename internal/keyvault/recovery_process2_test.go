package keyvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/namecoinjournal"
	"github.com/relux-works/swarma-keyvault/internal/namecoinprocess"
	"github.com/relux-works/swarma-keyvault/internal/namecoinpsbt"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

const process2FixturePolicyRevision = "process2-public-fixture-policy/1"

type recoveryProcess2Fixture struct {
	Record, Pair, AccountPin, Sidecar, Selection []byte
	ParsedRecord                                 RecoveryRecord
	ParsedPair                                   recoveryCiphertext
	Selected                                     namecoinpsbt.NativeSelection
}

func recoveryProcess2InputFromBytes(t *testing.T, recordRaw, pairRaw []byte) RecoveryProcess2Input {
	t.Helper()
	r, err := parseRecoveryRecord(recordRaw)
	if err != nil {
		t.Fatal("public pair record fixture invalid", err)
	}
	_, err = parseRecoveryCiphertext(pairRaw, r)
	if err != nil {
		t.Fatal("public pair ciphertext fixture invalid", err)
	}
	accountPin := recoveryProcess2AccountPin(t, r)
	pinHash := sha256.Sum256(accountPin)
	groupID, err := hex.DecodeString(r.GroupID)
	if err != nil {
		t.Fatal("public group fixture invalid", err)
	}
	var group [16]byte
	copy(group[:], groupID)
	publicKey, err := hex.DecodeString(r.Nostr.PublicKey)
	if err != nil {
		t.Fatal("public Nostr pin fixture invalid", err)
	}
	var nostrPin [32]byte
	copy(nostrPin[:], publicKey)
	var accountPinHash [32]byte
	copy(accountPinHash[:], pinHash[:])
	metadataHash := sha256.Sum256(recordRaw)
	pairHash := sha256.Sum256(pairRaw)
	sidecarValue := namecoinjournal.Sidecar{
		Binding:      namecoinjournal.Binding{Group: r.Account(), Account: r.PurposeAccount(r.Namecoin), PublicPin: accountPinHash, Policy: process2FixturePolicyRevision},
		NostrAccount: r.PurposeAccount(r.Nostr), GroupID: group, NostrPublicPin: nostrPin, MetadataHash: metadataHash, PairedValueHash: pairHash,
	}
	sidecar, err := namecoinjournal.EncodeSidecar(sidecarValue)
	if err != nil {
		t.Fatal("public sidecar fixture invalid", err)
	}
	selection := namecoinpsbt.NativeSelection{
		Schema: "keyvault-namecoin-native-selection/1",
		Selection: namecoinpsbt.Selection{
			Network: "namecoin-regtest", Genesis: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
			Group: r.Account(), Account: r.PurposeAccount(r.Namecoin), AccountPinSHA256: hex.EncodeToString(pinHash[:]),
			Policy: namecoinwire.Policy{Revision: process2FixturePolicyRevision, PerTxFeeCap: "100000", TotalFeeCap: "400000", MinFeeRate: "100000", MaxFeeRate: "1000000", DustRelayFee: "3000", CreatedAt: 1767323045, ReleaseNotAfter: 1767409445, FinalConfirmations: 1, ReleaseMode: "all-four-before-release"},
		},
		Sidecar: sidecarValue,
	}
	selectionBytes, err := json.Marshal(selection)
	if err != nil {
		t.Fatal("public selection fixture marshal failed", err)
	}
	selected, err := namecoinpsbt.DecodeNativeSelection(selectionBytes)
	if err != nil {
		t.Fatal("public selection fixture invalid", err)
	}
	return RecoveryProcess2Input{Selection: selected, AccountPin: accountPin, Sidecar: sidecar, Record: bytes.Clone(recordRaw), Pair: bytes.Clone(pairRaw)}
}

func recoveryProcess2AccountPin(t *testing.T, r RecoveryRecord) []byte {
	t.Helper()
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(r.Namecoin.Origin, "["), "]"), "/")
	if len(parts) != 4 || parts[1] != "84h" || parts[2] != "7h" || parts[3] != "0h" {
		t.Fatal("public Namecoin origin fixture invalid")
	}
	pin := namecoinwire.AccountPin{Schema: "keyvault-namecoin-account-pin/1", Group: r.Account(), Account: r.PurposeAccount(r.Namecoin), AccountXPub: r.Namecoin.XPub, MasterFingerprint: parts[0], AccountPath: "m/84h/7h/0h"}
	raw, err := json.Marshal(pin)
	if err != nil {
		t.Fatal("public account pin fixture marshal failed", err)
	}
	return raw
}

func recoveryProcess2V2Fixture(t *testing.T, rootService, namecoinService string, nostrVersion, namecoinVersion int) recoveryProcess2Fixture {
	t.Helper()
	m, store, helper := recoveryTestManager(t)
	m.random = bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	phrase := []byte(recoveryFixturePhrase)
	material, err := deriveRecovery(phrase)
	if err != nil {
		t.Fatal("published synthetic fixture derivation failed", err)
	}
	request := RecoveryRequest{
		Version: 7, NostrIdentity: rootService, NamecoinIdentity: namecoinService,
		NostrVersion: nostrVersion, NamecoinVersion: namecoinVersion,
		ExpectedNPub: material.npub, ExpectedXPub: material.xpub, ExpectedOrigin: material.origin,
	}
	r, err := m.Create(request, &recoveryFakeTerminal{phrase: bytes.Clone(phrase)}, true)
	if err != nil || len(store.groups) != 1 || len(helper.keys) != 2 {
		material.clear()
		t.Fatal("public v2 producer fixture creation failed", err)
	}
	recordRaw, err := json.Marshal(r)
	if err != nil {
		material.clear()
		t.Fatal("public v2 record marshal failed", err)
	}
	material.clear()
	pairRaw := bytes.Clone(store.data[r.Account()])
	parsedPair, err := parseRecoveryCiphertext(pairRaw, r)
	if err != nil {
		t.Fatal("public v2 pair from the production creation path is invalid", err)
	}
	input := recoveryProcess2InputFromBytes(t, recordRaw, pairRaw)
	selectionRaw, err := json.Marshal(input.Selection)
	if err != nil {
		t.Fatal("public v2 selection marshal failed", err)
	}
	return recoveryProcess2Fixture{Record: recordRaw, Pair: pairRaw, AccountPin: input.AccountPin, Sidecar: input.Sidecar, Selection: selectionRaw, ParsedRecord: r,
		ParsedPair: parsedPair, Selected: input.Selection}
}

func recoveryProcess2IndependentBindingPreimage(r RecoveryRecord, p RecoveryPurpose, recordRaw []byte) []byte {
	domain := "works.relux.mac-keyvault.recovery-envelope.v1"
	if r.Schema == "keyvault-recovery/2" {
		domain = "works.relux.mac-keyvault.recovery-envelope.v2"
	}
	physicalAccount := r.Service + "/recovery@" + strconv.Itoa(r.Version)
	logicalService := r.Service
	if r.Schema == "keyvault-recovery/2" {
		if p.Purpose == "nostr" {
			logicalService = r.Nostr.Service
		} else {
			logicalService = r.Namecoin.Service
		}
	}
	logicalAccount := logicalService + "/" + p.Purpose + "@" + strconv.Itoa(p.Version)
	parts := [][]byte{
		[]byte(domain), []byte("works.relux.mac-keyvault." + p.Purpose + "-wrap.v1"), []byte(physicalAccount),
		[]byte(p.Purpose), []byte(logicalAccount),
	}
	preimage := make([]byte, 0, len(recordRaw)+5*128+len(p.WrappingPoint))
	for _, part := range parts {
		preimage = append(preimage, part...)
		preimage = append(preimage, 0)
	}
	preimage = append(preimage, recordRaw...)
	preimage = append(preimage, 0)
	return append(preimage, p.WrappingPoint...)
}

type recoveryProcess2FilePin struct {
	Size   int    `json:"size_bytes"`
	SHA256 string `json:"sha256"`
}

type recoveryProcess2BindingPin struct {
	Purpose         string `json:"purpose"`
	Domain          string `json:"domain"`
	Namespace       string `json:"namespace"`
	PhysicalAccount string `json:"physical_account"`
	LogicalAccount  string `json:"logical_account"`
	MetadataFile    string `json:"metadata_file"`
	WrappingPoint   string `json:"wrapping_point_hex"`
	PreimageSHA256  string `json:"preimage_sha256"`
	BindingSHA256   string `json:"binding_sha256"`
}

type recoveryProcess2ManifestFixture struct {
	Name            string                             `json:"name"`
	RootService     string                             `json:"root_service"`
	NamecoinService string                             `json:"namecoin_service"`
	RecoveryVersion int                                `json:"recovery_version"`
	NostrVersion    int                                `json:"nostr_version"`
	NamecoinVersion int                                `json:"namecoin_version"`
	Files           map[string]recoveryProcess2FilePin `json:"files"`
	Bindings        []recoveryProcess2BindingPin       `json:"bindings"`
}

type recoveryProcess2Manifest struct {
	Schema   string                            `json:"schema"`
	Producer string                            `json:"producer"`
	Seed     string                            `json:"seed"`
	Fixtures []recoveryProcess2ManifestFixture `json:"fixtures"`
}

func recoveryProcess2FixtureDir(t *testing.T) string {
	t.Helper()
	return filepath.Join("testdata", "recovery", "process2")
}

// The frozen v1 pair and independently produced equal/different-service v2
// pairs all build one frame with only the Namecoin envelope projected. This
// proves software format compatibility, not Keychain identity or native use.
func TestBuildRecoveryProcess2FrameAcceptsFrozenV1AndV2Pairs(t *testing.T) {
	v1Record, err := os.ReadFile(filepath.Join("testdata", "recovery", "v1-public-record.json"))
	if err != nil {
		t.Fatal(err)
	}
	v1Pair, err := os.ReadFile(filepath.Join("testdata", "recovery", "v1-public-ciphertext.json"))
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []struct {
		name  string
		input RecoveryProcess2Input
	}{
		{"v1-frozen", recoveryProcess2InputFromBytes(t, v1Record, v1Pair)},
		{"v2-equal-service", readRecoveryProcess2Fixture(t, "v2-equal-service")},
		{"v2-distinct-service", readRecoveryProcess2Fixture(t, "v2-distinct-service")},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			frameBytes, err := BuildRecoveryProcess2Frame(fixture.input)
			if err != nil {
				t.Fatal("valid public paired fixture refused", err)
			}
			frame, err := namecoinprocess.DecodeProcess2CustodyFrame(frameBytes)
			if err != nil {
				t.Fatal("encoded custody frame did not decode", err)
			}
			if frame.Metadata.Service != recoveryAdoptionService || frame.Metadata.PhysicalAccount != fixture.input.Selection.Selection.Group ||
				!bytes.Equal(frame.Metadata.Sidecar, fixture.input.Sidecar) || !bytes.Equal(frame.Metadata.Record, fixture.input.Record) {
				t.Fatal("frame metadata is not the exact selected public pair")
			}
			r, err := parseRecoveryRecord(fixture.input.Record)
			if err != nil {
				t.Fatal(err)
			}
			pair, err := parseRecoveryCiphertext(fixture.input.Pair, r)
			if err != nil {
				t.Fatal(err)
			}
			wantBinding := recoveryBinding(r, r.Namecoin)
			if frame.Envelope.Binding != wantBinding || !bytes.Equal(frame.Envelope.Blob, pair.Namecoin.EnclaveBlob) ||
				!bytes.Equal(frame.Envelope.WrappingPoint[:], pair.Namecoin.Point) || !bytes.Equal(frame.Envelope.Ciphertext[:], pair.Namecoin.Ciphertext) {
				t.Fatal("frame did not project the selected Namecoin envelope")
			}
			if bytes.Contains(frameBytes, pair.Nostr.Ciphertext) || bytes.Contains(frameBytes, []byte(recoveryFixturePhrase)) {
				t.Fatal("frame leaked Nostr-only ciphertext or synthetic plaintext")
			}
		})
	}
}

// Claim: each malformed public custody input returns its required typed refusal,
// no frame, and no in-place input mutation. Limit: this pure builder test does
// not exercise process launch, helper identity, or native custody.
func TestBuildRecoveryProcess2FrameRefusesPairAndSelectionMismatches(t *testing.T) {
	good := readRecoveryProcess2Fixture(t, "v2-distinct-service")
	validFrame, err := BuildRecoveryProcess2Frame(cloneRecoveryProcess2Input(good))
	if err != nil || len(validFrame) == 0 {
		t.Fatal("nearby valid distinct-service control was refused", err)
	}
	cases := []struct {
		name     string
		wantCode string
		mutate   func(*RecoveryProcess2Input)
	}{
		{name: "nostr-only-ciphertext", wantCode: "recovery_invalid_envelope", mutate: func(in *RecoveryProcess2Input) {
			var pair recoveryCiphertext
			if err := json.Unmarshal(in.Pair, &pair); err != nil {
				t.Fatal(err)
			}
			pair.Nostr.Ciphertext[len(pair.Nostr.Ciphertext)-1] ^= 1
			in.Pair, _ = json.Marshal(pair)
		}},
		{name: "namecoin-only-cross-pair", wantCode: "recovery_invalid_envelope", mutate: func(in *RecoveryProcess2Input) {
			other := readRecoveryProcess2Fixture(t, "v2-equal-service")
			in.Pair = bytes.Clone(other.Pair)
		}},
		{name: "record-timestamp-with-old-sidecar", wantCode: "recovery_invalid_envelope", mutate: func(in *RecoveryProcess2Input) {
			in.Record = bytes.Replace(bytes.Clone(in.Record), []byte("2026-01-02T03:04:05Z"), []byte("2026-01-02T03:04:06Z"), 1)
		}},
		{name: "account-pin-bytes", wantCode: "recovery_invalid_record", mutate: func(in *RecoveryProcess2Input) { in.AccountPin[len(in.AccountPin)-2] ^= 1 }},
		{name: "account-pin-pair-identity", wantCode: "recovery_invalid_record", mutate: func(in *RecoveryProcess2Input) {
			var pin namecoinwire.AccountPin
			if err := json.Unmarshal(in.AccountPin, &pin); err != nil {
				t.Fatal(err)
			}
			pin.AccountXPub = "substituted-xpub"
			in.AccountPin, _ = json.Marshal(pin)
			setProcess2PinHash(t, in)
		}},
		{name: "selection-group", wantCode: "recovery_invalid_record", mutate: func(in *RecoveryProcess2Input) { in.Selection.Selection.Group = "other/recovery@7" }},
		{name: "selection-account", wantCode: "recovery_invalid_record", mutate: func(in *RecoveryProcess2Input) { in.Selection.Selection.Account = "other/namecoin@9" }},
		{name: "selection-policy", wantCode: "recovery_invalid_record", mutate: func(in *RecoveryProcess2Input) { in.Selection.Selection.Policy.Revision = "other-policy/1" }},
		{name: "sidecar-public-pin", wantCode: "recovery_invalid_record", mutate: func(in *RecoveryProcess2Input) {
			in.Selection.Sidecar.NostrPublicPin[0] ^= 1
			in.Sidecar, _ = namecoinjournal.EncodeSidecar(in.Selection.Sidecar)
		}},
		{name: "sidecar-group-id", wantCode: "recovery_invalid_record", mutate: func(in *RecoveryProcess2Input) {
			in.Selection.Sidecar.GroupID[0] ^= 1
			in.Sidecar, _ = namecoinjournal.EncodeSidecar(in.Selection.Sidecar)
		}},
		{name: "sidecar-trailing-byte", wantCode: "recovery_invalid_record", mutate: func(in *RecoveryProcess2Input) { in.Sidecar = append(bytes.Clone(in.Sidecar), 0) }},
		{name: "record-duplicate-member", wantCode: "recovery_invalid_record", mutate: func(in *RecoveryProcess2Input) {
			in.Record = bytes.Replace(bytes.Clone(in.Record), []byte(`{"schema":`), []byte(`{"schema":"other","schema":`), 1)
		}},
		{name: "record-unknown-member", wantCode: "recovery_invalid_record", mutate: func(in *RecoveryProcess2Input) {
			in.Record = bytes.Replace(bytes.Clone(in.Record), []byte(`{"schema":`), []byte(`{"unknown":0,"schema":`), 1)
		}},
		{name: "missing-pair", wantCode: "recovery_invalid_record", mutate: func(in *RecoveryProcess2Input) { in.Pair = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := cloneRecoveryProcess2Input(good)
			tc.mutate(&input)
			before := cloneRecoveryProcess2Input(input)
			frame, err := BuildRecoveryProcess2Frame(input)
			var refusal *Refusal
			if !errors.As(err, &refusal) || refusal.Code != tc.wantCode || frame != nil {
				gotCode := ""
				if refusal != nil {
					gotCode = refusal.Code
				}
				t.Fatalf("wrong refusal or frame escaped: got code %q, frame nil=%t, want %q", gotCode, frame == nil, tc.wantCode)
			}
			if !reflect.DeepEqual(input.Selection, before.Selection) || !bytes.Equal(input.AccountPin, before.AccountPin) ||
				!bytes.Equal(input.Sidecar, before.Sidecar) || !bytes.Equal(input.Record, before.Record) || !bytes.Equal(input.Pair, before.Pair) {
				t.Fatal("rejected build mutated caller-owned public custody input")
			}
		})
	}
}

func cloneRecoveryProcess2Input(in RecoveryProcess2Input) RecoveryProcess2Input {
	in.Selection.Selection.RevealValuesPin = bytes.Clone(in.Selection.Selection.RevealValuesPin)
	in.AccountPin = bytes.Clone(in.AccountPin)
	in.Sidecar = bytes.Clone(in.Sidecar)
	in.Record = bytes.Clone(in.Record)
	in.Pair = bytes.Clone(in.Pair)
	return in
}

func setProcess2PinHash(t *testing.T, in *RecoveryProcess2Input) {
	t.Helper()
	hash := sha256.Sum256(in.AccountPin)
	in.Selection.Selection.AccountPinSHA256 = hex.EncodeToString(hash[:])
	in.Selection.Sidecar.Binding.PublicPin = hash
	in.Sidecar, _ = namecoinjournal.EncodeSidecar(in.Selection.Sidecar)
}

func readRecoveryProcess2Fixture(t *testing.T, name string) RecoveryProcess2Input {
	t.Helper()
	base := recoveryProcess2FixtureDir(t)
	var files [5][]byte
	for i, suffix := range []string{"record.json", "pair.json", "account-pin.json", "sidecar.kvns", "selection.json"} {
		value, err := os.ReadFile(filepath.Join(base, name+"-"+suffix))
		if err != nil {
			t.Fatalf("fixture %s %s: %v", name, suffix, err)
		}
		files[i] = value
	}
	selection, err := namecoinpsbt.DecodeNativeSelection(files[4])
	if err != nil {
		t.Fatalf("fixture %s selection: %v", name, err)
	}
	return RecoveryProcess2Input{Selection: selection, AccountPin: files[2], Sidecar: files[3], Record: files[0], Pair: files[1]}
}

// Claim: the production Create path emits a valid paired v2 record for equal and distinct service layouts. Limit: fake software wrappers and public mnemonic fixture.
func TestRecoveryProcess2V2FixtureProducerUsesBothServiceLayouts(t *testing.T) {
	for _, fixture := range []struct {
		name, root, namecoin          string
		nostrVersion, namecoinVersion int
	}{
		{"v2-equal-service", "same-fixture", "same-fixture", 4, 9},
		{"v2-distinct-service", "nostr-fixture", "namecoin-fixture", 4, 9},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			generated := recoveryProcess2V2Fixture(t, fixture.root, fixture.namecoin, fixture.nostrVersion, fixture.namecoinVersion)
			raw, err := json.Marshal(generated.ParsedRecord)
			if err != nil || !bytes.Equal(raw, generated.Record) || generated.ParsedRecord.Nostr.Version != fixture.nostrVersion || generated.ParsedRecord.Namecoin.Version != fixture.namecoinVersion {
				t.Fatal("production Create path lost the selected v2 service generations")
			}
			frame, err := BuildRecoveryProcess2Frame(RecoveryProcess2Input{Selection: generated.Selected, AccountPin: generated.AccountPin, Sidecar: generated.Sidecar, Record: generated.Record, Pair: generated.Pair})
			if err != nil || len(frame) == 0 {
				t.Fatal("production-created v2 pair did not pass process2 custody validation", err)
			}
		})
	}
}

// Independent preimage construction matches literal v2 binding digests for
// both purposes and both service arrangements; the v1 frozen path is unchanged.
func TestRecoveryProcess2IndependentV2BindingPreimages(t *testing.T) {
	manifestRaw, err := os.ReadFile(filepath.Join(recoveryProcess2FixtureDir(t), "v2-fixtures.json"))
	if err != nil {
		t.Fatal("fixture manifest unavailable", err)
	}
	var manifest recoveryProcess2Manifest
	decoder := json.NewDecoder(bytes.NewReader(manifestRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || manifest.Schema != "keyvault-namecoin-process2-v2-public-fixtures/1" ||
		manifest.Producer != "RecoveryManager.Create using recoverySeal, the v2 recovery binding, and the production ECIES/AES-GCM code" ||
		manifest.Seed != "Published recoveryFixturePhrase constant in recovery_test.go; public 24-word input only; no plaintext is serialized" || len(manifest.Fixtures) != 2 {
		t.Fatal("fixture manifest is not the pinned v2 public fixture contract")
	}
	canonical, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil || !bytes.Equal(append(canonical, '\n'), manifestRaw) {
		t.Fatal("fixture manifest is not canonical JSON")
	}
	for _, fixture := range manifest.Fixtures {
		input := readRecoveryProcess2Fixture(t, fixture.Name)
		r, err := parseRecoveryRecord(input.Record)
		if err != nil {
			t.Fatal(err)
		}
		if r.Schema != "keyvault-recovery/2" || r.Service != fixture.RootService || r.Nostr.Service != fixture.RootService || r.Namecoin.Service != fixture.NamecoinService ||
			r.Version != fixture.RecoveryVersion || r.Nostr.Version != fixture.NostrVersion || r.Namecoin.Version != fixture.NamecoinVersion || len(fixture.Files) != 5 || len(fixture.Bindings) != 2 {
			t.Fatalf("fixture %s does not preserve the independently selected service generations", fixture.Name)
		}
		for _, file := range []string{fixture.Name + "-record.json", fixture.Name + "-pair.json", fixture.Name + "-account-pin.json", fixture.Name + "-sidecar.kvns", fixture.Name + "-selection.json"} {
			value, err := os.ReadFile(filepath.Join(recoveryProcess2FixtureDir(t), file))
			if err != nil {
				t.Fatalf("fixture file %s unavailable", file)
			}
			pin, ok := fixture.Files[file]
			sum := sha256.Sum256(value)
			if !ok || pin.Size != len(value) || pin.SHA256 != hex.EncodeToString(sum[:]) {
				t.Fatalf("fixture file %s does not match the manifest", file)
			}
		}
		for _, binding := range fixture.Bindings {
			var purpose RecoveryPurpose
			switch binding.Purpose {
			case "nostr":
				purpose = r.Nostr
			case "namecoin":
				purpose = r.Namecoin
			default:
				t.Fatalf("unknown fixture purpose %q", binding.Purpose)
			}
			preimage := recoveryProcess2IndependentBindingPreimage(r, purpose, input.Record)
			digest := sha256.Sum256(preimage)
			production := recoveryBinding(r, purpose)
			if binding.Domain != "works.relux.mac-keyvault.recovery-envelope.v2" || binding.Namespace != "works.relux.mac-keyvault."+purpose.Purpose+"-wrap.v1" ||
				binding.PhysicalAccount != r.Service+"/recovery@"+strconv.Itoa(r.Version) || binding.MetadataFile != fixture.Name+"-record.json" ||
				binding.LogicalAccount != recoveryProcess2ExpectedLogicalAccount(r, purpose) || binding.WrappingPoint != hex.EncodeToString(purpose.WrappingPoint) ||
				binding.PreimageSHA256 != hex.EncodeToString(digest[:]) || binding.BindingSHA256 != hex.EncodeToString(production[:]) ||
				!bytes.Equal(digest[:], production[:]) {
				t.Fatalf("%s purpose %s independent binding mismatch", fixture.Name, purpose.Purpose)
			}
		}
	}
}

func recoveryProcess2ExpectedLogicalAccount(r RecoveryRecord, p RecoveryPurpose) string {
	service := r.Service
	if r.Schema == "keyvault-recovery/2" {
		if p.Purpose == "nostr" {
			service = r.Nostr.Service
		} else {
			service = r.Namecoin.Service
		}
	}
	return service + "/" + p.Purpose + "@" + strconv.Itoa(p.Version)
}
