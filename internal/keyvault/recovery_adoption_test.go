package keyvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// These existing fixtures are public sealed data. No derivation, key access,
// native identity, Keychain, consent or successful OS mutation is simulated.
func adoptionPublicSelection(t testing.TB, variant int) *recoveryAdoptionSelection {
	t.Helper()
	metadata, e := os.ReadFile("testdata/recovery/v1-public-record.json")
	if e != nil {
		t.Fatal("public record fixture unavailable")
	}
	sealed, e := os.ReadFile("testdata/recovery/v1-public-ciphertext.json")
	if e != nil {
		t.Fatal("public sealed fixture unavailable")
	}
	metadata, sealed = bytes.TrimSpace(metadata), bytes.TrimSpace(sealed)
	if variant != 0 {
		r, err := parseRecoveryRecord(metadata)
		if err != nil {
			t.Fatal("public metadata fixture refused")
		}
		c, err := parseRecoveryCiphertext(sealed, r)
		if err != nil {
			t.Fatal("public sealed fixture refused")
		}
		r.Schema = "keyvault-recovery/2"
		r.Nostr.Service = r.Service
		r.Namecoin.Service = r.Service
		if variant == 2 {
			r.Namecoin.Service = "other"
		}
		c.Schema = "keyvault-recovery-ciphertext/2"
		metadata, _ = json.Marshal(r)
		sealed, _ = json.Marshal(c)
	}
	r, err := parseRecoveryRecord(metadata)
	if err != nil {
		t.Fatal("public record fixture refused")
	}
	s, err := newRecoveryAdoptionSelection(r.Account(), metadata, sealed, []byte("public-disposable-reference"),
		"/public/old-vault", bytes.Repeat([]byte{0x11}, 20), "/public/new-vault", bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal("valid public selection refused")
	}
	t.Cleanup(s.clear)
	return s
}

// Synthetic app data and authorization labels test the portable invariant only;
// they are deliberately NOT trusted-app objects or native identity evidence.
func adoptionTestACL(app []byte, change func(int, *[]byte, *[]byte)) []byte {
	frame := []byte("KVAC1")
	for _, v := range []uint32{501, 20, 0, 2} {
		frame = binary.BigEndian.AppendUint32(frame, v)
	}
	for i := 0; i < 2; i++ {
		state := binary.BigEndian.AppendUint32(nil, 1)
		name := "change-acl"
		if i == 1 {
			name = "decrypt"
		}
		state = recoveryAdoptionField(state, []byte(name))
		state = binary.BigEndian.AppendUint32(state, 1)
		state = recoveryAdoptionField(state, []byte("public descriptor"))
		state = binary.BigEndian.AppendUint32(state, 7) // preserve full CSSM version
		state = binary.BigEndian.AppendUint32(state, 0x91)
		applications := binary.BigEndian.AppendUint32(nil, 0) // null, not empty
		applications = binary.BigEndian.AppendUint32(applications, 0)
		if i == 1 {
			applications = recoveryAdoptionSoleApplication(app)
		}
		if change != nil {
			change(i, &state, &applications)
		}
		kind := uint32(i)
		frame = binary.BigEndian.AppendUint32(frame, kind)
		frame = recoveryAdoptionField(frame, state)
		frame = recoveryAdoptionField(frame, applications)
	}
	return recoveryAdoptionField(frame, []byte("KVAR1public-preserved-raw-state"))
}

func adoptionTestAttributes(s *recoveryAdoptionSelection) []byte {
	out := []byte("KVAT1")
	out = binary.BigEndian.AppendUint32(out, 5)
	for _, a := range []struct {
		tag   uint32
		value []byte
	}{
		{0x61636374, []byte(s.account)}, {0x69636d74, s.metadata}, {0x6c61626c, []byte(s.account)},
		{0x6d646174, []byte("public-modification-date")}, {0x73766365, []byte(recoveryAdoptionService)},
	} {
		out = binary.BigEndian.AppendUint32(out, a.tag)
		out = binary.BigEndian.AppendUint32(out, 6)
		out = recoveryAdoptionField(out, a.value)
	}
	return out
}
func adoptionTestFrame(s *recoveryAdoptionSelection) []byte {
	old, next := []byte("public-old-app"), []byte("public-new-app")
	out := []byte("KVAD1")
	for _, v := range [][]byte{old, next, adoptionTestAttributes(s), adoptionTestACL(old, nil), adoptionTestACL(next, nil)} {
		out = recoveryAdoptionField(out, v)
	}
	return out
}

// Valid v1 and same/different-service v2 selections remain admissible. Positive
// software plans do not qualify the OS ACL form or authorize an owner sitting.
func TestRecoveryAdoptionSelectionCompatibilityAndOwnership(t *testing.T) {
	for _, variant := range []int{0, 1, 2} {
		s := adoptionPublicSelection(t, variant)
		frame := adoptionTestFrame(s)
		plan, err := newRecoveryAdoptionPlan(s, frame)
		if err != nil {
			t.Fatal("valid public adoption plan refused")
		}
		defer plan.clear()
		doc, digest := plan.reviewDocument()
		before := bytes.Clone(doc)
		if !bytes.Contains(doc, []byte(s.account)) || !bytes.Contains(doc, []byte(recoveryAdoptionService)) || len(digest) != 64 {
			t.Fatal("public review incomplete")
		}
		s.metadata[0] ^= 1
		s.sealed[0] ^= 1
		s.persistent[0] ^= 1
		s.old.hash[0] ^= 1
		frame[0] ^= 1
		doc[0] ^= 1
		after, hash := plan.reviewDocument()
		if !bytes.Equal(after, before) || digest != hash {
			t.Fatal("mutable input changed frozen plan")
		}
		if strings.Contains(fmt.Sprintf("%v %#v %v %#v", s, s, plan, plan), "public-disposable-reference") {
			t.Fatal("opaque diagnostics exposed selected bytes")
		}
		plan.clear()
		plan.clear()
	}
}

func TestRecoveryAdoptionSelectionRefusals(t *testing.T) {
	s := adoptionPublicSelection(t, 0)
	cases := []struct {
		account                      string
		metadata, sealed, persistent []byte
		oldPath                      string
		oldHash                      []byte
		newPath                      string
		newHash                      []byte
	}{
		{"other/recovery@1", s.metadata, s.sealed, s.persistent, s.old.path, s.old.hash, s.next.path, s.next.hash},
		{s.account, append(bytes.Clone(s.metadata), ' '), s.sealed, s.persistent, s.old.path, s.old.hash, s.next.path, s.next.hash},
		{s.account, s.metadata, nil, s.persistent, s.old.path, s.old.hash, s.next.path, s.next.hash},
		{s.account, s.metadata, s.sealed[:30], s.persistent, s.old.path, s.old.hash, s.next.path, s.next.hash},
		{s.account, s.metadata, s.sealed, nil, s.old.path, s.old.hash, s.next.path, s.next.hash},
		{s.account, s.metadata, s.sealed, make([]byte, 4097), s.old.path, s.old.hash, s.next.path, s.next.hash},
		{s.account, s.metadata, s.sealed, s.persistent, s.old.path, s.old.hash[:19], s.next.path, s.next.hash},
		{s.account, s.metadata, s.sealed, s.persistent, s.old.path, s.old.hash, s.next.path, s.old.hash},
		{s.account, s.metadata, s.sealed, s.persistent, s.old.path, s.old.hash, s.old.path, s.next.hash},
	}
	for i, c := range cases {
		v, err := newRecoveryAdoptionSelection(c.account, c.metadata, c.sealed, c.persistent, c.oldPath, c.oldHash, c.newPath, c.newHash)
		if v != nil || err != errRecoveryAdoptionInvalid {
			t.Fatalf("invalid selection case %d admitted", i)
		}
	}
	for _, bad := range []string{"relative", "/", "/public/../vault", "/public//vault", "/public/vault\x00suffix", "/public/vault\n", "/public/\xff", strings.Repeat("a", 4096)} {
		if _, err := recoveryAdoptionIdentity(bad, s.old.hash); err == nil {
			t.Fatal("forbidden identity path admitted")
		}
	}
	for _, n := range []int{20, 32} {
		if _, err := recoveryAdoptionIdentity("/public/vault", make([]byte, n)); err != nil {
			t.Fatal("valid public hash size refused")
		}
	}
}

// Pair a sole-old -> sole-new positive with every non-write-set change. No
// native success is mocked, and unknown/private Apple subject forms are unproved.
func TestRecoveryAdoptionACLWriteSet(t *testing.T) {
	old, next := []byte("public-old-app"), []byte("public-new-app")
	before, after := adoptionTestACL(old, nil), adoptionTestACL(next, nil)
	if !recoveryAdoptionACLTransition(before, after, old, next) {
		t.Fatal("sole application substitution refused")
	}
	for _, altered := range [][]byte{
		adoptionTestACL(old, nil),
		adoptionTestACL(next, func(i int, state, apps *[]byte) {
			if i == 0 {
				*apps = recoveryAdoptionSoleApplication(next)
			}
		}),
		adoptionTestACL(next, func(i int, state, apps *[]byte) {
			if i == 1 {
				*apps = recoveryAdoptionSoleApplication(old)
			}
		}),
		adoptionTestACL(next, func(i int, state, apps *[]byte) {
			if i == 1 {
				*apps = append(recoveryAdoptionSoleApplication(next), recoveryAdoptionField(nil, old)...)
				binary.BigEndian.PutUint32((*apps)[4:8], 2)
			}
		}),
		adoptionTestACL(next, func(i int, state, apps *[]byte) {
			if i == 0 {
				(*apps)[3] = 1
			}
		}), // null -> empty
		adoptionTestACL(next, func(i int, state, apps *[]byte) {
			if i == 1 {
				(*state)[len(*state)-1] ^= 1
			}
		}),
		adoptionTestACL(next, func(i int, state, apps *[]byte) {
			if i == 0 {
				(*state)[len(*state)-5] ^= 1
			}
		}),
		bytes.Replace(after, []byte("public descriptor"), []byte("public alteredval"), 1),
		bytes.Replace(after, []byte("change-acl"), []byte("change-own"), 1),
		bytes.Replace(after, []byte("KVAR1public-preserved"), []byte("KVAR1public-alteredxx"), 1),
	} {
		if recoveryAdoptionACLTransition(before, altered, old, next) {
			t.Fatal("out-of-scope ACL change admitted")
		}
	}
	altered := bytes.Clone(after)
	altered[8] ^= 1
	if recoveryAdoptionACLTransition(before, altered, old, next) {
		t.Fatal("owner change admitted")
	}
	if recoveryAdoptionACLTransition(before, after[:len(after)-1], old, next) {
		t.Fatal("truncated ACL admitted")
	}
}

// A mixed authorization cannot share the changed application list, and an
// unchanged no-decrypt frame is not an adoption positive.
func TestRecoveryAdoptionExclusiveDecryptAndRequiredChange(t *testing.T) {
	old, next := []byte("public-old-app"), []byte("public-new-app")
	before := adoptionTestACL(old, nil)
	mixed := adoptionTestACL(next, func(i int, state, apps *[]byte) {
		if i != 1 {
			return
		}
		reader := recoveryAdoptionReader{(*state)[4:]}
		first, ok := reader.field()
		if !ok {
			t.Fatal("fixture state malformed")
		}
		out := binary.BigEndian.AppendUint32(nil, 2)
		out = recoveryAdoptionField(out, first)
		out = recoveryAdoptionField(out, []byte("sign"))
		*state = append(out, reader.rest...)
	})
	if recoveryAdoptionACLTransition(before, mixed, old, next) {
		t.Fatal("mixed decrypt authorization admitted")
	}
	noDecrypt := bytes.Clone(before)
	r := recoveryAdoptionReader{noDecrypt[21:]}
	_, _ = r.u32()
	_, _ = r.field()
	_, _ = r.field()
	at := len(noDecrypt) - len(r.rest)
	binary.BigEndian.PutUint32(noDecrypt[at:at+4], 0)
	if recoveryAdoptionACLTransition(noDecrypt, noDecrypt, old, next) {
		t.Fatal("absent decrypt change admitted")
	}
}

func TestRecoveryAdoptionFrameAndSelectionBinding(t *testing.T) {
	s := adoptionPublicSelection(t, 0)
	good := adoptionTestFrame(s)
	if _, err := parseRecoveryAdoptionNativeFrame(good); err != nil {
		t.Fatal("valid public frame refused")
	}
	for i := 0; i < len(good); i++ {
		if _, err := parseRecoveryAdoptionNativeFrame(good[:i]); err == nil {
			t.Fatal("truncated native frame admitted")
		}
	}
	for _, bad := range [][]byte{append(bytes.Clone(good), 0), []byte("KVAD1\xff\xff\xff\xff"), bytes.Repeat([]byte{0}, recoveryAdoptionMaxFrame+1)} {
		if _, err := parseRecoveryAdoptionNativeFrame(bad); err == nil {
			t.Fatal("invalid native frame admitted")
		}
	}
	for _, token := range [][]byte{[]byte(s.account), []byte(recoveryAdoptionService), []byte("keyvault-recovery/1")} {
		bad := bytes.Clone(good)
		at := bytes.Index(bad, token)
		if at < 0 {
			t.Fatal("fixture lacks selection field")
		}
		bad[at] ^= 1
		if p, err := newRecoveryAdoptionPlan(s, bad); p != nil || err == nil {
			t.Fatal("mismatched native selection admitted")
		}
	}
}

// Byte-preservation and review binding are not envelope authentication. A
// shape-valid sealed-byte change must change review; no account is decrypted.
func TestRecoveryAdoptionSealedBytesBindReview(t *testing.T) {
	s := adoptionPublicSelection(t, 0)
	frame := adoptionTestFrame(s)
	p, err := newRecoveryAdoptionPlan(s, frame)
	if err != nil {
		t.Fatal("public positive plan refused")
	}
	defer p.clear()
	r, _ := parseRecoveryRecord(s.metadata)
	c, _ := parseRecoveryCiphertext(s.sealed, r)
	c.Namecoin.Ciphertext[len(c.Namecoin.Ciphertext)-1] ^= 1
	sealed, _ := json.Marshal(c)
	altered, err := newRecoveryAdoptionSelection(s.account, s.metadata, sealed, s.persistent, s.old.path, s.old.hash, s.next.path, s.next.hash)
	if err != nil {
		t.Fatal("shape-valid public sealed control refused")
	}
	defer altered.clear()
	q, err := newRecoveryAdoptionPlan(altered, frame)
	if err != nil {
		t.Fatal("public changed-value control refused")
	}
	defer q.clear()
	_, a := p.reviewDocument()
	_, b := q.reviewDocument()
	if a == b {
		t.Fatal("changed purpose ciphertext did not alter review")
	}
	want := sha256.Sum256(p.review)
	if p.digest != want {
		t.Fatal("review digest does not bind full document")
	}
}

// Native statuses do not become raw OS diagnostics. A failed or contradictory
// post-mutation reply remains UNKNOWN. This tests classification, not OS writes.
func TestRecoveryAdoptionOutcomeBoundary(t *testing.T) {
	for _, c := range []struct {
		status    int
		attempted bool
		want      error
	}{
		{0, true, nil}, {1, false, errRecoveryAdoptionNative}, {-25293, false, errRecoveryAdoptionNative},
		{0, false, errRecoveryAdoptionNative}, {1, true, errRecoveryAdoptionUnknown}, {2, true, errRecoveryAdoptionUnknown}, {2, false, errRecoveryAdoptionUnknown}, {-50, true, errRecoveryAdoptionUnknown},
	} {
		if recoveryAdoptionResult(c.status, c.attempted) != c.want {
			t.Fatal("unsafe adoption outcome classification")
		}
	}
}

func FuzzRecoveryAdoptionNativeFrame(f *testing.F) {
	f.Add([]byte("KVAD1"))
	f.Add([]byte("KVAD1\xff\xff\xff\xff"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = parseRecoveryAdoptionNativeFrame(raw) // no native APIs, no byte diagnostics
	})
}

// Literal oracle independently constructed with stdlib framing/SHA256 from
// the retained public fixtures, not from this implementation or native calls.
func TestRecoveryAdoptionPublicReviewVector(t *testing.T) {
	s := adoptionPublicSelection(t, 0)
	frame := adoptionTestFrame(s)
	hash := sha256.Sum256(frame)
	if hex.EncodeToString(hash[:]) != "9bcb08611eb5f90d2ae996967be29add77f8bf0302178b984ef4de5adbf8ea2d" {
		t.Fatal("public native-frame vector changed")
	}
	p, err := newRecoveryAdoptionPlan(s, frame)
	if err != nil {
		t.Fatal("public vector refused")
	}
	defer p.clear()
	doc, digest := p.reviewDocument()
	if len(doc) != 3379 || digest != "42bee0e2bed6d94dfc9b72ad3c75053ef494b94dc5b3ec37a37823b02e86a4af" {
		t.Fatal("public review vector changed")
	}
}
