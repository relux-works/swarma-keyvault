package namecoinpsbt

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

func fixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{"testdata"}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func requestFixture(t *testing.T, mode, slot string) namecoinwire.Request {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "namecoinwire", "testdata", mode, slot+"-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r namecoinwire.Request
	if err = json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r
}
func snapshot(t *testing.T, r namecoinwire.Request) namecoinwire.Snapshot {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	s, err := namecoinwire.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func candidate(t *testing.T, mode, slot string) Candidate {
	t.Helper()
	c, err := Inspect(snapshot(t, requestFixture(t, mode, slot)), fixture(t, mode, "account-pin.json"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func signedFixture(t *testing.T, mode, slot string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(fixture(t, mode, slot+"-signed.psbt"))))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func requireCode(t *testing.T, err error, code namecoinwire.Code) {
	t.Helper()
	var f namecoinwire.Failure
	if !errors.As(err, &f) || f.Code() != code {
		t.Fatalf("want closed code %s, got %v", code, err)
	}
}

// All eight actual Core-produced public PSBTs pass structural/account checks;
// each signature verifies against our independent BIP143 implementation, and
// witness assembly reproduces Core's exact finalized transaction bytes. These
// public fixtures do not prove native custody, consent or journal provenance.
func TestCoreRegistrationGraphsAndSignatures(t *testing.T) {
	for _, mode := range []string{"all-four-before-release", "two-stage"} {
		for _, slot := range []string{"A", "B", "C", "D"} {
			t.Run(mode+"/"+slot, func(t *testing.T) {
				c := candidate(t, mode, slot)
				view := c.View()
				expectedInputs := 1
				if slot == "C" || slot == "D" {
					expectedInputs = 2
				}
				if len(view.Inputs) != expectedInputs || len(view.Outputs) != 2 || view.Fee != 100000 || view.InputTotal-view.OutputTotal != view.Fee || view.NameAmount != 1000000 {
					t.Fatal("computed fixture facts differ")
				}
				sigs, err := c.VerifySignedPSBT(signedFixture(t, mode, slot))
				if err != nil {
					t.Fatal("Core public signature refused", err)
				}
				psbt, final, err := c.Assemble(sigs)
				if err != nil {
					t.Fatal(err)
				}
				want, err := hex.DecodeString(strings.TrimSpace(string(fixture(t, mode, slot+"-final.hex"))))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(final, want) {
					t.Fatal("final transaction differs from actual Core")
				}
				if _, err := c.VerifySignedPSBT(psbt); err != nil {
					t.Fatal(err)
				}
				for i := range sigs {
					bad := make([][]byte, len(sigs))
					for j := range sigs {
						bad[j] = bytes.Clone(sigs[j])
					}
					bad[i][len(bad[i])-2] ^= 1
					requireCode(t, c.VerifySignatures(bad), namecoinwire.SighashRefused)
				}
			})
		}
	}
}

// Actual Core-emitted optional forms and map ordering stay compatible. The
// profile intentionally refuses unknown fields, missing full parents and
// non-ALL even where Core's general PSBT decoder accepts them.
func TestCorePSBTCompatibilityTable(t *testing.T) {
	for _, test := range []struct {
		name string
		code namecoinwire.Code
	}{
		{"explicit-version0", ""}, {"explicit-ALL", ""}, {"fullprev-no-witnessUTXO", ""}, {"reversed-map-order", ""},
		{"unknown-global-policy-refusal", namecoinwire.UnsupportedPSBT}, {"missing-fullprev-policy-refusal", namecoinwire.UnsupportedPSBT},
		{"non-ALL-policy-refusal", namecoinwire.SighashRefused}, {"duplicate-global-unsigned", namecoinwire.UnsupportedPSBT},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(fixture(t, "compatibility", test.name+".psbt"))))
			if err != nil {
				t.Fatal(err)
			}
			_, err = parsePacket(raw)
			if test.code != "" {
				requireCode(t, err, test.code)
			} else if err != nil {
				t.Fatal("legitimate Core form refused", err)
			}
		})
	}
}

// A matching optional account global xpub and complete origin is accepted;
// checksum/depth/key/origin mismatches fail independently of its fingerprint.
// This source-generated BIP174 positive supplements Core's xpub-free builder.
func TestMatchingGlobalXpubAndWrongAccountControls(t *testing.T) {
	c := candidate(t, "all-four-before-release", "A")
	p := c.packet
	value := append([]byte(nil), c.account.fingerprint[:]...)
	for _, child := range []uint32{0x80000054, 0x80000007, 0x80000000} {
		value = binary.LittleEndian.AppendUint32(value, child)
	}
	key := append([]byte{1}, c.account.serialized[:]...)
	extra := entry{key, value}
	encode := func(e entry) []byte {
		globals := append(append(section(nil), p.globals...), e)
		raw := appendSection([]byte{'p', 's', 'b', 't', 255}, globals)
		for _, i := range p.inputs {
			raw = appendSection(raw, i.entries)
		}
		for _, o := range p.outputMaps {
			raw = appendSection(raw, o)
		}
		return raw
	}
	r := requestFixture(t, "all-four-before-release", "A")
	r.PSBT = base64.StdEncoding.EncodeToString(encode(extra))
	if _, err := Inspect(snapshot(t, r), fixture(t, "all-four-before-release", "account-pin.json")); err != nil {
		t.Fatal("matching global xpub refused", err)
	}
	for _, mutation := range []struct {
		key    bool
		offset int
	}{{true, 5}, {true, 10}, {true, 46}, {false, 0}, {false, 4}, {false, 12}} {
		e := entry{bytes.Clone(key), bytes.Clone(value)}
		if mutation.key {
			e.key[mutation.offset] ^= 1
		} else {
			e.value[mutation.offset] ^= 1
		}
		r.PSBT = base64.StdEncoding.EncodeToString(encode(e))
		_, err := Inspect(snapshot(t, r), fixture(t, "all-four-before-release", "account-pin.json"))
		requireCode(t, err, namecoinwire.AccountMismatch)
	}
}

// Full-parent txids ignore witness bytes but bind every non-witness byte.
// A parent with a superfluous marker/unknown flags, noncanonical sizes,
// truncation or trailing bytes must not become an alternate admitted encoding.
func TestTransactionBoundsAndWitnessTxID(t *testing.T) {
	for _, mode := range []string{"all-four-before-release", "two-stage"} {
		c := candidate(t, mode, "C")
		parent := c.packet.inputs[0].previous
		witnessParent := parent
		witnessParent.inputs = append([]input(nil), parent.inputs...)
		witnessParent.segwit = true
		witnessParent.inputs[0].witness = [][]byte{{1, 2, 3}}
		raw := witnessParent.serialize(true)
		decoded, err := parseTransaction(raw, true)
		if err != nil || decoded.hash() != parent.hash() {
			t.Fatal("witness-bearing parent changes txid", err)
		}
		mutated := decoded
		mutated.locktime++
		if mutated.hash() == parent.hash() {
			t.Fatal("non-witness mutation did not change txid")
		}
		for _, bad := range [][]byte{raw[:len(raw)-1], append(bytes.Clone(raw), 0), append([]byte{0, 0, 0, 0, 0, 2}, raw[6:]...), append(append(bytes.Clone(raw[:4]), 253, 1, 0), raw[7:]...)} {
			if _, err := parseTransaction(bad, true); err == nil {
				t.Fatal("malformed transaction admitted")
			}
		}
		if _, err := parseTransaction(raw, false); err == nil {
			t.Fatal("unsigned transaction admitted witness serialization")
		}
	}
}

// Every signed fact below is independently covered by Core's existing
// signature: values, sequences, locktime, and complete name-bearing outputs.
func TestBIP143MutationAndWrongKeyControls(t *testing.T) {
	c := candidate(t, "all-four-before-release", "C")
	sigs, err := c.VerifySignedPSBT(signedFixture(t, "all-four-before-release", "C"))
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*transaction, *output, *[20]byte){
		func(tx *transaction, _ *output, _ *[20]byte) { tx.version++ },
		func(tx *transaction, _ *output, _ *[20]byte) { tx.locktime++ },
		func(tx *transaction, _ *output, _ *[20]byte) { tx.inputs[0].sequence-- },
		func(tx *transaction, _ *output, _ *[20]byte) { tx.outputs[0].script[2] ^= 1 },
		func(tx *transaction, _ *output, _ *[20]byte) { tx.outputs[1].amount++ },
		func(_ *transaction, prev *output, _ *[20]byte) { prev.amount++ },
		func(_ *transaction, _ *output, program *[20]byte) { program[0] ^= 1 },
	}
	for _, mutate := range mutations {
		tx, _ := parseTransaction(c.packet.tx.serialize(false), false)
		prev := c.packet.inputs[0].prevout
		f, _ := splitScript(prev.script)
		program := f.program
		mutate(&tx, &prev, &program)
		digest, err := tx.signatureHash(0, prev, program[:])
		if err != nil {
			t.Fatal(err)
		}
		if digest == c.digests[0] {
			t.Fatal("signed field omitted from digest")
		}
		changed := c
		changed.digests = append([][32]byte(nil), c.digests...)
		changed.digests[0] = digest
		requireCode(t, changed.VerifySignatures(sigs), namecoinwire.SighashRefused)
	}
	other := candidate(t, "all-four-before-release", "D")
	wrongKey, err := other.VerifySignedPSBT(signedFixture(t, "all-four-before-release", "D"))
	if err != nil {
		t.Fatal(err)
	}
	requireCode(t, c.VerifySignatures(wrongKey), namecoinwire.SighashRefused)
	for _, suffix := range []byte{0, 2, 3, 0x81, 0xff} {
		bad := make([][]byte, len(sigs))
		for i := range sigs {
			bad[i] = bytes.Clone(sigs[i])
		}
		bad[0][len(bad[0])-1] = suffix
		requireCode(t, c.VerifySignatures(bad), namecoinwire.SighashRefused)
	}
}

// Structural name prefixes cannot hide unsupported spend scripts or use a
// noncanonical push. Valid controls cover ordinary, reservation and reveal.
func TestNameScriptAllowlist(t *testing.T) {
	for _, slot := range []string{"A", "C"} {
		c := candidate(t, "all-four-before-release", slot)
		for _, o := range c.packet.tx.outputs {
			if _, err := splitScript(o.script); err != nil {
				t.Fatal(err)
			}
		}
	}
	c := candidate(t, "all-four-before-release", "A")
	good := c.packet.tx.outputs[0].script
	nonminimal := append([]byte{0x51, 76, 20}, good[2:]...)
	for _, bad := range [][]byte{nil, {0x51}, nonminimal, append(bytes.Clone(good), 0), {0xa9, 20}, append([]byte{0x51, 20}, good[2:len(good)-1]...), {0, 32}, {0x51, 20, 0}} {
		_, err := splitScript(bad)
		requireCode(t, err, namecoinwire.UnsupportedScript)
	}
}
