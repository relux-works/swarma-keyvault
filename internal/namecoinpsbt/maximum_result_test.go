package namecoinpsbt

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// These are process-contract limits, deliberately separate from the more
// permissive public library limits. No native process is started by this file.
const f4RequestLimit = 2 << 20
const f4PSBTLimit = 1 << 20
const f4ConsumerLimit = 6 << 20

type f4Measurement struct {
	AtUnsignedLimit         bool                `json:"at_unsigned_psbt_limit"`
	RequestSHA256           string              `json:"request_sha256"`
	ManifestSHA256          string              `json:"manifest_sha256"`
	GlobalMapBytes          int                 `json:"global_map_bytes"`
	InputMapBytes           []int               `json:"input_map_bytes"`
	OutputMapBytes          []int               `json:"output_map_bytes"`
	SyntheticPolicy         namecoinwire.Policy `json:"synthetic_policy"`
	SyntheticClockUnix      int64               `json:"synthetic_clock_unix"`
	Mode                    string              `json:"mode"`
	Slot                    string              `json:"slot"`
	OptionalMask            int                 `json:"optional_mask"`
	WitnessInput            int                 `json:"witness_input"`
	RequestBytes            int                 `json:"request_bytes"`
	ManifestBytes           int                 `json:"manifest_bytes"`
	EscapedManifestBytes    int                 `json:"escaped_manifest_bytes"`
	UnsignedPSBTBytes       int                 `json:"unsigned_psbt_bytes"`
	UnsignedBase64Bytes     int                 `json:"unsigned_base64_bytes"`
	SignedPSBTBytes         int                 `json:"signed_psbt_bytes"`
	SignedBase64Bytes       int                 `json:"signed_base64_bytes"`
	GlobalMapEntries        int                 `json:"global_map_entries"`
	InputMapEntries         []int               `json:"input_map_entries"`
	OutputMapEntries        []int               `json:"output_map_entries"`
	PreviousTotalBytes      []int               `json:"previous_total_bytes"`
	PreviousStrippedBytes   []int               `json:"previous_stripped_bytes"`
	Inputs                  int                 `json:"inputs"`
	Outputs                 int                 `json:"outputs"`
	SignatureDERBytes       []int               `json:"signature_der_bytes"`
	GroupBytes              int                 `json:"group_bytes"`
	AccountBytes            int                 `json:"account_bytes"`
	Sequence                uint64              `json:"dispatch_sequence"`
	SequenceDigits          int                 `json:"dispatch_sequence_digits"`
	ReceiptBytes            int                 `json:"receipt_bytes"`
	CanonicalResultBytes    int                 `json:"canonical_result_bytes_including_lf"`
	ResultSHA256            string              `json:"result_sha256"`
	FinalStrippedBytes      int                 `json:"final_stripped_bytes"`
	FinalTotalBytes         int                 `json:"final_total_bytes"`
	Weight                  int                 `json:"weight"`
	VSize                   int                 `json:"vsize"`
	FeeAtoms                uint64              `json:"fee_atoms"`
	FeeRateFloorAtomsPerKVB uint64              `json:"fee_rate_floor_atoms_per_kvb"`
	PublicChecks            string              `json:"public_checks"`
}

func f4MustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// Max-length synthetic identity labels affect only public commitments, not the
// spending keys or sighashes. The existing published Core signatures are reused.
func f4Base(t *testing.T, mode, slot string) (namecoinwire.Request, []byte, Candidate, [][]byte) {
	t.Helper()
	original := candidate(t, mode, slot)
	sigs, e := original.VerifySignedPSBT(signedFixture(t, mode, slot))
	if e != nil {
		t.Fatal(e)
	}
	pin, e := namecoinwire.DecodeAccountPin(fixture(t, mode, "account-pin.json"))
	if e != nil {
		t.Fatal(e)
	}
	pin.Group = strings.Repeat("g", 40) + "/recovery@2147483647"
	pin.Account = strings.Repeat("a", 40) + "/namecoin@2147483647"
	pinRaw := f4MustJSON(t, pin)
	hash := sha256.Sum256(pinRaw)
	r := requestFixture(t, mode, slot)
	var plan map[string]json.RawMessage
	if e = json.Unmarshal([]byte(r.ManifestUTF8), &plan); e != nil {
		t.Fatal(e)
	}
	plan["group"] = f4MustJSON(t, pin.Group)
	plan["account"] = f4MustJSON(t, pin.Account)
	plan["account_pin_sha256"] = f4MustJSON(t, hex.EncodeToString(hash[:]))
	r.ManifestUTF8 = string(f4MustJSON(t, plan))
	r.PlanSHA256 = namecoinwire.PlanDigest([]byte(r.ManifestUTF8))
	if slot == "A" || slot == "B" {
		r.ReservationPlanSHA256 = r.PlanSHA256
	}
	c, e := Inspect(snapshot(t, r), pinRaw)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.VerifySignatures(sigs); e != nil {
		t.Fatal(e)
	}
	return r, pinRaw, c, sigs
}

// Bits 0/1 select global xpub/version; each input then has independent
// sighash/witness-UTXO bits. All permitted optional-entry combinations are used.
func f4Options(c Candidate, mask int) packet {
	p := c.packet
	p.globals = append(section(nil), p.globals...)
	if mask&1 != 0 {
		value := append([]byte(nil), c.account.fingerprint[:]...)
		for _, v := range []uint32{0x80000054, 0x80000007, 0x80000000} {
			value = binary.LittleEndian.AppendUint32(value, v)
		}
		p.globals = append(p.globals, entry{append([]byte{1}, c.account.serialized[:]...), value})
	}
	if mask&2 != 0 {
		p.globals = append(p.globals, entry{[]byte{251}, []byte{0, 0, 0, 0}})
	}
	p.inputs = append([]packetInput(nil), p.inputs...)
	for i := range p.inputs {
		var entries section
		for _, e := range p.inputs[i].entries {
			if bytes.Equal(e.key, []byte{1}) || bytes.Equal(e.key, []byte{3}) {
				continue
			}
			entries = append(entries, e)
		}
		if mask&(1<<(2+2*i)) != 0 {
			entries = append(entries, entry{[]byte{3}, []byte{1, 0, 0, 0}})
		}
		if mask&(1<<(3+2*i)) != 0 {
			entries = append(entries, entry{[]byte{1}, serializeOutput(nil, p.inputs[i].prevout)})
		}
		p.inputs[i].entries = entries
	}
	return p
}

// A previous witness is syntactically admitted public data. It is not a claim
// that the synthetic witness was mined or that its spend is chain-qualified.
func f4Witness(p packet, inputIndex, payloadBytes, itemCount int) packet {
	p.inputs = append([]packetInput(nil), p.inputs...)
	in := p.inputs[inputIndex]
	tx := in.previous
	tx.inputs = append([]input(nil), tx.inputs...)
	tx.segwit = true
	for i := range tx.inputs {
		tx.inputs[i].witness = nil
	}
	tx.inputs[0].witness = make([][]byte, itemCount)
	tx.inputs[0].witness[0] = bytes.Repeat([]byte{0x5a}, payloadBytes)
	previous := tx.serialize(true)
	in.entries = append(section(nil), in.entries...)
	for j, e := range in.entries {
		if bytes.Equal(e.key, []byte{0}) {
			in.entries[j] = entry{e.key, previous}
		}
	}
	p.inputs[inputIndex] = in
	return p
}

func f4SizedPacket(t *testing.T, p packet, inputIndex, target int) []byte {
	t.Helper()
	payload := target - len(encodePacket(f4Witness(p, inputIndex, 0, 1)))
	for range 4 {
		if payload < 0 {
			t.Fatalf("target %d below fixture overhead", target)
		}
		raw := encodePacket(f4Witness(p, inputIndex, payload, 1))
		if len(raw) == target {
			return raw
		}
		payload += target - len(raw)
	}
	t.Fatalf("target %d unreachable across CompactSize discontinuity", target)
	return nil
}

func f4Candidate(t *testing.T, r namecoinwire.Request, pin, psbt []byte) (Candidate, []byte) {
	t.Helper()
	r.PSBT = base64.StdEncoding.EncodeToString(psbt)
	raw := f4MustJSON(t, r)
	s, e := namecoinwire.Decode(raw)
	if e != nil {
		t.Fatal(e)
	}
	c, e := Inspect(s, pin)
	if e != nil {
		t.Fatal(e)
	}
	return c, raw
}

func f4Measure(t *testing.T, mode string, mask, inputIndex int, c Candidate, request []byte, sigs [][]byte, sequence uint64) (f4Measurement, []byte) {
	t.Helper()
	selected := fixtureSelection(t, c)
	// This fixed synthetic fixture clock checks public admission only. It is not
	// historical reconstruction, fresh emission or the native actual-time gate.
	if e := c.Admit(selected, time.Unix(int64(selected.Policy.CreatedAt)+1, 0)); e != nil {
		t.Fatal(e)
	}
	if e := c.CheckFinalFeeRate(sigs, selected); e != nil {
		t.Fatal(e)
	}
	ctx, e := c.ReviewContext(selected)
	if e != nil {
		t.Fatal(e)
	}
	review, e := c.snapshot.ReviewDigest(ctx)
	if e != nil {
		t.Fatal(e)
	}
	head := sha256.Sum256([]byte("synthetic public dispatch correlation only"))
	result, e := c.ResultBytes(sigs, review, sequence, head)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.VerifyResult(result, review); e != nil {
		t.Fatal(e)
	}
	if e = namecoinwire.VerifyAcknowledgement(namecoinwire.Acknowledgement(sha256.Sum256(result)), result); e != nil {
		t.Fatal(e)
	}
	signed, final, e := c.Assemble(sigs)
	if e != nil {
		t.Fatal(e)
	}
	expectedFinal, e := hex.DecodeString(strings.TrimSpace(string(fixture(t, mode, c.View().Slot+"-final.hex"))))
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(final, expectedFinal) {
		t.Fatal("final transaction differs from unchanged Core fixture")
	}
	decoded, e := namecoinwire.DecodeResult(result)
	if e != nil {
		t.Fatal(e)
	}
	receipt := f4MustJSON(t, decoded.Receipt)
	// Independent wire ledger: two outer string fields, embedded receipt, LF;
	// base64 uses an alphabet requiring no JSON escaping. No decoded/file cap sum.
	want := len(`{"schema":"keyvault-namecoin-psbt-result/2","signed_psbt":"","receipt":}`) + base64.StdEncoding.EncodedLen(len(signed)) + len(receipt) + 1
	if len(result) != want || result[len(result)-1] != '\n' {
		t.Fatalf("canonical result ledger: got %d want %d", len(result), want)
	}
	added := 0
	for _, s := range sigs {
		added += 1 + 34 + 1 + len(s)
	}
	if len(signed) != len(c.snapshot.PSBTBytes())+added {
		t.Fatal("partial signature entry ledger differs")
	}
	if !bytes.Equal(f4MustJSON(t, decoded), result[:len(result)-1]) {
		t.Fatal("noncanonical producer serialization")
	}
	base := len(c.packet.tx.serialize(false))
	weight := 3*base + len(final)
	m := f4Measurement{Mode: mode, Slot: c.View().Slot, OptionalMask: mask, WitnessInput: inputIndex, RequestBytes: len(request), ManifestBytes: len(c.snapshot.ManifestBytes()), EscapedManifestBytes: len(f4MustJSON(t, c.snapshot.Request().ManifestUTF8)), UnsignedPSBTBytes: len(c.snapshot.PSBTBytes()), UnsignedBase64Bytes: base64.StdEncoding.EncodedLen(len(c.snapshot.PSBTBytes())), SignedPSBTBytes: len(signed), SignedBase64Bytes: base64.StdEncoding.EncodedLen(len(signed)), GlobalMapEntries: len(c.packet.globals), Inputs: len(c.packet.inputs), Outputs: len(c.packet.outputs), GroupBytes: len(selected.Group), AccountBytes: len(selected.Account), Sequence: sequence, SequenceDigits: len(strconv.FormatUint(sequence, 10)), ReceiptBytes: len(receipt), CanonicalResultBytes: len(result), ResultSHA256: fmt.Sprintf("%x", sha256.Sum256(result)), FinalStrippedBytes: base, FinalTotalBytes: len(final), Weight: weight, VSize: (weight + 3) / 4, FeeAtoms: c.View().Fee, FeeRateFloorAtomsPerKVB: c.View().Fee * 1000 / uint64((weight+3)/4), PublicChecks: "Decode,Inspect,Admit(synthetic clock),VerifySignatures,CheckFinalFeeRate,ResultBytes,VerifyResult,exact ACK hash: PASS; native history/reachability/timing: UNVERIFIED"}
	m.AtUnsignedLimit = m.UnsignedPSBTBytes == f4PSBTLimit
	m.RequestSHA256 = fmt.Sprintf("%x", sha256.Sum256(request))
	m.ManifestSHA256 = fmt.Sprintf("%x", sha256.Sum256(c.snapshot.ManifestBytes()))
	m.GlobalMapBytes = len(appendSection(nil, c.packet.globals))
	m.SyntheticPolicy = selected.Policy
	m.SyntheticClockUnix = int64(selected.Policy.CreatedAt) + 1
	for i, in := range c.packet.inputs {
		m.InputMapBytes = append(m.InputMapBytes, len(appendSection(nil, in.entries)))
		m.InputMapEntries = append(m.InputMapEntries, len(in.entries))
		m.PreviousTotalBytes = append(m.PreviousTotalBytes, len(in.previous.serialize(true)))
		m.PreviousStrippedBytes = append(m.PreviousStrippedBytes, len(in.previous.serialize(false)))
		m.SignatureDERBytes = append(m.SignatureDERBytes, len(sigs[i])-1)
	}
	for _, out := range c.packet.outputMaps {
		m.OutputMapEntries = append(m.OutputMapEntries, len(out))
		m.OutputMapBytes = append(m.OutputMapBytes, len(appendSection(nil, out)))
	}
	maps := 5 + m.GlobalMapBytes
	for _, n := range m.InputMapBytes {
		maps += n
	}
	for _, n := range m.OutputMapBytes {
		maps += n
	}
	if maps != m.UnsignedPSBTBytes {
		t.Fatal("original map serialization ledger differs")
	}
	if m.RequestBytes > f4RequestLimit || m.ManifestBytes > namecoinwire.MaxManifestBytes || m.UnsignedPSBTBytes > f4PSBTLimit || len(result) > f4ConsumerLimit {
		t.Fatal("simultaneous process bounds exceeded")
	}
	return m, result
}

// Every legal optional-map combination and selected-parent witness location is
// checked in all eight public fixture families. Both optional-map extrema then
// saturate 1MiB at every location. The exact insertion ledger makes maximum
// result LENGTH independent of intermediate optional maps at that same cap.
// Core signatures stay unchanged; native maximum/reachability is not proved.
func TestF4MaximumCanonicalResults(t *testing.T) {
	var measurements []f4Measurement
	maxResult := 0
	saturated := 0
	var largest f4Measurement
	var largestRequest, largestResult, largestPin []byte
	for _, mode := range []string{"all-four-before-release", "two-stage"} {
		for _, slot := range []string{"A", "B", "C", "D"} {
			t.Run(mode+"/"+slot, func(t *testing.T) {
				r, pin, base, sigs := f4Base(t, mode, slot)
				for mask := 0; mask < 1<<(2+2*len(base.View().Inputs)); mask++ {
					for inputIndex := range base.View().Inputs {
						p := f4Options(base, mask)
						cases := [][]byte{encodePacket(f4Witness(p, inputIndex, 253, 1))}
						if mask == 0 || mask == (1<<(2+2*len(base.View().Inputs)))-1 {
							cases = append(cases, f4SizedPacket(t, p, inputIndex, f4PSBTLimit))
						}
						for _, psbt := range cases {
							c, raw := f4Candidate(t, r, pin, psbt)
							m, result := f4Measure(t, mode, mask, inputIndex, c, raw, sigs, 65535)
							measurements = append(measurements, m)
							if m.AtUnsignedLimit {
								saturated++
							}
							if m.CanonicalResultBytes > maxResult {
								maxResult = m.CanonicalResultBytes
								largest = m
								largestRequest, largestResult, largestPin = raw, result, pin
							}
						}
					}
				}
			})
		}
	}
	if len(measurements) != 600 || saturated != 24 {
		t.Fatalf("matrix incomplete: %d measurements, %d saturated", len(measurements), saturated)
	}
	// A universal public-format bound uses two 71-byte DERs, maximum identities,
	// the longest network, and even the full uint64 sequence. It over-approximates
	// durable history (<=65536 records including S); it asserts no reachability.
	upper := f4SerializationUpper(t)
	if maxResult > upper || upper >= f4ConsumerLimit {
		t.Fatalf("size bound failed: measured %d upper %d", maxResult, upper)
	}
	t.Logf("F4 measurements=%d cap_saturated=24 largest=%d serialization_upper=%d consumer_limit=%d", len(measurements), maxResult, upper, f4ConsumerLimit)
	if path := os.Getenv("NAMECOIN_F4_RECEIPT"); path != "" {
		receipt := struct {
			Schema             string          `json:"schema"`
			Native             string          `json:"native"`
			MaximumClaim       string          `json:"maximum_claim"`
			Largest            f4Measurement   `json:"largest"`
			SerializationUpper int             `json:"serialization_upper_bytes"`
			Measurements       []f4Measurement `json:"measurements"`
		}{"namecoin-canonical-result-measurement/1", "UNVERIFIED", "All optional maps checked; cap-saturated extrema measured; universal upper is not an attained native maximum", largest, upper, measurements}
		for suffix, raw := range map[string][]byte{".request.json": largestRequest, ".result.json": largestResult, ".pin.json": largestPin} {
			if e := os.WriteFile(path+suffix, raw, 0600); e != nil {
				t.Fatal(e)
			}
		}
		if e := os.WriteFile(path, append(f4MustJSON(t, receipt), '\n'), 0600); e != nil {
			t.Fatal(e)
		}
	}
}

func f4SerializationUpper(t *testing.T) int {
	t.Helper()
	// Width accounting independent of the implementation's encoder. All string
	// fields have fixed safe alphabets; no receipt field can require escaping.
	stringsByKey := []struct {
		k string
		n int
	}{
		{"schema", len("keyvault-namecoin-psbt-receipt/2")}, {"status", 6}, {"request_id", 64}, {"sitting_id", 64}, {"slot", 1}, {"plan_sha256", 64}, {"reservation_plan_sha256", 64}, {"review_sha256", 64}, {"network", len("namecoin-regtest")}, {"group", 60}, {"account", 60}, {"account_pin_sha256", 64}, {"unsigned_txid", 64}, {"signed_psbt_sha256", 64}, {"journal_head_sha256", 64},
	}
	receipt := 2 // object braces
	fields := len(stringsByKey) + 2
	receipt += fields - 1 // commas
	for _, f := range stringsByKey {
		receipt += len(f.k) + 5 + f.n
	} // quoted key, colon, quoted value
	receipt += len(`"journal_sequence":`) + 20
	// Two signatures: each entry has one-digit index, fixed labels and maximum
	// 142-character strict DER hex. Object commas and array punctuation included.
	sig := len(`{"index":0,"pubkey":"","algorithm":"secp256k1-ecdsa","encoding":"strict-der-low-s","sighash":"ALL","signature":""}`) + 66 + 142
	receipt += len(`"input_signatures":`) + 2 + 2*sig + 1
	signed := f4PSBTLimit + 2*(1+34+1+72)
	return len(`{"schema":"keyvault-namecoin-psbt-result/2","signed_psbt":"","receipt":}`) + base64.StdEncoding.EncodedLen(signed) + receipt + 1
}

// CompactSize witness item/count/section-length transitions remain valid;
// changed stripped prevouts and unknown PSBT entries reach their exact refusals.
func TestF4WitnessTransitionsAndForbiddenShapes(t *testing.T) {
	r, pin, base, sigs := f4Base(t, "two-stage", "C")
	for _, size := range []int{0, 1, 252, 253, 65535, 65536} {
		for _, count := range []int{1, 252, 253, 1000} {
			p := f4Witness(f4Options(base, 63), 0, size, count)
			c, _ := f4Candidate(t, r, pin, encodePacket(p))
			if e := c.VerifySignatures(sigs); e != nil {
				t.Fatal(e)
			}
		}
	}
	p := f4Options(base, 63)
	p.inputs[0].entries = append(p.inputs[0].entries, entry{[]byte{0xfc}, []byte{1}})
	bad := r
	bad.PSBT = base64.StdEncoding.EncodeToString(encodePacket(p))
	_, e := Inspect(snapshot(t, bad), pin)
	requireCode(t, e, namecoinwire.UnsupportedPSBT)
	p = f4Witness(f4Options(base, 63), 0, 253, 1)
	for j, e := range p.inputs[0].entries {
		if bytes.Equal(e.key, []byte{0}) {
			v := bytes.Clone(e.value)
			v[len(v)-1] ^= 1
			p.inputs[0].entries[j].value = v
		}
	}
	bad = r
	bad.PSBT = base64.StdEncoding.EncodeToString(encodePacket(p))
	_, e = Inspect(snapshot(t, bad), pin)
	requireCode(t, e, namecoinwire.PrevoutMismatch)
	p = f4Witness(f4Options(base, 63), 0, 1, 1001)
	bad = r
	bad.PSBT = base64.StdEncoding.EncodeToString(encodePacket(p))
	_, e = Inspect(snapshot(t, bad), pin)
	requireCode(t, e, namecoinwire.UnsupportedPSBT)
	// Generic 128-input decoder bounds do not widen this phase graph.
	plan := base.snapshot.Plan()
	if e := checkPhaseGraph(plan); e != nil {
		t.Fatal(e)
	}
	tx, e := parseTransaction(decodeHex(plan.Transactions[0].UnsignedHex), false)
	if e != nil {
		t.Fatal(e)
	}
	originalInput, originalMeta := tx.inputs[0], plan.Transactions[0].Inputs[0]
	tx.inputs = make([]input, 128)
	plan.Transactions[0].Inputs = make([]namecoinwire.Input, 128)
	for i := range tx.inputs {
		tx.inputs[i] = originalInput
		plan.Transactions[0].Inputs[i] = originalMeta
	}
	plan.Transactions[0].UnsignedHex = hex.EncodeToString(tx.serialize(false))
	plan.Transactions[0].UnsignedTxID = rpcHash(tx.hash())
	// Decoder and metadata cardinality agree at 128. The phase-specific
	// selected-input constraint is reached; no signature/admission is claimed.
	if _, e := parseTransaction(decodeHex(plan.Transactions[0].UnsignedHex), false); e != nil {
		t.Fatal(e)
	}
	requireCode(t, checkPhaseGraph(plan), namecoinwire.IntentMismatch)
}

// Valid signed JSON plus legal outer whitespace reaches the consumer envelope
// neighbors; exact ACK hashes are recomputed. These are transport fixtures,
// never canonical producer measurements. Main's library cap is 8MiB, so the
// 6MiB process guard and post-sign UNKNOWN require separate integration proof.
func TestF4ConsumerBoundaryAndSchemaControls(t *testing.T) {
	c := candidate(t, "two-stage", "C")
	sigs, e := c.VerifySignedPSBT(signedFixture(t, "two-stage", "C"))
	if e != nil {
		t.Fatal(e)
	}
	selected := fixtureSelection(t, c)
	ctx, e := c.ReviewContext(selected)
	if e != nil {
		t.Fatal(e)
	}
	review, e := c.snapshot.ReviewDigest(ctx)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := c.ResultBytes(sigs, review, 65535, sha256.Sum256([]byte("public correlation")))
	if e != nil {
		t.Fatal(e)
	}
	for _, n := range []int{f4ConsumerLimit - 1, f4ConsumerLimit, f4ConsumerLimit + 1} {
		transport := append(bytes.Clone(raw), bytes.Repeat([]byte(" "), n-len(raw))...)
		if _, e = c.VerifyResult(transport, review); e != nil {
			t.Fatal(e)
		}
		if e = namecoinwire.VerifyAcknowledgement(namecoinwire.Acknowledgement(sha256.Sum256(transport)), transport); e != nil {
			t.Fatal(e)
		}
		if e = namecoinwire.VerifyAcknowledgement(namecoinwire.Acknowledgement(sha256.Sum256(raw)), transport); !errors.Is(e, namecoinwire.ErrInvalidRequest) {
			t.Fatalf("stale canonical ACK: want invalid request, got %v", e)
		}
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":0,"schema":`), 1),
		bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"duplicate","schema":`), 1),
		bytes.Replace(raw, []byte(`"status":"SIGNED"`), []byte(`"status":"UNKNOWN"`), 1),
	} {
		if _, e = namecoinwire.DecodeResult(bad); !errors.Is(e, namecoinwire.ErrInvalidRequest) {
			t.Fatalf("closed result schema: want invalid request, got %v", e)
		}
	}
	// Public formatter accepts uint64 width, but no completed 65536-record
	// history can authenticate this sequence. Keep it out of reachable receipts.
	wide, e := c.ResultBytes(sigs, review, math.MaxUint64, sha256.Sum256([]byte("width only")))
	if e != nil {
		t.Fatal(e)
	}
	if len(wide)-len(raw) != 15 {
		t.Fatal("sequence width accounting differs")
	}
}

// Size-neighbor fixtures retain real semantic commitments. The public library
// admits all three because its caps are wider; the process predicates are not
// claimed executed here. Oversize helper suppression belongs to its adapter.
func TestF4RequestAndPSBTSizeNeighbors(t *testing.T) {
	r, pin, base, sigs := f4Base(t, "two-stage", "A")
	for _, n := range []int{f4PSBTLimit - 1, f4PSBTLimit, f4PSBTLimit + 1} {
		c, raw := f4Candidate(t, r, pin, f4SizedPacket(t, f4Options(base, 15), 0, n))
		if e := c.VerifySignatures(sigs); e != nil {
			t.Fatal(e)
		}
		for _, size := range []int{f4RequestLimit - 1, f4RequestLimit, f4RequestLimit + 1} {
			transport := append(bytes.Clone(raw), bytes.Repeat([]byte(" "), size-len(raw))...)
			s, e := namecoinwire.Decode(transport)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = Inspect(s, pin); e != nil {
				t.Fatal(e)
			}
		}
	}
}

// Manifest escaping and request whitespace consume a joint budget. A maximum
// PSBT coexists with the exact request cap, but cannot coexist with the maximum
// manifest. This tests feasible combinations rather than adding independent caps.
func TestF4JointManifestRequestBudget(t *testing.T) {
	for _, mode := range []string{"all-four-before-release", "two-stage"} {
		for _, slot := range []string{"A", "B", "C", "D"} {
			t.Run(mode+"/"+slot, func(t *testing.T) {
				r, pin, base, sigs := f4Base(t, mode, slot)
				p := f4SizedPacket(t, f4Options(base, (1<<(2+2*len(base.View().Inputs)))-1), 0, f4PSBTLimit)
				r.PSBT = base64.StdEncoding.EncodeToString(p)
				initial := len(f4MustJSON(t, r))
				for _, ws := range []string{" ", "\t", "\r\n"} {
					changed := r
					width := len(f4MustJSON(t, ws)) - 2
					changed.ManifestUTF8 += strings.Repeat(ws, (f4RequestLimit-initial)/width)
					changed.PlanSHA256 = namecoinwire.PlanDigest([]byte(changed.ManifestUTF8))
					if slot == "A" || slot == "B" {
						changed.ReservationPlanSHA256 = changed.PlanSHA256
					}
					raw := f4MustJSON(t, changed)
					raw = append(raw, bytes.Repeat([]byte(" "), f4RequestLimit-len(raw))...)
					s, e := namecoinwire.Decode(raw)
					if e != nil {
						t.Fatal(e)
					}
					c, e := Inspect(s, pin)
					if e != nil {
						t.Fatal(e)
					}
					m, _ := f4Measure(t, mode, -1, 0, c, raw, sigs, 65535)
					if m.RequestBytes != f4RequestLimit || m.ManifestBytes > namecoinwire.MaxManifestBytes {
						t.Fatal("joint budget not reached")
					}
					t.Logf("slot=%s mode=%s whitespace=%q raw_request=%d manifest=%d escaped_manifest=%d result=%d", slot, mode, ws, m.RequestBytes, m.ManifestBytes, m.EscapedManifestBytes, m.CanonicalResultBytes)
				}
				impossible := r
				impossible.ManifestUTF8 += strings.Repeat(" ", namecoinwire.MaxManifestBytes-len(impossible.ManifestUTF8))
				impossible.PlanSHA256 = namecoinwire.PlanDigest([]byte(impossible.ManifestUTF8))
				if slot == "A" || slot == "B" {
					impossible.ReservationPlanSHA256 = impossible.PlanSHA256
				}
				raw := f4MustJSON(t, impossible)
				if len(raw) <= f4RequestLimit {
					t.Fatal("independent manifest/PSBT maxima falsely coexist")
				}
				// Reached wider library semantics, but explicitly not process admission.
				s, e := namecoinwire.Decode(raw)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = Inspect(s, pin); e != nil {
					t.Fatal(e)
				}
			})
		}
	}
}

// Correct public signatures remain necessary after every size/commitment check;
// a valid JSON receipt with a changed DER still refuses the exact signature gate.
func TestF4RehashedSignatureCounterexample(t *testing.T) {
	c := candidate(t, "two-stage", "C")
	sigs, e := c.VerifySignedPSBT(signedFixture(t, "two-stage", "C"))
	if e != nil {
		t.Fatal(e)
	}
	ctx, e := c.ReviewContext(fixtureSelection(t, c))
	if e != nil {
		t.Fatal(e)
	}
	review, e := c.snapshot.ReviewDigest(ctx)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := c.ResultBytes(sigs, review, 7, sha256.Sum256([]byte("public control")))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.VerifyResult(raw, review); e != nil {
		t.Fatal(e)
	}
	decoded, e := namecoinwire.DecodeResult(raw)
	if e != nil {
		t.Fatal(e)
	}
	signature := decoded.Receipt.InputSignatures[0].Signature
	first := "0"
	if signature[0] == '0' {
		first = "1"
	}
	decoded.Receipt.InputSignatures[0].Signature = first + signature[1:]
	bad, e := namecoinwire.EncodeResult(decoded)
	if e != nil {
		t.Fatal(e)
	}
	if e = namecoinwire.VerifyAcknowledgement(namecoinwire.Acknowledgement(sha256.Sum256(bad)), bad); e != nil {
		t.Fatal(e)
	}
	_, e = c.VerifyResult(bad, review)
	requireCode(t, e, namecoinwire.SighashRefused)
}
