package namecoinpsbt

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

const reviewCore28MinimumAtoms uint64 = 1_000_000

// Claim: A/B and C/D in both release modes reject a coherent below-minimum
// name output before an attempt escapes, while minimum and over-minimum controls
// remain admissible and a separate below-dust change still returns fee_refused.
func TestCore28MinimumNameOutputBeforeAttempt(t *testing.T) {
	pinFor := func(mode string) []byte { return fixture(t, mode, "account-pin.json") }
	for _, mode := range []string{"all-four-before-release", "two-stage"} {
		for _, slot := range []string{"A", "B", "C", "D"} {
			t.Run(mode+"/"+slot, func(t *testing.T) {
				pin := pinFor(mode)
				baseCandidate := candidate(t, mode, slot)
				selected := fixtureSelection(t, baseCandidate)
				now := time.Unix(int64(selected.Policy.CreatedAt)+1, 0)

				for _, amount := range []uint64{reviewCore28MinimumAtoms, reviewCore28MinimumAtoms + 1} {
					request, raw := coherentNameAmountRequest(t, mode, slot, "name", amount)
					verifyCoherentNameRequest(t, request, slot, "name", amount)
					before := bytes.Clone(raw)
					attempt, err := PrepareAttempt(raw, pin, selected, now)
					if err != nil || attempt.Candidate().View().NameAmount != amount {
						t.Fatalf("valid %d-atom name output refused: view=%+v err=%v", amount, attempt.Candidate().View(), err)
					}
					if !bytes.Equal(raw, before) {
						t.Fatal("successful preparation changed its request bytes")
					}
				}

				request, raw := coherentNameAmountRequest(t, mode, slot, "name", reviewCore28MinimumAtoms-1)
				verifyCoherentNameRequest(t, request, slot, "name", reviewCore28MinimumAtoms-1)
				before := bytes.Clone(raw)
				attempt, err := PrepareAttempt(raw, pin, selected, now)
				requireCode(t, err, namecoinwire.FeeRefused)
				if len(attempt.Candidate().SignatureHashes()) != 0 || len(attempt.Candidate().View().Inputs) != 0 || attempt.Candidate().View().NameAmount != 0 {
					t.Fatal("below-minimum refusal returned candidate state")
				}
				if !bytes.Equal(raw, before) {
					t.Fatal("below-minimum refusal changed its request bytes")
				}
			})
		}
	}

	// These leaf transactions let the dust control isolate relay dust without
	// changing a descendant's funded change output.
	for _, mode := range []string{"all-four-before-release", "two-stage"} {
		for _, slot := range []string{"B", "D"} {
			t.Run(mode+"/"+slot+"/below-dust-change", func(t *testing.T) {
				pin := pinFor(mode)
				baseCandidate := candidate(t, mode, slot)
				selected := fixtureSelection(t, baseCandidate)
				now := time.Unix(int64(selected.Policy.CreatedAt)+1, 0)
				request, raw := coherentNameAmountRequest(t, mode, slot, "change", 1)
				verifyCoherentNameRequest(t, request, slot, "change", 1)
				before := bytes.Clone(raw)
				attempt, err := PrepareAttempt(raw, pin, selected, now)
				requireCode(t, err, namecoinwire.FeeRefused)
				if len(attempt.Candidate().SignatureHashes()) != 0 || attempt.Candidate().View().NameAmount != 0 {
					t.Fatal("below-dust refusal returned candidate state")
				}
				if !bytes.Equal(raw, before) {
					t.Fatal("below-dust refusal changed its request bytes")
				}
			})
		}
	}
}

func coherentNameAmountRequest(t *testing.T, mode, slot, outputKind string, amount uint64) (namecoinwire.Request, []byte) {
	t.Helper()
	r := requestFixture(t, mode, slot)
	var shape struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal([]byte(r.ManifestUTF8), &shape); err != nil {
		t.Fatal("decode fixture plan kind:", err)
	}
	var selectedTx transaction
	switch shape.Kind {
	case "reservation":
		var p namecoinwire.ReservationPlan
		if err := json.Unmarshal([]byte(r.ManifestUTF8), &p); err != nil {
			t.Fatal("decode reservation fixture:", err)
		}
		parsed := mutateCore28PlanTransactions(t, p.Transactions, slot, outputKind, amount)
		r.ManifestUTF8 = marshalCore28Plan(t, p)
		selectedTx = transactionForSlot(t, p.Transactions, parsed, slot)
	case "reveal":
		var p namecoinwire.RevealPlan
		if err := json.Unmarshal([]byte(r.ManifestUTF8), &p); err != nil {
			t.Fatal("decode reveal fixture:", err)
		}
		parsed := mutateCore28PlanTransactions(t, p.Transactions, slot, outputKind, amount)
		r.ManifestUTF8 = marshalCore28Plan(t, p)
		selectedTx = transactionForSlot(t, p.Transactions, parsed, slot)
	default:
		t.Fatalf("unsupported fixture plan kind %q", shape.Kind)
	}
	r.PlanSHA256 = namecoinwire.PlanDigest([]byte(r.ManifestUTF8))
	if shape.Kind == "reservation" {
		r.ReservationPlanSHA256 = r.PlanSHA256
	}
	psbtBytes, err := base64.StdEncoding.Strict().DecodeString(r.PSBT)
	if err != nil {
		t.Fatal("decode fixture PSBT:", err)
	}
	p, err := parsePacket(psbtBytes)
	if err != nil {
		t.Fatal("parse fixture PSBT:", err)
	}
	p.tx = selectedTx
	globalFound := false
	for i := range p.globals {
		if bytes.Equal(p.globals[i].key, []byte{0}) {
			p.globals[i].value = selectedTx.serialize(false)
			globalFound = true
		}
	}
	if !globalFound {
		t.Fatal("fixture PSBT has no unsigned transaction")
	}
	r.PSBT = base64.StdEncoding.EncodeToString(encodePacket(p))
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal("encode recommitted fixture request:", err)
	}
	return r, raw
}

func marshalCore28Plan(t *testing.T, plan any) string {
	t.Helper()
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal("encode recommitted fixture plan:", err)
	}
	return string(raw)
}

func mutateCore28PlanTransactions(t *testing.T, templates []namecoinwire.Transaction, targetSlot, outputKind string, amount uint64) []transaction {
	t.Helper()
	parsed := make([]transaction, len(templates))
	oldIDs := make(map[string]string, len(templates))
	currentIDs := make([]string, len(templates))
	for i, meta := range templates {
		tx, err := parseTransaction(decodeHex(meta.UnsignedHex), false)
		if err != nil || rpcHash(tx.hash()) != meta.UnsignedTxID {
			t.Fatalf("invalid base transaction %s: %v", meta.Slot, err)
		}
		parsed[i] = tx
		oldIDs[meta.Slot] = meta.UnsignedTxID
		currentIDs[i] = meta.UnsignedTxID
	}
	found := false
	for i := range templates {
		meta := &templates[i]
		tx := &parsed[i]
		parentChanged := false
		for inputIndex := range meta.Inputs {
			for parentIndex := 0; parentIndex < i; parentIndex++ {
				if meta.Inputs[inputIndex].TxID != oldIDs[templates[parentIndex].Slot] || currentIDs[parentIndex] == oldIDs[templates[parentIndex].Slot] {
					continue
				}
				parent := parsed[parentIndex]
				tx.inputs[inputIndex].hash = parent.hash()
				meta.Inputs[inputIndex].TxID = rpcHash(parent.hash())
				meta.Inputs[inputIndex].PreviousTransactionHex = hex.EncodeToString(parent.serialize(false))
				parentChanged = true
				break
			}
		}
		if meta.Slot == targetSlot {
			mutateCore28Output(t, meta, tx, outputKind, amount)
			found = true
		}
		if parentChanged {
			preserveCore28PlanFee(t, meta, tx)
		}
		if err := checkCore28PlanFee(*meta, *tx); err != nil {
			t.Fatalf("incoherent transaction %s after mutation: %v", meta.Slot, err)
		}
		meta.UnsignedHex = hex.EncodeToString(tx.serialize(false))
		meta.UnsignedTxID = rpcHash(tx.hash())
		currentIDs[i] = meta.UnsignedTxID
	}
	if !found {
		t.Fatalf("fixture plan lacks target slot %s", targetSlot)
	}
	return parsed
}

func mutateCore28Output(t *testing.T, meta *namecoinwire.Transaction, tx *transaction, kind string, amount uint64) {
	t.Helper()
	nameIndex, changeIndex := -1, -1
	for i, out := range meta.Outputs {
		switch out.Kind {
		case "name":
			nameIndex = i
		case "change":
			changeIndex = i
		}
	}
	if nameIndex < 0 || changeIndex < 0 || nameIndex >= len(tx.outputs) || changeIndex >= len(tx.outputs) {
		t.Fatal("fixture transaction must have one name output and one change output")
	}
	total := tx.outputs[nameIndex].amount + tx.outputs[changeIndex].amount
	if total < tx.outputs[nameIndex].amount || amount > total {
		t.Fatal("mutated output amount is outside fixture total")
	}
	switch kind {
	case "name":
		tx.outputs[nameIndex].amount = amount
		tx.outputs[changeIndex].amount = total - amount
	case "change":
		tx.outputs[changeIndex].amount = amount
		tx.outputs[nameIndex].amount = total - amount
	default:
		t.Fatalf("unsupported fixture output kind %q", kind)
	}
}

func preserveCore28PlanFee(t *testing.T, meta *namecoinwire.Transaction, tx *transaction) {
	t.Helper()
	inputTotal := core28InputTotal(t, *meta)
	outputTotal := core28OutputTotal(t, *tx)
	fee, ok := namecoinwire.Decimal(meta.Fee)
	if !ok || inputTotal < fee {
		t.Fatalf("invalid fixture fee/input total for %s", meta.Slot)
	}
	wantOutputs := inputTotal - fee
	if outputTotal == wantOutputs {
		return
	}
	changeIndex := -1
	for i, out := range meta.Outputs {
		if out.Kind == "change" {
			changeIndex = i
		}
	}
	if changeIndex < 0 || changeIndex >= len(tx.outputs) {
		t.Fatalf("changed parent amount cannot preserve %s without a change output", meta.Slot)
	}
	otherOutputs := outputTotal - tx.outputs[changeIndex].amount
	if wantOutputs < otherOutputs {
		t.Fatalf("changed parent amount underfunds %s name output", meta.Slot)
	}
	tx.outputs[changeIndex].amount = wantOutputs - otherOutputs
}

func checkCore28PlanFee(meta namecoinwire.Transaction, tx transaction) error {
	inputTotal := uint64(0)
	for _, in := range meta.Inputs {
		parent, err := parseTransaction(decodeHex(in.PreviousTransactionHex), true)
		if err != nil {
			return err
		}
		if uint64(in.Vout) >= uint64(len(parent.outputs)) {
			return failure(namecoinwire.PrevoutMismatch)
		}
		value := parent.outputs[in.Vout].amount
		if inputTotal > maxMoney-value {
			return failure(namecoinwire.FeeRefused)
		}
		inputTotal += value
	}
	outputTotal := uint64(0)
	for _, out := range tx.outputs {
		if outputTotal > maxMoney-out.amount {
			return failure(namecoinwire.FeeRefused)
		}
		outputTotal += out.amount
	}
	fee, ok := namecoinwire.Decimal(meta.Fee)
	if !ok || inputTotal < outputTotal || inputTotal-outputTotal != fee {
		return failure(namecoinwire.FeeRefused)
	}
	return nil
}

func core28InputTotal(t *testing.T, meta namecoinwire.Transaction) uint64 {
	t.Helper()
	var total uint64
	for _, in := range meta.Inputs {
		parent, err := parseTransaction(decodeHex(in.PreviousTransactionHex), true)
		if err != nil || uint64(in.Vout) >= uint64(len(parent.outputs)) {
			t.Fatalf("invalid previous transaction for %s: %v", meta.Slot, err)
		}
		value := parent.outputs[in.Vout].amount
		if total > maxMoney-value {
			t.Fatalf("input total overflow for %s", meta.Slot)
		}
		total += value
	}
	return total
}

func core28OutputTotal(t *testing.T, tx transaction) uint64 {
	t.Helper()
	var total uint64
	for _, out := range tx.outputs {
		if total > maxMoney-out.amount {
			t.Fatal("output total overflow")
		}
		total += out.amount
	}
	return total
}

func transactionForSlot(t *testing.T, templates []namecoinwire.Transaction, parsed []transaction, slot string) transaction {
	t.Helper()
	for i, meta := range templates {
		if meta.Slot == slot {
			return parsed[i]
		}
	}
	t.Fatalf("fixture plan lacks target slot %s", slot)
	return transaction{}
}

func verifyCoherentNameRequest(t *testing.T, r namecoinwire.Request, slot, outputKind string, amount uint64) {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal("encode request for coherence check:", err)
	}
	snapshot, err := namecoinwire.Decode(raw)
	if err != nil {
		t.Fatal("recommitted request failed its wire commitments:", err)
	}
	plan := snapshot.Plan()
	if err := checkPhaseGraph(plan); err != nil {
		t.Fatal("recommitted plan graph is inconsistent:", err)
	}
	var selected *namecoinwire.Transaction
	for i := range plan.Transactions {
		meta := &plan.Transactions[i]
		tx, err := parseTransaction(decodeHex(meta.UnsignedHex), false)
		if err != nil || rpcHash(tx.hash()) != meta.UnsignedTxID || len(tx.inputs) != len(meta.Inputs) || len(tx.outputs) != len(meta.Outputs) {
			t.Fatalf("recommitted transaction %s does not match its plan: %v", meta.Slot, err)
		}
		if err := checkCore28PlanFee(*meta, tx); err != nil {
			t.Fatalf("recommitted transaction %s has inconsistent amounts/fee: %v", meta.Slot, err)
		}
		if meta.Slot == slot {
			selected = meta
			matches := 0
			for i, out := range meta.Outputs {
				if out.Vout != uint32(i) {
					t.Fatalf("selected output metadata index=%d, want %d", out.Vout, i)
				}
				if out.Kind == outputKind {
					matches++
					if tx.outputs[i].amount != amount {
						t.Fatalf("target %s output amount=%d, want %d", outputKind, tx.outputs[i].amount, amount)
					}
				}
			}
			if matches != 1 {
				t.Fatalf("selected transaction has %d outputs of kind %q, want one", matches, outputKind)
			}
		}
	}
	if selected == nil {
		t.Fatalf("request plan lacks selected slot %s", slot)
	}
	p, err := parsePacket(snapshot.PSBTBytes())
	if err != nil || !bytes.Equal(p.tx.serialize(false), decodeHex(selected.UnsignedHex)) {
		t.Fatalf("selected PSBT transaction is not recommitted: %v", err)
	}
}
