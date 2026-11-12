package namecoinpsbt

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// ReviewFact uses explicit semantic kinds; arbitrary binary escaping never
// stands in for meaningful NAME/VALUE consent in the native review window.
type ReviewFact struct {
	Label string `json:"label"`
	Kind  string `json:"kind"`
	Bytes []byte `json:"bytes"`
}
type ReviewDocument struct {
	Operation   string       `json:"operation"`
	Account     string       `json:"account"`
	FeeAtoms    uint64       `json:"fee_atoms"`
	ReviewFrame []byte       `json:"review_frame"`
	Facts       []ReviewFact `json:"facts"`
}

// ReviewDocument derives facts and commitment from the SAME owned parsed
// candidate. It refuses unrenderable semantic names/values before native unseal;
// all binary scripts/hashes remain complete separately labelled byte facts.
func (a PublicAttempt) ReviewDocument() ([]byte, error) {
	if len(a.review) == 0 {
		return nil, failure(namecoinwire.InvalidRequest)
	}
	r, p := a.candidate.snapshot.Request(), a.candidate.snapshot.Plan()
	operation := "name_new"
	if p.Kind == "reveal" {
		operation = "name_firstupdate"
	}
	doc := ReviewDocument{Operation: operation, Account: p.Account, FeeAtoms: a.candidate.view.Fee, ReviewFrame: a.ReviewFrame()}
	add := func(label, kind string, value []byte) {
		doc.Facts = append(doc.Facts, ReviewFact{Label: label, Kind: kind, Bytes: append([]byte{}, value...)})
	}
	text := func(label, value string) { add(label, "binary", []byte(value)) }
	for _, registration := range p.Registrations {
		name, nameOK := semanticReviewBytes(registration.NameHex)
		value, valueOK := semanticReviewBytes(registration.ValueHex)
		if !nameOK || !valueOK {
			return nil, failure(namecoinwire.DisplayRefused)
		}
		prefix := registration.ReservationSlot + "/" + registration.RevealSlot
		add(prefix+" NAME", "semanticName", name)
		if p.Kind == "reservation" && registration.ReservationSlot == "A" {
			text(prefix+" VALUE state", "Pending; no final value bytes are approved at reservation")
		} else {
			add(prefix+" VALUE", "semanticValue", value)
		}
		rand, _ := hex.DecodeString(registration.RandHex)
		add(prefix+" commitment randomness", "binary", rand)
		text(prefix+" name output derivation", registration.NameOutputPath)
	}
	text("Network / genesis", p.Network+" / "+p.Genesis)
	text("Existing recovery group", p.Group)
	text("Account public pin SHA256", p.AccountPinSHA256)
	text("Policy revision", p.Policy.Revision)
	text("Release mode", p.Policy.ReleaseMode)
	text("Release deadline UTC seconds", strconv.FormatUint(p.Policy.ReleaseNotAfter, 10))
	text("Final confirmations required", strconv.FormatUint(uint64(p.Policy.FinalConfirmations), 10))
	text("Request / sitting", r.RequestID+" / "+r.SittingID)
	text("Plan SHA256", r.PlanSHA256)
	text("Reservation plan SHA256", r.ReservationPlanSHA256)
	text("Request expires UTC seconds", strconv.FormatUint(r.ExpiresAt, 10))
	text("Fee caps per transaction / total atoms", p.Policy.PerTxFeeCap+" / "+p.Policy.TotalFeeCap)
	text("Fee rates min / max atoms per kvB", p.Policy.MinFeeRate+" / "+p.Policy.MaxFeeRate)
	text("Dust relay atoms per kvB", p.Policy.DustRelayFee)
	text("Submitted signatures", "Anyone holding exported signatures can submit them. No hard revocation or exactly-once network submission is promised.")
	for _, tx := range p.Transactions {
		view, parsed, err := inspectTemplate(tx, p, a.candidate.account)
		if err != nil {
			return nil, err
		}
		prefix := "Transaction " + tx.Slot
		text(prefix+" unsigned txid", view.UnsignedTxID)
		text(prefix+" locktime", strconv.FormatUint(uint64(view.Locktime), 10))
		text(prefix+" input / output / fee atoms", fmt.Sprintf("%d / %d / %d", view.InputTotal, view.OutputTotal, view.Fee))
		raw, _ := hex.DecodeString(tx.UnsignedHex)
		add(prefix+" complete unsigned transaction", "binary", raw)
		for i, input := range view.Inputs {
			ip := fmt.Sprintf("%s input %d", prefix, i)
			text(ip+" outpoint", input.TxID+":"+strconv.FormatUint(uint64(input.Vout), 10))
			text(ip+" account derivation", input.Path)
			text(ip+" address", input.Address)
			text(ip+" atoms", strconv.FormatUint(input.Amount, 10))
			text(ip+" sequence / signals RBF", fmt.Sprintf("%d / %t", input.Sequence, parsed.inputs[i].sequence < 0xfffffffe))
			script, _ := hex.DecodeString(input.ScriptHex)
			add(ip+" complete script", "binary", script)
		}
		for i, output := range view.Outputs {
			op := fmt.Sprintf("%s output %d", prefix, i)
			text(op+" kind / account derivation", output.Kind+" / "+output.Path)
			text(op+" address", output.Address)
			text(op+" atoms", strconv.FormatUint(output.Amount, 10))
			script, _ := hex.DecodeString(output.ScriptHex)
			add(op+" complete script", "binary", script)
		}
	}
	total := 0
	for _, fact := range doc.Facts {
		total += len(fact.Bytes)
		if len(fact.Label) > 72 || len(fact.Bytes) > 262144 || total > 1<<20 {
			return nil, failure(namecoinwire.DisplayRefused)
		}
	}
	if len(doc.Facts) > 2048 {
		return nil, failure(namecoinwire.DisplayRefused)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, failure(namecoinwire.DisplayRefused)
	}
	return raw, nil
}

func semanticReviewBytes(encoded string) ([]byte, bool) {
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, false
	}
	for _, b := range raw {
		if b < 32 || b > 126 {
			return nil, false
		}
	}
	return raw, true
}
