package namecoinpsbt

import (
	"bytes"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// checkPhaseGraph restricts the locally described graph, independently of
// individually valid account paths and signatures. Full predecessor custody
// still needs the authenticated completed reservation/reveal history.
func checkPhaseGraph(p namecoinwire.Plan) error {
	refuse := func() error { return failure(namecoinwire.IntentMismatch) }
	if len(p.Transactions) != 2 {
		return refuse()
	}
	templates := make(map[string]namecoinwire.Transaction, 2)
	txs := make(map[string]transaction, 2)
	for _, meta := range p.Transactions {
		if _, exists := templates[meta.Slot]; exists {
			return refuse()
		}
		tx, err := parseTransaction(decodeHex(meta.UnsignedHex), false)
		if err != nil {
			return err
		}
		if len(tx.inputs) != len(meta.Inputs) || len(tx.outputs) != len(meta.Outputs) {
			return refuse()
		}
		templates[meta.Slot], txs[meta.Slot] = meta, tx
	}
	if p.Kind == "reservation" {
		a, b := txs["A"], txs["B"]
		am, bm := templates["A"], templates["B"]
		ac, aok := changeIndex(am, true)
		_, bok := changeIndex(bm, true)
		if !aok || !bok || len(a.inputs) != 1 || len(b.inputs) != 1 {
			return refuse()
		}
		funding, err := parseTransaction(decodeHex(p.Funding.TransactionHex), true)
		if err != nil || rpcHash(funding.hash()) != p.Funding.TxID || uint64(p.Funding.Vout) >= uint64(len(funding.outputs)) {
			return refuse()
		}
		if !matchesParent(a.inputs[0], am.Inputs[0], funding, p.Funding.Vout) || !matchesParent(b.inputs[0], bm.Inputs[0], a, uint32(ac)) {
			return refuse()
		}
		return nil
	}
	if p.Kind != "reveal" {
		return refuse()
	}
	c, d := txs["C"], txs["D"]
	cm, dm := templates["C"], templates["D"]
	cc, cok := changeIndex(cm, true)
	_, dok := changeIndex(dm, false)
	if !cok || !dok || len(c.inputs) != 2 || len(d.inputs) != 2 {
		return refuse()
	}
	a, err := parseTransaction(decodeHex(cm.Inputs[0].PreviousTransactionHex), true)
	if err != nil {
		return err
	}
	b, err := parseTransaction(decodeHex(cm.Inputs[1].PreviousTransactionHex), true)
	if err != nil {
		return err
	}
	ac, aok := reservationParent(a, c.inputs[0].index)
	bc, bok := reservationParent(b, d.inputs[0].index)
	if !aok || !bok || b.inputs[0].hash != a.hash() || b.inputs[0].index != uint32(ac) {
		return refuse()
	}
	if !matchesParent(c.inputs[0], cm.Inputs[0], a, c.inputs[0].index) || !matchesParent(c.inputs[1], cm.Inputs[1], b, uint32(bc)) || !matchesParent(d.inputs[0], dm.Inputs[0], b, d.inputs[0].index) || !matchesParent(d.inputs[1], dm.Inputs[1], c, uint32(cc)) {
		return refuse()
	}
	return nil
}

func changeIndex(meta namecoinwire.Transaction, required bool) (int, bool) {
	if len(meta.Outputs) < 1 || len(meta.Outputs) > 2 || required && len(meta.Outputs) != 2 {
		return 0, false
	}
	change, names := -1, 0
	for i, out := range meta.Outputs {
		if out.Vout != uint32(i) {
			return 0, false
		}
		switch out.Kind {
		case "name":
			names++
		case "change":
			if change >= 0 {
				return 0, false
			}
			change = i
		default:
			return 0, false
		}
	}
	return change, names == 1 && (!required || change >= 0)
}
func matchesParent(spend input, meta namecoinwire.Input, parent transaction, index uint32) bool {
	if spend.hash != parent.hash() || spend.index != index || meta.TxID != rpcHash(parent.hash()) || meta.Vout != index {
		return false
	}
	previous, err := parseTransaction(decodeHex(meta.PreviousTransactionHex), true)
	return err == nil && bytes.Equal(previous.serialize(false), parent.serialize(false))
}
func reservationParent(tx transaction, nameIndex uint32) (int, bool) {
	if tx.version != 0x7100 || len(tx.inputs) != 1 || len(tx.inputs[0].script) != 0 || len(tx.outputs) != 2 || nameIndex > 1 {
		return 0, false
	}
	name, err := splitScript(tx.outputs[nameIndex].script)
	if err != nil || name.operation != "name_new" {
		return 0, false
	}
	change := 1 - int(nameIndex)
	facts, err := splitScript(tx.outputs[change].script)
	return change, err == nil && facts.operation == ""
}
