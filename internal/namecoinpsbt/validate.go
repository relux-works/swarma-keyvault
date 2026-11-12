package namecoinpsbt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

type InputView struct {
	TxID         string
	Vout         uint32
	Path         string
	Amount       uint64
	ScriptHex    string
	Sequence     uint32
	PublicKeyHex string
	Address      string
}
type OutputView struct {
	Vout       uint32
	Path, Kind string
	Amount     uint64
	ScriptHex  string
	Address    string
}
type View struct {
	Slot, UnsignedTxID                       string
	Locktime                                 uint32
	Inputs                                   []InputView
	Outputs                                  []OutputView
	InputTotal, OutputTotal, Fee, NameAmount uint64
}

// Candidate owns only public material. It establishes structural transaction,
// account and manifest consistency. Admission still requires an independently
// trusted policy/clock/value pin and authentic protected phase/journal lineage.
type Candidate struct {
	snapshot namecoinwire.Snapshot
	packet   packet
	account  accountPublic
	view     View
	digests  [][32]byte
}

func (c Candidate) View() View {
	v := c.view
	v.Inputs = append([]InputView(nil), v.Inputs...)
	v.Outputs = append([]OutputView(nil), v.Outputs...)
	return v
}
func (c Candidate) SignatureHashes() [][32]byte { return append([][32]byte(nil), c.digests...) }

func Inspect(snapshot namecoinwire.Snapshot, independentlySelectedPin []byte) (Candidate, error) {
	var result Candidate
	plan := snapshot.Plan()
	request := snapshot.Request()
	pin, err := namecoinwire.DecodeAccountPin(independentlySelectedPin)
	if err != nil {
		return result, failure(namecoinwire.AccountMismatch)
	}
	pinHash := sha256.Sum256(independentlySelectedPin)
	if pin.Group != plan.Group || pin.Account != plan.Account || hex.EncodeToString(pinHash[:]) != plan.AccountPinSHA256 {
		return result, failure(namecoinwire.AccountMismatch)
	}
	account, err := parseAccount(pin)
	if err != nil {
		return result, err
	}
	p, err := parsePacket(snapshot.PSBTBytes())
	if err != nil {
		return result, err
	}
	if err = account.checkGlobal(p); err != nil {
		return result, err
	}
	var selected namecoinwire.Transaction
	var selectedView View
	for _, template := range plan.Transactions {
		view, tx, err := inspectTemplate(template, plan, account)
		if err != nil {
			return result, err
		}
		if template.Slot == request.Slot {
			selected, selectedView = template, view
			if !bytes.Equal(p.tx.serialize(false), tx.serialize(false)) {
				return Candidate{}, failure(namecoinwire.IntentMismatch)
			}
		}
	}
	if err := checkPhaseGraph(plan); err != nil {
		return Candidate{}, err
	}
	if selected.Slot == "" || len(selected.Inputs) != len(p.inputs) || len(selected.Outputs) != len(p.outputs) {
		return Candidate{}, failure(namecoinwire.IntentMismatch)
	}
	for i, v := range p.inputs {
		if err := account.checkOrigin(v.origin); err != nil {
			return Candidate{}, err
		}
		if v.origin.path() != selected.Inputs[i].Path {
			return Candidate{}, failure(namecoinwire.PathRefused)
		}
		expectedParent, err := parseTransaction(decodeHex(selected.Inputs[i].PreviousTransactionHex), true)
		if err != nil {
			return Candidate{}, err
		}
		if !bytes.Equal(v.previous.serialize(false), expectedParent.serialize(false)) {
			return Candidate{}, failure(namecoinwire.PrevoutMismatch)
		}
		f, err := splitScript(v.prevout.script)
		if err != nil {
			return Candidate{}, err
		}
		if f.program != hash160(v.origin.key[:]) {
			return Candidate{}, failure(namecoinwire.AccountMismatch)
		}
		digest, err := p.tx.signatureHash(i, v.prevout, f.program[:])
		if err != nil {
			return Candidate{}, err
		}
		result.digests = append(result.digests, digest)
	}
	for i, o := range p.outputs {
		if err := account.checkOrigin(o); err != nil {
			return Candidate{}, err
		}
		if o.path() != selected.Outputs[i].Path {
			return Candidate{}, failure(namecoinwire.PathRefused)
		}
	}
	// A firstupdate must spend exactly its explicitly selected reservation.
	if request.Slot == "C" || request.Slot == "D" {
		var intent namecoinwire.RevealIntent
		if err := json.Unmarshal(request.Intent, &intent); err != nil {
			return Candidate{}, failure(namecoinwire.InvalidRequest)
		}
		if len(selectedView.Inputs) == 0 || intent.Reservation.TxID != selectedView.Inputs[0].TxID || intent.Reservation.Vout != selectedView.Inputs[0].Vout {
			return Candidate{}, failure(namecoinwire.IntentMismatch)
		}
	}
	result.snapshot = snapshot
	result.packet = p
	result.account = account
	result.view = selectedView
	return result, nil
}

func inspectTemplate(template namecoinwire.Transaction, plan namecoinwire.Plan, account accountPublic) (View, transaction, error) {
	var view View
	tx, err := parseTransaction(decodeHex(template.UnsignedHex), false)
	if err != nil {
		return view, transaction{}, err
	}
	refuse := func(code namecoinwire.Code) (View, transaction, error) { return View{}, transaction{}, failure(code) }
	if tx.version != 0x7100 || rpcHash(tx.hash()) != template.UnsignedTxID || len(tx.inputs) != len(template.Inputs) || len(tx.outputs) != len(template.Outputs) {
		return refuse(namecoinwire.IntentMismatch)
	}
	view.Slot, view.UnsignedTxID, view.Locktime = template.Slot, template.UnsignedTxID, tx.locktime
	reveal := template.Slot == "C" || template.Slot == "D"
	registration := 0
	if template.Slot == "B" || template.Slot == "D" {
		registration = 1
	}
	reg := plan.Registrations[registration]
	nameInputs, nameOutputs := 0, 0
	seen := make(map[[36]byte]bool)
	for i, v := range tx.inputs {
		meta := template.Inputs[i]
		if len(v.script) != 0 || rpcHash(v.hash) != meta.TxID || v.index != meta.Vout {
			return refuse(namecoinwire.PrevoutMismatch)
		}
		var point [36]byte
		copy(point[:32], v.hash[:])
		point[32] = byte(v.index)
		point[33] = byte(v.index >> 8)
		point[34] = byte(v.index >> 16)
		point[35] = byte(v.index >> 24)
		if seen[point] {
			return refuse(namecoinwire.PrevoutMismatch)
		}
		seen[point] = true
		previous, err := parseTransaction(decodeHex(meta.PreviousTransactionHex), true)
		if err != nil {
			return View{}, transaction{}, err
		}
		if previous.hash() != v.hash || uint64(v.index) >= uint64(len(previous.outputs)) {
			return refuse(namecoinwire.PrevoutMismatch)
		}
		prev := previous.outputs[v.index]
		facts, err := splitScript(prev.script)
		if err != nil {
			return View{}, transaction{}, err
		}
		pub, err := publicAtPath(account, meta.Path)
		if err != nil {
			return View{}, transaction{}, err
		}
		if facts.program != hash160(pub[:]) {
			return refuse(namecoinwire.AccountMismatch)
		}
		if facts.operation != "" {
			nameInputs++
			if !reveal || i != 0 || meta.Path != reg.NameOutputPath || facts.operation != "name_new" || !bytes.Equal(prev.script, nameScript(reg, false, facts.program)) {
				return refuse(namecoinwire.IntentMismatch)
			}
		}
		if view.InputTotal > maxMoney-prev.amount {
			return refuse(namecoinwire.FeeRefused)
		}
		view.InputTotal += prev.amount
		address, err := witnessAddress(plan.Network, facts.program)
		if err != nil {
			return View{}, transaction{}, err
		}
		view.Inputs = append(view.Inputs, InputView{TxID: meta.TxID, Vout: meta.Vout, Path: meta.Path, Amount: prev.amount, ScriptHex: hex.EncodeToString(prev.script), Sequence: v.sequence, PublicKeyHex: hex.EncodeToString(pub[:]), Address: address})
	}
	for i, v := range tx.outputs {
		meta := template.Outputs[i]
		if meta.Vout != uint32(i) {
			return refuse(namecoinwire.IntentMismatch)
		}
		pub, err := publicAtPath(account, meta.Path)
		if err != nil {
			return View{}, transaction{}, err
		}
		facts, err := splitScript(v.script)
		if err != nil {
			return View{}, transaction{}, err
		}
		if facts.program != hash160(pub[:]) {
			return refuse(namecoinwire.AccountMismatch)
		}
		if facts.operation != "" {
			nameOutputs++
			view.NameAmount = v.amount
			if meta.Kind != "name" || meta.Path != reg.NameOutputPath || !bytes.Equal(v.script, nameScript(reg, reveal, facts.program)) {
				return refuse(namecoinwire.IntentMismatch)
			}
		} else if meta.Kind != "change" {
			return refuse(namecoinwire.IntentMismatch)
		}
		view.OutputTotal += v.amount // parser has already bounded sum by maxMoney
		address, err := witnessAddress(plan.Network, facts.program)
		if err != nil {
			return View{}, transaction{}, err
		}
		view.Outputs = append(view.Outputs, OutputView{Vout: uint32(i), Path: meta.Path, Kind: meta.Kind, Amount: v.amount, ScriptHex: hex.EncodeToString(v.script), Address: address})
	}
	if nameOutputs != 1 || (!reveal && nameInputs != 0) || (reveal && nameInputs != 1) {
		return refuse(namecoinwire.IntentMismatch)
	}
	if view.OutputTotal > view.InputTotal {
		return refuse(namecoinwire.FeeRefused)
	}
	view.Fee = view.InputTotal - view.OutputTotal
	fee, ok := namecoinwire.Decimal(template.Fee)
	cap, capOK := namecoinwire.Decimal(plan.Policy.PerTxFeeCap)
	if !ok || !capOK || fee != view.Fee || view.Fee > cap {
		return refuse(namecoinwire.FeeRefused)
	}
	return view, tx, nil
}
func publicAtPath(account accountPublic, path string) ([33]byte, error) {
	if !namecoinwire.Path(path) {
		return [33]byte{}, failure(namecoinwire.PathRefused)
	}
	parts := strings.Split(path, "/")
	branch, _ := strconv.ParseUint(parts[4], 10, 32)
	index, _ := strconv.ParseUint(parts[5], 10, 32)
	return derivePublic(account, uint32(branch), uint32(index))
}
