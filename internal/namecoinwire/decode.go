package namecoinwire

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Snapshot owns once-decoded bytes. Its accessors return independent copies;
// replacing caller files/buffers or editing a returned view cannot change it.
// A snapshot is syntax/commitment evidence, not permission for private use.
type Snapshot struct {
	request                               Request
	plan                                  Plan
	manifest                              []byte
	psbt                                  []byte
	operation, nameHex, valueHex, randHex string
	reservation                           *Outpoint
}

func (s Snapshot) Request() Request {
	r := s.request
	r.Intent = bytes.Clone(r.Intent)
	return r
}
func (s Snapshot) ManifestBytes() []byte { return bytes.Clone(s.manifest) }
func (s Snapshot) PSBTBytes() []byte     { return bytes.Clone(s.psbt) }
func (s Snapshot) Plan() Plan {
	p := s.plan
	p.Registrations = append([]Registration(nil), p.Registrations...)
	p.ParentResults = append([]ParentResult(nil), p.ParentResults...)
	p.Transactions = append([]Transaction(nil), p.Transactions...)
	for i := range p.Transactions {
		p.Transactions[i].Inputs = append([]Input(nil), p.Transactions[i].Inputs...)
		p.Transactions[i].Outputs = append([]Output(nil), p.Transactions[i].Outputs...)
	}
	return p
}

// Decode validates the exact closed request/phase schemas and their byte
// commitments. The engine still owes PSBT/transaction/account verification,
// trusted profile/time/value checks and authentic protected parent lineage.
func Decode(raw []byte) (Snapshot, error) {
	var s Snapshot
	var r Request
	if decodeClosed(raw, &r, MaxRequestBytes) != nil || r.Schema != "keyvault-namecoin-psbt/2" ||
		!hashString(r.RequestID) || !hashString(r.SittingID) || !hashString(r.PlanSHA256) ||
		!hashString(r.ReservationPlanSHA256) || !network(r.Network) ||
		len(r.Slot) != 1 || !strings.Contains("ABCD", r.Slot) || r.ExpiresAt > math.MaxInt64 {
		return s, ErrInvalidRequest
	}
	manifest := []byte(r.ManifestUTF8)
	if len(manifest) == 0 || len(manifest) > MaxManifestBytes {
		return s, ErrInvalidRequest
	}
	p, err := decodePlan(manifest)
	if err != nil {
		return s, err
	}
	if r.Network != p.Network || PlanDigest(manifest) != r.PlanSHA256 {
		return s, ErrIntentMismatch
	}
	phase := byte(0)
	if r.Slot == "C" || r.Slot == "D" {
		phase = 1
	}
	if phase == 0 && (p.Kind != "reservation" || r.ReservationPlanSHA256 != r.PlanSHA256) ||
		phase == 1 && (p.Kind != "reveal" || r.ReservationPlanSHA256 != p.ReservationPlanSHA256) {
		return s, ErrIntentMismatch
	}
	psbt, err := base64.StdEncoding.Strict().DecodeString(r.PSBT)
	if err != nil || len(psbt) == 0 || len(psbt) > MaxPSBTBytes || base64.StdEncoding.EncodeToString(psbt) != r.PSBT {
		return s, NewFailure(UnsupportedPSBT, false)
	}
	s = Snapshot{request: r, plan: p, manifest: bytes.Clone(manifest), psbt: psbt}
	index := 0
	if r.Slot == "B" || r.Slot == "D" {
		index = 1
	}
	registration := p.Registrations[index]
	if phase == 0 {
		var intent NewIntent
		if decodeClosed(r.Intent, &intent, 4096) != nil || intent.Operation != "name_new" ||
			!nameString(intent.NameHex) || !hexString(intent.RandHex, 20, 20) {
			return Snapshot{}, ErrInvalidRequest
		}
		s.operation, s.nameHex, s.randHex = intent.Operation, intent.NameHex, intent.RandHex
	} else {
		var intent RevealIntent
		if decodeClosed(r.Intent, &intent, 4096) != nil || intent.Operation != "name_firstupdate" ||
			!nameString(intent.NameHex) || !valueString(intent.ValueHex) ||
			!hexString(intent.RandHex, 20, 20) || !hashString(intent.Reservation.TxID) {
			return Snapshot{}, ErrInvalidRequest
		}
		s.operation, s.nameHex, s.valueHex, s.randHex = intent.Operation, intent.NameHex, intent.ValueHex, intent.RandHex
		o := intent.Reservation
		s.reservation = &o
		if intent.ValueHex != registration.ValueHex {
			return Snapshot{}, ErrIntentMismatch
		}
	}
	if s.nameHex != registration.NameHex || s.randHex != registration.RandHex {
		return Snapshot{}, ErrIntentMismatch
	}
	return s, nil
}

func decodePlan(raw []byte) (Plan, error) {
	var header struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return Plan{}, ErrInvalidRequest
	}
	var p Plan
	switch header.Kind {
	case "reservation":
		var r ReservationPlan
		if decodeClosed(raw, &r, MaxManifestBytes) != nil || r.Schema != "swarma-identity/namecoin-registration-plan/2" || len(r.Registrations) != 2 {
			return p, ErrInvalidRequest
		}
		p = Plan{Kind: r.Kind, Network: r.Network, Genesis: r.Genesis, Group: r.Group, Account: r.Account, AccountPinSHA256: r.AccountPinSHA256, Funding: r.Funding, Transactions: r.Transactions, Policy: r.Policy}
		if !hexString(r.Funding.TransactionHex, 1, MaxTransactionBytes) || !hashString(r.Funding.TxID) {
			return Plan{}, ErrInvalidRequest
		}
		for i, r := range r.Registrations {
			v := Registration{NameHex: r.NameHex, RandHex: r.RandHex, NameOutputPath: r.NameOutputPath, ReservationSlot: r.ReservationSlot, RevealSlot: r.RevealSlot}
			if i == 0 {
				var future struct {
					State string `json:"state"`
				}
				if decodeClosed(r.FutureValue, &future, 4096) != nil || future.State != "pending" {
					return Plan{}, ErrInvalidRequest
				}
			} else {
				var future struct {
					State       string `json:"state"`
					ValueHex    string `json:"value_hex"`
					ValueSHA256 string `json:"value_sha256"`
				}
				if decodeClosed(r.FutureValue, &future, 4096) != nil || future.State != "fixed" || !valueHash(future.ValueHex, future.ValueSHA256) {
					return Plan{}, ErrInvalidRequest
				}
				v.ValueHex, v.ValueSHA256 = future.ValueHex, future.ValueSHA256
			}
			p.Registrations = append(p.Registrations, v)
		}
	case "reveal":
		var r RevealPlan
		if decodeClosed(raw, &r, MaxManifestBytes) != nil || r.Schema != "swarma-identity/namecoin-registration-plan/2" ||
			len(r.Registrations) != 2 || len(r.ParentResults) != 2 || !hashString(r.ReservationPlanSHA256) {
			return p, ErrInvalidRequest
		}
		p = Plan{Kind: r.Kind, Network: r.Network, Genesis: r.Genesis, Group: r.Group, Account: r.Account, AccountPinSHA256: r.AccountPinSHA256, ReservationPlanSHA256: r.ReservationPlanSHA256, Registrations: r.Registrations, ParentResults: r.ParentResults, Transactions: r.Transactions, Policy: r.Policy}
		for i, parent := range r.ParentResults {
			if parent.Slot != string("AB"[i]) || !hashString(parent.RequestID) || !hashString(parent.SittingID) || !hashString(parent.UnsignedTxID) || !hashString(parent.SignedPSBTSHA256) {
				return Plan{}, ErrInvalidRequest
			}
		}
		for _, r := range r.Registrations {
			if !valueHash(r.ValueHex, r.ValueSHA256) {
				return Plan{}, ErrInvalidRequest
			}
		}
	default:
		return p, ErrInvalidRequest
	}
	if err := validatePlanSyntax(p); err != nil {
		return Plan{}, err
	}
	return p, nil
}

func validatePlanSyntax(p Plan) error {
	if !network(p.Network) || !hashString(p.Genesis) || !identity(p.Group, "recovery") || !identity(p.Account, "namecoin") || !hashString(p.AccountPinSHA256) || len(p.Transactions) != 2 {
		return ErrInvalidRequest
	}
	if len(p.Policy.Revision) == 0 || len(p.Policy.Revision) > 128 || !utf8.ValidString(p.Policy.Revision) ||
		p.Policy.ReleaseMode != "all-four-before-release" && p.Policy.ReleaseMode != "two-stage" ||
		p.Policy.CreatedAt > math.MaxInt64 || p.Policy.ReleaseNotAfter > math.MaxInt64 {
		return ErrInvalidRequest
	}
	for _, s := range []string{p.Policy.PerTxFeeCap, p.Policy.TotalFeeCap, p.Policy.MinFeeRate, p.Policy.MaxFeeRate, p.Policy.DustRelayFee} {
		if _, ok := Decimal(s); !ok {
			return ErrInvalidRequest
		}
	}
	for i, r := range p.Registrations {
		if !nameString(r.NameHex) || !hexString(r.RandHex, 20, 20) || !Path(r.NameOutputPath) || r.ReservationSlot != string("AB"[i]) || r.RevealSlot != string("CD"[i]) {
			return ErrInvalidRequest
		}
		name, _ := hex.DecodeString(r.NameHex)
		prefix := "id/"
		if i == 1 {
			prefix = "d/"
		}
		if !bytes.HasPrefix(name, []byte(prefix)) || len(name) == len(prefix) {
			return ErrIntentMismatch
		}
	}
	slots := "AB"
	if p.Kind == "reveal" {
		slots = "CD"
	}
	for i, t := range p.Transactions {
		if t.Slot != string(slots[i]) || !hexString(t.UnsignedHex, 1, MaxTransactionBytes) || !hashString(t.UnsignedTxID) ||
			len(t.Inputs) < 1 || len(t.Inputs) > MaxInputs || len(t.Outputs) < 1 || len(t.Outputs) > MaxOutputs {
			return ErrInvalidRequest
		}
		if _, ok := Decimal(t.Fee); !ok {
			return ErrInvalidRequest
		}
		for _, in := range t.Inputs {
			if !hexString(in.PreviousTransactionHex, 1, MaxTransactionBytes) || !hashString(in.TxID) || !Path(in.Path) {
				return ErrInvalidRequest
			}
		}
		for index, out := range t.Outputs {
			if out.Vout != uint32(index) || !Path(out.Path) || out.Kind != "name" && out.Kind != "change" {
				return ErrInvalidRequest
			}
		}
	}
	return nil
}

func PlanDigest(manifest []byte) string {
	frame := append([]byte("swarma-identity/namecoin-registration-plan/2\x00"), lp(manifest)...)
	h := sha256.Sum256(frame)
	return hex.EncodeToString(h[:])
}
func lp(raw []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(raw)))
	return append(b, raw...)
}
func hashString(s string) bool { return hexString(s, 32, 32) }
func hexString(s string, min, max int) bool {
	if len(s)%2 != 0 || len(s)/2 < min || len(s)/2 > max {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func network(s string) bool { return s == "namecoin-mainnet" || s == "namecoin-regtest" }
func nameString(s string) bool {
	if !hexString(s, 1, 255) {
		return false
	}
	b, _ := hex.DecodeString(s)
	return utf8.Valid(b)
}
func valueString(s string) bool {
	if !hexString(s, 0, 520) {
		return false
	}
	b, _ := hex.DecodeString(s)
	return utf8.Valid(b)
}
func valueHash(value, digest string) bool {
	if !valueString(value) || !hashString(digest) {
		return false
	}
	b, _ := hex.DecodeString(value)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]) == digest
}
func identity(s, purpose string) bool {
	parts := strings.Split(s, "/")
	if len(parts) != 2 || len(parts[0]) < 1 || len(parts[0]) > 40 || !strings.HasPrefix(parts[1], purpose+"@") {
		return false
	}
	for _, c := range []byte(parts[0]) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	v := strings.TrimPrefix(parts[1], purpose+"@")
	n, err := strconv.ParseUint(v, 10, 31)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == v
}

// Decimal admits the contract's canonical unsigned integer string, without a
// floating-point conversion. The transaction engine applies monetary bounds.
func Decimal(s string) (uint64, bool) {
	if s == "" || len(s) > 20 || len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}

// Path admits only the exact retained account's non-hardened branch/index.
func Path(s string) bool {
	parts := strings.Split(s, "/")
	if len(parts) != 6 || parts[0] != "m" || parts[1] != "84h" || parts[2] != "7h" || parts[3] != "0h" || parts[4] != "0" && parts[4] != "1" {
		return false
	}
	n, ok := Decimal(parts[5])
	return ok && n < 1<<31
}

func DecodeAccountPin(raw []byte) (AccountPin, error) {
	var p AccountPin
	if decodeClosed(raw, &p, 16384) != nil || p.Schema != "keyvault-namecoin-account-pin/1" || !identity(p.Group, "recovery") || !identity(p.Account, "namecoin") || !hexString(p.MasterFingerprint, 4, 4) || p.AccountPath != "m/84h/7h/0h" || len(p.AccountXPub) < 1 || len(p.AccountXPub) > 256 {
		return AccountPin{}, ErrInvalidRequest
	}
	// Extended-key checksum/version/depth/child and its actual public point are
	// checked by the engine, not inferred from a prefix or fingerprint here.
	return p, nil
}
func DecodeRevealPin(raw []byte) (RevealValuesPin, error) {
	var p RevealValuesPin
	if decodeClosed(raw, &p, 16384) != nil || p.Schema != "keyvault-namecoin-reveal-values/1" || !hashString(p.ReservationPlanSHA256) || len(p.Registrations) != 2 {
		return RevealValuesPin{}, ErrInvalidRequest
	}
	for _, r := range p.Registrations {
		if !nameString(r.NameHex) || !valueHash(r.ValueHex, r.ValueSHA256) {
			return RevealValuesPin{}, ErrInvalidRequest
		}
	}
	return p, nil
}
func DecodeReconcile(raw []byte) (ReconcileQuery, error) {
	var q ReconcileQuery
	if decodeClosed(raw, &q, 4096) != nil || q.Schema != "keyvault-namecoin-reconcile/2" || !hashString(q.RequestID) || !hashString(q.PlanSHA256) || len(q.Slot) != 1 || !strings.Contains("ABCD", q.Slot) {
		return ReconcileQuery{}, ErrInvalidRequest
	}
	return q, nil
}
