package namecoinwire

import "encoding/json"

const (
	MaxRequestBytes     = 8 << 20
	MaxManifestBytes    = 1 << 20
	MaxPSBTBytes        = 4 << 20
	MaxTransactionBytes = 4 << 20
	MaxInputs           = 128
	MaxOutputs          = 128
)

type Outpoint struct {
	TxID string `json:"txid"`
	Vout uint32 `json:"vout"`
}

type Request struct {
	Schema                string          `json:"schema"`
	RequestID             string          `json:"request_id"`
	SittingID             string          `json:"sitting_id"`
	Slot                  string          `json:"slot"`
	Network               string          `json:"network"`
	ExpiresAt             uint64          `json:"expires_at"`
	PSBT                  string          `json:"psbt"`
	ManifestUTF8          string          `json:"plan_manifest_utf8"`
	PlanSHA256            string          `json:"plan_sha256"`
	ReservationPlanSHA256 string          `json:"reservation_plan_sha256"`
	Intent                json.RawMessage `json:"intent"`
}

type NewIntent struct {
	Operation string `json:"operation"`
	NameHex   string `json:"name_hex"`
	RandHex   string `json:"rand_hex"`
}
type RevealIntent struct {
	Operation   string   `json:"operation"`
	NameHex     string   `json:"name_hex"`
	ValueHex    string   `json:"value_hex"`
	RandHex     string   `json:"rand_hex"`
	Reservation Outpoint `json:"reservation_outpoint"`
}

type Policy struct {
	Revision           string `json:"revision"`
	PerTxFeeCap        string `json:"per_tx_fee_cap_atoms"`
	TotalFeeCap        string `json:"total_fee_cap_atoms"`
	MinFeeRate         string `json:"min_fee_rate_atoms_per_kvb"`
	MaxFeeRate         string `json:"max_fee_rate_atoms_per_kvb"`
	DustRelayFee       string `json:"dust_relay_fee_atoms_per_kvb"`
	CreatedAt          uint64 `json:"created_at"`
	ReleaseNotAfter    uint64 `json:"release_not_after"`
	FinalConfirmations uint32 `json:"final_confirmations"`
	ReleaseMode        string `json:"release_mode"`
}
type Funding struct {
	TransactionHex string `json:"tx_hex"`
	TxID           string `json:"txid"`
	Vout           uint32 `json:"vout"`
}
type Input struct {
	PreviousTransactionHex string `json:"prev_tx_hex"`
	TxID                   string `json:"txid"`
	Vout                   uint32 `json:"vout"`
	Path                   string `json:"path"`
}
type Output struct {
	Vout uint32 `json:"vout"`
	Path string `json:"path"`
	Kind string `json:"kind"`
}
type Transaction struct {
	Slot         string   `json:"slot"`
	UnsignedHex  string   `json:"unsigned_tx_hex"`
	UnsignedTxID string   `json:"unsigned_txid"`
	Inputs       []Input  `json:"inputs"`
	Outputs      []Output `json:"outputs"`
	Fee          string   `json:"fee_atoms"`
}
type ReservationRegistration struct {
	NameHex         string          `json:"name_hex"`
	RandHex         string          `json:"rand_hex"`
	NameOutputPath  string          `json:"name_output_path"`
	ReservationSlot string          `json:"reservation_slot"`
	RevealSlot      string          `json:"reveal_slot"`
	FutureValue     json.RawMessage `json:"future_value"`
}
type Registration struct {
	NameHex         string `json:"name_hex"`
	ValueHex        string `json:"value_hex"`
	ValueSHA256     string `json:"value_sha256"`
	RandHex         string `json:"rand_hex"`
	NameOutputPath  string `json:"name_output_path"`
	ReservationSlot string `json:"reservation_slot"`
	RevealSlot      string `json:"reveal_slot"`
}
type ParentResult struct {
	Slot             string `json:"slot"`
	RequestID        string `json:"request_id"`
	SittingID        string `json:"sitting_id"`
	UnsignedTxID     string `json:"unsigned_txid"`
	SignedPSBTSHA256 string `json:"signed_psbt_sha256"`
}
type ReservationPlan struct {
	Schema           string                    `json:"schema"`
	Kind             string                    `json:"kind"`
	Network          string                    `json:"network"`
	Genesis          string                    `json:"genesis"`
	Group            string                    `json:"group"`
	Account          string                    `json:"account"`
	AccountPinSHA256 string                    `json:"account_pin_sha256"`
	Funding          Funding                   `json:"funding"`
	Registrations    []ReservationRegistration `json:"registrations"`
	Transactions     []Transaction             `json:"transactions"`
	Policy           Policy                    `json:"policy"`
}
type RevealPlan struct {
	Schema                string         `json:"schema"`
	Kind                  string         `json:"kind"`
	Network               string         `json:"network"`
	Genesis               string         `json:"genesis"`
	Group                 string         `json:"group"`
	Account               string         `json:"account"`
	AccountPinSHA256      string         `json:"account_pin_sha256"`
	ReservationPlanSHA256 string         `json:"reservation_plan_sha256"`
	ParentResults         []ParentResult `json:"parent_results"`
	Registrations         []Registration `json:"registrations"`
	Transactions          []Transaction  `json:"transactions"`
	Policy                Policy         `json:"policy"`
}

// Plan is a normalized, public syntax view. Parent-result fields remain caller
// claims until independently matched to the protected engine's actual history.
type Plan struct {
	Kind, Network, Genesis, Group, Account, AccountPinSHA256 string
	ReservationPlanSHA256                                    string
	Funding                                                  Funding
	Registrations                                            []Registration
	ParentResults                                            []ParentResult
	Transactions                                             []Transaction
	Policy                                                   Policy
}

type AccountPin struct {
	Schema            string `json:"schema"`
	Group             string `json:"group"`
	Account           string `json:"account"`
	AccountXPub       string `json:"account_xpub"`
	MasterFingerprint string `json:"master_fingerprint"`
	AccountPath       string `json:"account_path"`
}
type RevealValue struct {
	NameHex     string `json:"name_hex"`
	ValueHex    string `json:"value_hex"`
	ValueSHA256 string `json:"value_sha256"`
}
type RevealValuesPin struct {
	Schema                string        `json:"schema"`
	ReservationPlanSHA256 string        `json:"reservation_plan_sha256"`
	Registrations         []RevealValue `json:"registrations"`
}
type ReconcileQuery struct {
	Schema     string `json:"schema"`
	RequestID  string `json:"request_id"`
	PlanSHA256 string `json:"plan_sha256"`
	Slot       string `json:"slot"`
}
