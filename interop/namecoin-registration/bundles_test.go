package registration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// These records implement the public retained-bundle contract. They deliberately
// do not import the identity module's private planner or restoration APIs.
const prefix = "swarma-identity/registration-"

type profile struct {
	Schema  string              `json:"schema"`
	Network string              `json:"network"`
	Genesis string              `json:"genesis"`
	Policy  namecoinwire.Policy `json:"policy"`
}
type fileRecord struct {
	Name string `json:"name"`
	Size uint64 `json:"size_bytes"`
	Hash string `json:"sha256"`
}
type bundleIndex struct {
	Schema      string       `json:"schema"`
	Kind        string       `json:"kind"`
	ProfileHash string       `json:"profile_sha256"`
	PinHash     string       `json:"account_pin_sha256"`
	Files       []fileRecord `json:"files"`
}
type funding struct {
	Hex  string `json:"tx_hex"`
	TxID string `json:"txid"`
	Vout uint32 `json:"vout"`
	Path string `json:"path"`
}
type savedName struct {
	Name  string `json:"name"`
	Path  string `json:"name_output_path"`
	Value string `json:"fixed_value_hex"`
	Rand  string `json:"rand_hex"`
}
type reservationState struct {
	Schema     string      `json:"schema"`
	PreparedAt uint64      `json:"prepared_at"`
	Funding    funding     `json:"funding"`
	Names      []savedName `json:"registrations"`
	Change     []string    `json:"change_paths"`
	Fees       []string    `json:"fees_atoms"`
}
type parent struct {
	Bundle     string `json:"request_bundle"`
	BundleHash string `json:"request_bundle_sha256"`
	Result     string `json:"result"`
	ResultHash string `json:"result_sha256"`
	Stdout     string `json:"stdout"`
	StdoutHash string `json:"stdout_sha256"`
	Exit       uint8  `json:"process_exit"`
}
type revealState struct {
	Schema          string   `json:"schema"`
	Reservation     string   `json:"reservation_bundle"`
	ReservationHash string   `json:"reservation_bundle_sha256"`
	Parents         []parent `json:"parents"`
	Pin             string   `json:"reveal_values_pin"`
	PinHash         string   `json:"reveal_values_pin_sha256"`
	Change          []string `json:"change_paths"`
	Fees            []string `json:"fees_atoms"`
	PreparedAt      uint64   `json:"prepared_at"`
}
type requestState struct {
	Schema      string `json:"schema"`
	Plan        string `json:"plan_bundle"`
	PlanHash    string `json:"plan_bundle_sha256"`
	Slot        string `json:"slot"`
	PreparedAt  uint64 `json:"prepared_at"`
	RequestID   string `json:"request_id"`
	SittingID   string `json:"sitting_id"`
	ExpiresAt   uint64 `json:"expires_at"`
	RequestHash string `json:"request_sha256"`
	ReviewHash  string `json:"review_sha256"`
}
type transactionRow struct {
	Slot     string `json:"slot"`
	TxID     string `json:"txid"`
	File     string `json:"psbt_file"`
	Unsigned uint32 `json:"unsigned_vsize"`
	Min      uint32 `json:"signed_vsize_min"`
	Max      uint32 `json:"signed_vsize_max"`
}
type transactionIndex struct {
	Schema       string           `json:"schema"`
	Transactions []transactionRow `json:"transactions"`
}
type envelope struct {
	Schema  string `json:"schema"`
	OK      bool   `json:"ok"`
	Command string `json:"command"`
	Network string `json:"network"`
	Result  *struct {
		Hash  string       `json:"bundle_sha256"`
		Files []fileRecord `json:"files"`
	} `json:"result"`
	Error *struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		Retryable bool   `json:"retryable"`
	} `json:"error"`
}
type fixtureEnv struct {
	dir, profilePath, pinPath string
	profile, pin              []byte
	reservation, reveal       string
	parents                   map[string]parent
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func jsonBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func canonical(t *testing.T, v any) []byte { return append(jsonBytes(t, v), '\n') }
func decode(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}
func wireFixture(t *testing.T, mode, name string) []byte {
	t.Helper()
	return read(t, filepath.Join("..", "..", "internal", "namecoinwire", "testdata", mode, name))
}
func psbtFixture(t *testing.T, mode, name string) []byte {
	t.Helper()
	return read(t, filepath.Join("..", "..", "internal", "namecoinpsbt", "testdata", mode, name))
}
func freshDir(t *testing.T) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func (e *fixtureEnv) base() map[string][]byte {
	return map[string][]byte{"profile.json": bytes.Clone(e.profile), "account-pin.json": bytes.Clone(e.pin)}
}

var payloads = map[string][]string{
	"reservation":    {"profile.json", "account-pin.json", "funding.hex", "reservation-state.json", "reservation-manifest.json", "A.psbt", "B.psbt", "transaction-index.json"},
	"reveal":         {"profile.json", "account-pin.json", "reveal-state.json", "reveal-values-pin.json", "reveal-manifest.json", "C.psbt", "D.psbt", "transaction-index.json"},
	"request":        {"profile.json", "account-pin.json", "request-state.json", "request.json", "review-frame.bin"},
	"checked-result": {"profile.json", "account-pin.json", "verification-state.json", "verified-transaction.hex", "public-result.json"},
}

func (e *fixtureEnv) bundle(t *testing.T, label, kind string, files map[string][]byte) string {
	t.Helper()
	dir := filepath.Join(e.dir, label)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	index := bundleIndex{prefix + "bundle/1", kind, digest(e.profile), digest(e.pin), []fileRecord{}}
	for _, name := range payloads[kind] {
		b, ok := files[name]
		if !ok {
			t.Fatalf("missing adapter payload %s", name)
		}
		write(t, filepath.Join(dir, name), b)
		index.Files = append(index.Files, fileRecord{name, uint64(len(b)), digest(b)})
	}
	path := filepath.Join(dir, "bundle.json")
	write(t, path, canonical(t, index))
	return path
}
func reseal(t *testing.T, path string) string {
	t.Helper()
	var index bundleIndex
	decode(t, read(t, path), &index)
	for i := range index.Files {
		b := read(t, filepath.Join(filepath.Dir(path), index.Files[i].Name))
		index.Files[i].Size, index.Files[i].Hash = uint64(len(b)), digest(b)
	}
	write(t, path, canonical(t, index))
	return digest(read(t, path))
}

// Materialize retained public fixture records, never a fresh API call at an
// invented clock. Original requests, manifests, PSBTs and frames stay byte exact.
func frozen(t *testing.T, mode string) *fixtureEnv {
	t.Helper()
	return frozenAt(t, mode, false)
}

func frozenAt(t *testing.T, mode string, contemporary bool) *fixtureEnv {
	t.Helper()
	e := &fixtureEnv{dir: freshDir(t), parents: map[string]parent{}}
	requests, frames, results := map[string][]byte{}, map[string][]byte{}, map[string][]byte{}
	for _, slot := range []string{"A", "B", "C", "D"} {
		requests[slot] = wireFixture(t, mode, slot+"-request.json")
		frame, err := hex.DecodeString(strings.TrimSpace(string(wireFixture(t, mode, slot+"-review-frame.hex"))))
		if err != nil {
			t.Fatal(err)
		}
		frames[slot], results[slot] = frame, wireFixture(t, mode, slot+"-result.json")
	}
	revealPin := wireFixture(t, mode, "trusted-reveal-values-pin.json")
	if contemporary {
		revealPin = contemporaryPublicContexts(t, mode, requests, frames, results, revealPin)
	}
	var a, c namecoinwire.Request
	decode(t, requests["A"], &a)
	decode(t, requests["C"], &c)
	var reservation namecoinwire.ReservationPlan
	var reveal namecoinwire.RevealPlan
	decode(t, []byte(a.ManifestUTF8), &reservation)
	decode(t, []byte(c.ManifestUTF8), &reveal)
	e.profile = jsonBytes(t, profile{prefix + "profile/1", reservation.Network, reservation.Genesis, reservation.Policy})
	e.pin = psbtFixture(t, mode, "account-pin.json")
	e.profilePath, e.pinPath = filepath.Join(e.dir, "selected-profile.json"), filepath.Join(e.dir, "selected-pin.json")
	write(t, e.profilePath, e.profile)
	write(t, e.pinPath, e.pin)
	state := reservationState{Schema: prefix + "reservation-state/1", PreparedAt: reservation.Policy.CreatedAt + 60,
		Funding: funding{"funding.hex", reservation.Funding.TxID, reservation.Funding.Vout, reservation.Transactions[0].Inputs[0].Path},
		Names:   []savedName{}, Change: []string{}, Fees: []string{}}
	for i, n := range reservation.Registrations {
		name, err := hex.DecodeString(n.NameHex)
		if err != nil {
			t.Fatal(err)
		}
		var value struct {
			Hex string `json:"value_hex"`
		}
		decode(t, n.FutureValue, &value)
		state.Names = append(state.Names, savedName{string(name), n.NameOutputPath, value.Hex, n.RandHex})
		state.Change = append(state.Change, reservation.Transactions[i].Outputs[1].Path)
		state.Fees = append(state.Fees, reservation.Transactions[i].Fee)
	}
	planPayload := func(kind string, transactions []namecoinwire.Transaction, manifest string) map[string][]byte {
		files := e.base()
		files[kind+"-manifest.json"] = []byte(manifest)
		index := transactionIndex{prefix + "transactions/1", []transactionRow{}}
		for _, tx := range transactions {
			var req namecoinwire.Request
			decode(t, requests[tx.Slot], &req)
			files[tx.Slot+".psbt"] = []byte(req.PSBT)
			// Contract interval: stripped bytes plus marker/flag and one
			// 45..108-byte P2WPKH witness per admitted input. Not a maximum-shape measurement.
			n, inputs := uint32(len(tx.UnsignedHex)/2), uint32(len(tx.Inputs))
			index.Transactions = append(index.Transactions, transactionRow{tx.Slot, tx.UnsignedTxID, tx.Slot + ".psbt", n,
				(4*n + 2 + 45*inputs + 3) / 4, (4*n + 2 + 108*inputs + 3) / 4})
		}
		files["transaction-index.json"] = canonical(t, index)
		return files
	}
	files := planPayload("reservation", reservation.Transactions, a.ManifestUTF8)
	files["funding.hex"], files["reservation-state.json"] = []byte(reservation.Funding.TransactionHex), canonical(t, state)
	e.reservation = e.bundle(t, "reservation", "reservation", files)
	requestBundle := func(slot, plan string) {
		raw := requests[slot]
		var req namecoinwire.Request
		decode(t, raw, &req)
		frame := frames[slot]
		files := e.base()
		files["request.json"], files["review-frame.bin"] = raw, frame
		files["request-state.json"] = canonical(t, requestState{prefix + "request-state/1", plan, digest(read(t, plan)), slot,
			state.PreparedAt, req.RequestID, req.SittingID, req.ExpiresAt, digest(raw), digest(frame)})
		bundle := e.bundle(t, "request-"+slot, "request", files)
		resultPath, stdoutPath := filepath.Join(e.dir, slot+"-result.json"), filepath.Join(e.dir, slot+"-ack.stdout")
		result, stdout := results[slot], wireFixture(t, mode, slot+"-ack.stdout")
		if contemporary {
			stdout = acknowledgement(result)
		}
		write(t, resultPath, result)
		write(t, stdoutPath, stdout)
		e.parents[slot] = parent{bundle, digest(read(t, bundle)), resultPath, digest(result), stdoutPath, digest(stdout), 0}
	}
	requestBundle("A", e.reservation)
	requestBundle("B", e.reservation)
	files = planPayload("reveal", reveal.Transactions, c.ManifestUTF8)
	files["reveal-values-pin.json"] = revealPin
	files["reveal-state.json"] = canonical(t, revealState{prefix + "reveal-state/1", e.reservation, digest(read(t, e.reservation)),
		[]parent{e.parents["A"], e.parents["B"]}, "reveal-values-pin.json", digest(files["reveal-values-pin.json"]),
		[]string{reveal.Transactions[0].Outputs[1].Path, reveal.Transactions[1].Outputs[1].Path},
		[]string{reveal.Transactions[0].Fee, reveal.Transactions[1].Fee}, state.PreparedAt})
	e.reveal = e.bundle(t, "reveal", "reveal", files)
	requestBundle("C", e.reveal)
	requestBundle("D", e.reveal)
	return e
}

func acknowledgement(result []byte) []byte {
	return []byte("{\"schema\":\"keyvault-namecoin-psbt-ack/2\",\"status\":\"SIGNED\",\"result_sha256\":\"" + digest(result) + "\"}\n")
}

// Re-correlate existing public Core signatures to contemporary synthetic public
// contexts without signing. Transactions/sighashes are unchanged; journal claims
// remain format-only. This never authenticates preparation time or native history.
func contemporaryPublicContexts(t *testing.T, mode string, requests, frames, results map[string][]byte, revealPin []byte) []byte {
	t.Helper()
	var a, c namecoinwire.Request
	decode(t, requests["A"], &a)
	decode(t, requests["C"], &c)
	var reservation namecoinwire.ReservationPlan
	var reveal namecoinwire.RevealPlan
	decode(t, []byte(a.ManifestUTF8), &reservation)
	decode(t, []byte(c.ManifestUTF8), &reveal)
	now := uint64(time.Now().Unix())
	reservation.Policy.CreatedAt, reservation.Policy.ReleaseNotAfter = now-60, now-60+86400
	reveal.Policy = reservation.Policy
	reservationRaw := jsonBytes(t, reservation)
	reveal.ReservationPlanSHA256 = namecoinwire.PlanDigest(reservationRaw)
	revealRaw := jsonBytes(t, reveal)
	var pinHash [32]byte
	copy(pinHash[:], mustHex(t, reservation.AccountPinSHA256))
	context := namecoinwire.ReviewContext{Group: reservation.Group, Account: reservation.Account,
		Network: reservation.Network, Genesis: reservation.Genesis, PolicyRevision: reservation.Policy.Revision,
		AccountPinSHA256: pinHash, PerTxFeeCap: 100000}
	for _, slot := range []string{"A", "B", "C", "D"} {
		var req namecoinwire.Request
		decode(t, requests[slot], &req)
		manifest := reservationRaw
		if slot == "C" || slot == "D" {
			manifest = revealRaw
		}
		req.ManifestUTF8, req.PlanSHA256 = string(manifest), namecoinwire.PlanDigest(manifest)
		req.ReservationPlanSHA256, req.ExpiresAt = reveal.ReservationPlanSHA256, now+600
		requests[slot] = jsonBytes(t, req)
		snapshot, err := namecoinwire.Decode(requests[slot])
		if err != nil {
			t.Fatal(err)
		}
		frames[slot], err = snapshot.ReviewFrame(context)
		if err != nil {
			t.Fatal(err)
		}
		var result namecoinwire.Result
		decode(t, results[slot], &result)
		result.Receipt.PlanSHA256, result.Receipt.ReservationPlanSHA256 = req.PlanSHA256, req.ReservationPlanSHA256
		result.Receipt.ReviewSHA256 = digest(frames[slot])
		results[slot] = canonical(t, result)
	}
	var pin namecoinwire.RevealValuesPin
	decode(t, revealPin, &pin)
	pin.ReservationPlanSHA256 = reveal.ReservationPlanSHA256
	return jsonBytes(t, pin)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func identityCLI(t *testing.T) string {
	t.Helper()
	path := os.Getenv("KEYVAULT_IDENTITY_CLI")
	if path == "" {
		t.Skip("public CLI docking not selected; set KEYVAULT_IDENTITY_CLI to the independently built identity binary")
	}
	if !filepath.IsAbs(path) {
		t.Fatal("KEYVAULT_IDENTITY_CLI must be absolute")
	}
	return path
}
func (e *fixtureEnv) run(t *testing.T, command, label string, input any, extra ...string) (string, envelope, int) {
	t.Helper()
	cli := identityCLI(t)
	in, out := filepath.Join(e.dir, label+"-input.json"), filepath.Join(e.dir, label)
	write(t, in, jsonBytes(t, input))
	args := []string{"registration", command, "--request", in, "--out-dir", out, "--json", "--profile", e.profilePath,
		"--profile-sha256", digest(e.profile), "--account-pin", e.pinPath, "--account-pin-sha256", digest(e.pin)}
	args = append(args, extra...)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, cli, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	exit := 0
	if err != nil {
		var failure *exec.ExitError
		if !errors.As(err, &failure) || failure.ExitCode() < 0 {
			t.Fatalf("CLI setup or abnormal termination: %v", err)
		}
		exit = failure.ExitCode()
	}
	if stderr.Len() != 0 || bytes.Count(stdout.Bytes(), []byte{'\n'}) != 1 || !bytes.HasSuffix(stdout.Bytes(), []byte{'\n'}) {
		t.Fatal("CLI did not return its single-line public envelope")
	}
	// The field order and closed envelope are part of the public CLI contract,
	// independently of a permissive struct decoder's acceptance.
	ordered := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	if token, err := ordered.Token(); err != nil || token != json.Delim('{') {
		t.Fatal("envelope is not an object")
	}
	for _, name := range []string{"schema", "ok", "command", "network", "result", "error"} {
		if token, err := ordered.Token(); err != nil || token != name {
			t.Fatal("closed envelope field order differs")
		}
		var field json.RawMessage
		if err := ordered.Decode(&field); err != nil {
			t.Fatal(err)
		}
	}
	if token, err := ordered.Token(); err != nil || token != json.Delim('}') {
		t.Fatal("envelope has extra fields")
	}
	if _, err := ordered.Token(); err != io.EOF {
		t.Fatal("envelope has trailing data")
	}
	var en envelope
	decoder := json.NewDecoder(&stdout)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&en); err != nil {
		t.Fatal("invalid public envelope", err)
	}
	if en.Schema != "swarma-identity/result/1" || en.Command != "registration "+command {
		t.Fatal("envelope identity mismatch")
	}
	if en.OK {
		var selected profile
		decode(t, e.profile, &selected)
		if en.Network != selected.Network {
			t.Fatal("success network differs from independently selected profile")
		}
	}
	return out, en, exit
}
func checkInput(p parent) map[string]any {
	return map[string]any{"schema": prefix + "check-result/1", "request_bundle": p.Bundle, "request_bundle_sha256": p.BundleHash,
		"result": p.Result, "result_sha256": p.ResultHash, "stdout": p.Stdout, "stdout_sha256": p.StdoutHash, "process_exit": p.Exit}
}
func requireRefusal(t *testing.T, out string, en envelope, exit int, code string, wantExit int) {
	t.Helper()
	if exit != wantExit || en.OK || en.Result != nil || en.Error == nil || en.Error.Code != code || en.Error.Retryable {
		t.Fatalf("intended refusal missing: want %s/%d, got exit%d envelope %+v", code, wantExit, exit, en)
	}
	messages := map[string]string{
		"BAD_INPUT":                   "The input does not satisfy the selected contract.",
		"REGISTRATION_POLICY_REFUSED": "The registration policy was refused.",
		"REGISTRATION_PARENT_REFUSED": "The registration predecessor context was refused.",
		"REGISTRATION_RESULT_REFUSED": "The registration result was refused.",
		"REGISTRATION_FILES":          "The registration files could not be admitted or committed.",
	}
	if en.Error.Message != messages[code] {
		t.Fatal("fixed refusal message differs")
	}
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("semantic refusal created output")
	}
}
func requireSuccess(t *testing.T, out string, en envelope, exit int, kind string) {
	t.Helper()
	if exit != 0 || !en.OK || en.Error != nil || en.Result == nil {
		t.Fatalf("valid control refused: exit%d %+v", exit, en)
	}
	raw := read(t, filepath.Join(out, "bundle.json"))
	var index bundleIndex
	decode(t, raw, &index)
	if !bytes.Equal(raw, canonical(t, index)) {
		t.Fatal("bundle index is not closed canonical JSON plus LF")
	}
	if en.Result.Hash != digest(raw) || index.Kind != kind || len(index.Files) != len(payloads[kind]) || !bytes.Equal(jsonBytes(t, en.Result.Files), jsonBytes(t, index.Files)) {
		t.Fatal("bundle/envelope commitments differ")
	}
	for i, row := range index.Files {
		b := read(t, filepath.Join(out, row.Name))
		if row.Name != payloads[kind][i] || row.Size != uint64(len(b)) || row.Hash != digest(b) {
			t.Fatal("committed payload differs")
		}
	}
}

func decodePSBT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
