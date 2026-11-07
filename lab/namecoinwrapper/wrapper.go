// Package namecoinwrapper is an offline/regtest-only adapter experiment.
// It deliberately has no RPC transport, wallet, watcher, signer or effect runner.
package namecoinwrapper

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const RegtestGenesis = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"

var ErrRefused = errors.New("lab verification refused")

// Node must be the verifier's independently configured own-node read broker.
// Never implement this from request-supplied snapshots in a live composition.
// Calls must honor context cancellation and return fresh replies, never cached
// successes on transport/health failure. This seam matches chain-lab's public
// read pipe; no transport is provided here.
type Node interface {
	Call(context.Context, string, ...any) (json.RawMessage, error)
}

// Policy is independently installed lab policy, never derived from certificate
// or request fields. All keys in this experiment are simulated throwaway keys.
type Policy struct {
	// ExpectedOwner is independent identity policy, never a name-record or
	// payload value. Empty preserves the original Alexis test profile.
	ExpectedOwner                                string
	OwnerName, RequesterName                     string
	Account, Device, Deployment, Executor, Cycle string
	CLI, CLIHash, PrivateRoot                    string
	AnchorTxID, AnchorBlock, SealTxID            string
	SealVout                                     int
}

// Verifier serializes a short lab session. A confirmed issuance replacement,
// detected seal spend/unknown seal, reorg or changed tip creates a private
// refusal latch for these exact bytes.
// Reusing the same private policy root preserves the latch across restarts.
// This is not a long-running watcher or a distributed lifecycle service.
type Verifier struct {
	mu     sync.Mutex
	closed bool
}

// Observation records a repeatable verification at an explicit lab timestamp.
// It neither reserves a request nor authorizes an effect. Durable admission and
// the independent stale-node watcher belong to the integrating application.
type Observation struct {
	Verdict           string `json:"verdict"`
	CertificateID     string `json:"certificate_id"`
	RequestID         string `json:"request_id"`
	CertificateSHA256 string `json:"certificate_sha256"`
	AnchorBlock       string `json:"anchor_block"`
}

type tip struct {
	Chain  string `json:"chain"`
	Hash   string `json:"bestblockhash"`
	Height int    `json:"blocks"`
	IBD    bool   `json:"initialblockdownload"`
}
type point struct {
	TxID string `json:"txid"`
	Vout int    `json:"vout"`
}
type nameShow struct {
	Name          string `json:"name"`
	Value         string `json:"value"`
	TxID          string `json:"txid"`
	Vout          int    `json:"vout"`
	Address       string `json:"address"`
	Expired       bool   `json:"expired"`
	ExpiresIn     int    `json:"expires_in"`
	Height        int    `json:"height"`
	NameEncoding  string `json:"name_encoding"`
	ValueEncoding string `json:"value_encoding"`
}
type record struct {
	Swarma struct {
		Owner       string `json:"keyvault_owner_spki"`
		Requester   string `json:"keyvault_requester_spki"`
		Certificate string `json:"keyvault_certificate_sha256"`
		Seal        *point `json:"keyvault_seal"`
	} `json:"swarma"`
}
type nameOperation struct {
	Op            string          `json:"op"`
	Name          string          `json:"name"`
	Value         string          `json:"value"`
	NameEncoding  string          `json:"name_encoding"`
	ValueEncoding string          `json:"value_encoding"`
	NameError     json.RawMessage `json:"name_error"`
	ValueError    json.RawMessage `json:"value_error"`
}

// Project the official RPC spellings exactly. encoding/json's normal struct
// matching would otherwise accept aliases such as NAME_ENCODING.
func (op *nameOperation) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return ErrRefused
	}
	for key, dst := range map[string]any{
		"op": &op.Op, "name": &op.Name, "value": &op.Value,
		"name_encoding": &op.NameEncoding, "value_encoding": &op.ValueEncoding,
	} {
		if field, ok := fields[key]; ok {
			if json.Unmarshal(field, dst) != nil {
				return ErrRefused
			}
		}
	}
	op.NameError = fields["name_error"]
	op.ValueError = fields["value_error"]
	return nil
}

type script struct {
	Hex     string        `json:"hex"`
	Address string        `json:"address"`
	NameOp  nameOperation `json:"nameOp"`
}
type transaction struct {
	TxID          string `json:"txid"`
	Blockhash     string `json:"blockhash"`
	Confirmations int    `json:"confirmations"`
	Vout          []struct {
		N      int    `json:"n"`
		Script script `json:"scriptPubKey"`
	} `json:"vout"`
}

// uniqueJSON rejects ambiguous duplicate members at every nesting level before
// normal projection. Bounds apply before parsing, including public RPC replies.
func uniqueJSON(raw []byte, max int, out any) error {
	if len(raw) == 0 || len(raw) > max {
		return ErrRefused
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	var scan func(int) error
	scan = func(depth int) error {
		if depth > 24 {
			return ErrRefused
		}
		t, err := d.Token()
		if err != nil {
			return ErrRefused
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, err := d.Token()
					if err != nil {
						return ErrRefused
					}
					s, ok := k.(string)
					if !ok || seen[s] {
						return ErrRefused
					}
					seen[s] = true
					if err := scan(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err := scan(depth + 1); err != nil {
						return err
					}
				}
			default:
				return ErrRefused
			}
			if _, err := d.Token(); err != nil {
				return ErrRefused
			}
		}
		return nil
	}
	if err := scan(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrRefused
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return ErrRefused
	}
	return nil
}

func hash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func digest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func public(s string) ([]byte, error) {
	if len(s) != 122 {
		return nil, ErrRefused
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, ErrRefused
	}
	k, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, ErrRefused
	}
	p, ok := k.(*ecdsa.PublicKey)
	if !ok || p.Curve != elliptic.P256() {
		return nil, ErrRefused
	}
	canonical, err := x509.MarshalPKIXPublicKey(p)
	if err != nil || !bytes.Equal(canonical, b) {
		return nil, ErrRefused
	}
	return b, nil
}

func call(ctx context.Context, n Node, method string, out any, args ...any) error {
	// Closed read methods only; no caller-provided method or argv enters here.
	switch method {
	case "getblockchaininfo", "getblockhash", "getblockheader", "name_show", "getrawtransaction", "gettxout":
	default:
		return ErrRefused
	}
	raw, err := n.Call(ctx, method, args...)
	if err != nil {
		return ErrRefused
	}
	max := 65536
	if method == "name_show" {
		max = 4096
	}
	return uniqueJSON(raw, max, out)
}

// This lab uses the byte-preserving ASCII route, including nameOp projections
// from getrawtransaction. The broker must use Namecoin's ASCII configuration
// for those transaction projections; no decoding or normalization is allowed.
func ascii(s string) bool {
	for i := range s {
		if s[i] < 0x20 || s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func nameOptions() map[string]any {
	return map[string]any{"nameEncoding": "ascii", "valueEncoding": "ascii", "allowExpired": false}
}

func resolveName(ctx context.Context, n Node, name string) (nameShow, error) {
	var v nameShow
	var fields map[string]json.RawMessage
	if err := call(ctx, n, "name_show", &fields, name, nameOptions()); err != nil {
		return v, err
	}
	if _, ok := fields["name_error"]; ok {
		return v, ErrRefused
	}
	if _, ok := fields["value_error"]; ok {
		return v, ErrRefused
	}
	for key, dst := range map[string]any{
		"name": &v.Name, "value": &v.Value, "txid": &v.TxID,
		"vout": &v.Vout, "address": &v.Address, "expired": &v.Expired,
		"expires_in": &v.ExpiresIn, "name_encoding": &v.NameEncoding,
		"value_encoding": &v.ValueEncoding, "height": &v.Height,
	} {
		raw, ok := fields[key]
		if !ok || bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, dst) != nil {
			return v, ErrRefused
		}
	}
	if v.Name != name || v.Expired || v.ExpiresIn <= 0 || v.Height < 0 || v.Vout < 0 || !digest(v.TxID) || v.Address == "" ||
		v.NameEncoding != "ascii" || v.ValueEncoding != "ascii" || !ascii(v.Name) || !ascii(v.Value) {
		return v, ErrRefused
	}
	return v, nil
}

func parseRecord(v nameShow) (record, error) {
	var r record
	var outer map[string]json.RawMessage
	if err := uniqueJSON([]byte(v.Value), 520, &outer); err != nil {
		return r, err
	}
	// encoding/json matches struct fields case-insensitively. Project the exact
	// public record keys explicitly so spelling aliases cannot select a pin.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(outer["swarma"], &fields); err != nil {
		return r, ErrRefused
	}
	for key, dst := range map[string]*string{"keyvault_owner_spki": &r.Swarma.Owner, "keyvault_requester_spki": &r.Swarma.Requester, "keyvault_certificate_sha256": &r.Swarma.Certificate} {
		if raw, ok := fields[key]; ok {
			if err := json.Unmarshal(raw, dst); err != nil {
				return r, ErrRefused
			}
		}
	}
	if raw, ok := fields["keyvault_seal"]; ok {
		var f map[string]json.RawMessage
		if err := json.Unmarshal(raw, &f); err != nil {
			return r, ErrRefused
		}
		p := &point{}
		if err := json.Unmarshal(f["txid"], &p.TxID); err != nil {
			return r, ErrRefused
		}
		if err := json.Unmarshal(f["vout"], &p.Vout); err != nil {
			return r, ErrRefused
		}
		r.Swarma.Seal = p
	}
	return r, nil
}

func checkedName(ctx context.Context, n Node, v nameShow) (transaction, error) {
	var tx transaction
	if err := call(ctx, n, "getrawtransaction", &tx, v.TxID, true); err != nil {
		return tx, err
	}
	if tx.TxID != v.TxID || tx.Confirmations < 1 || !digest(tx.Blockhash) || len(tx.Vout) > 128 {
		return tx, ErrRefused
	}
	count := 0
	for _, o := range tx.Vout {
		if o.Script.NameOp.Name == v.Name {
			count++
			if o.N != v.Vout || o.Script.Address != v.Address || o.Script.NameOp.Value != v.Value ||
				(o.Script.NameOp.Op != "name_update" && o.Script.NameOp.Op != "name_firstupdate") ||
				o.Script.NameOp.NameEncoding != "ascii" || o.Script.NameOp.ValueEncoding != "ascii" ||
				len(o.Script.NameOp.NameError) != 0 || len(o.Script.NameOp.ValueError) != 0 {
				return tx, ErrRefused
			}
		}
	}
	if count != 1 {
		return tx, ErrRefused
	}
	var header struct {
		Height        int `json:"height"`
		Confirmations int `json:"confirmations"`
	}
	if err := call(ctx, n, "getblockheader", &header, tx.Blockhash); err != nil {
		return tx, err
	}
	if header.Height < 0 || header.Height != v.Height || header.Confirmations < 1 {
		return tx, ErrRefused
	}
	var canonical string
	if err := call(ctx, n, "getblockhash", &canonical, header.Height); err != nil || canonical != tx.Blockhash {
		return tx, ErrRefused
	}
	return tx, nil
}

// Verify returns only a repeatable verification observation, never admission.
// It does not implement replay reservation, a 30-minute idle STOP or a provider.
// at is an explicit lab observation; it is not a protected production clock.
// Recheck all inputs on every attempt: there is no cached-enrollment fallback.
func (v *Verifier) Verify(ctx context.Context, n Node, p Policy, certificate, request []byte, at time.Time) (*Observation, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed || n == nil || len(certificate) == 0 || len(certificate) > 98304 || len(request) == 0 || len(request) > 12288 || at.IsZero() {
		return nil, ErrRefused
	}
	if p.OwnerName == "" || p.RequesterName == "" || p.OwnerName == p.RequesterName || len(p.OwnerName) > 255 || len(p.RequesterName) > 255 {
		return nil, ErrRefused
	}
	if !digest(p.AnchorTxID) || !digest(p.AnchorBlock) || !digest(p.SealTxID) || p.SealVout < 0 {
		return nil, ErrRefused
	}
	// The broker contract and CLI share this observation deadline.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var before tip
	var genesis string
	if err := call(ctx, n, "getblockchaininfo", &before); err != nil {
		return nil, err
	}
	if before.Chain != "regtest" || before.IBD || before.Height < 1 || !digest(before.Hash) {
		return nil, ErrRefused
	}
	if err := call(ctx, n, "getblockhash", &genesis, 0); err != nil || genesis != RegtestGenesis {
		return nil, ErrRefused
	}
	certHash := hash(certificate)
	if !privateRoot(p.PrivateRoot) {
		return nil, ErrRefused
	}
	latch := filepath.Join(p.PrivateRoot, "closed-"+certHash)
	if _, err := os.Lstat(latch); !os.IsNotExist(err) {
		return nil, ErrRefused
	}
	closeObservation := func() {
		v.closed = true
		// Even an I/O failure keeps this instance closed. The caller must retain
		// this private root; removing its state is an explicit reset, not recovery.
		f, err := os.OpenFile(latch, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			_, _ = f.Write([]byte("refused\n"))
			_ = f.Sync()
			_ = f.Close()
			if parent, err := os.Open(p.PrivateRoot); err == nil {
				_ = parent.Sync()
				_ = parent.Close()
			}
		}
	}
	owner, err := resolveName(ctx, n, p.OwnerName)
	if err != nil {
		return nil, err
	}
	anchor, err := checkedName(ctx, n, owner)
	if err != nil {
		closeObservation()
		return nil, ErrRefused
	}
	// Establish canonical confirmation before treating an issuance replacement
	// as final. Persist closure BEFORE parsing the replacement's record or
	// resolving the requester: neither can hide a confirmed generation change.
	if owner.TxID != p.AnchorTxID || anchor.Blockhash != p.AnchorBlock {
		closeObservation()
		return nil, ErrRefused
	}
	o, err := parseRecord(owner)
	if err != nil {
		return nil, err
	}
	if !digest(o.Swarma.Certificate) || o.Swarma.Certificate != certHash || o.Swarma.Seal == nil || o.Swarma.Seal.TxID != p.SealTxID || o.Swarma.Seal.Vout != p.SealVout {
		return nil, ErrRefused
	}
	requester, err := resolveName(ctx, n, p.RequesterName)
	if err != nil {
		return nil, err
	}
	r, err := parseRecord(requester)
	if err != nil {
		return nil, err
	}
	op, err := public(o.Swarma.Owner)
	if err != nil {
		return nil, err
	}
	rp, err := public(r.Swarma.Requester)
	if err != nil || bytes.Equal(op, rp) {
		return nil, ErrRefused
	}
	if _, err := checkedName(ctx, n, requester); err != nil {
		closeObservation()
		return nil, err
	}
	found := 0
	for _, out := range anchor.Vout {
		if out.Script.Hex == "6a20"+certHash {
			found++
		}
	}
	if found != 1 {
		return nil, ErrRefused
	}
	if err := checkSeal(ctx, n, *o.Swarma.Seal, owner.Address, before.Hash); err != nil {
		closeObservation()
		return nil, err
	}
	facts, err := verifyCLI(ctx, p, o.Swarma.Owner, r.Swarma.Requester, certificate, request, at)
	if err != nil {
		return nil, err
	}
	// A name can be updated independently of the observed block tip. Re-resolve
	// both names; no changed pin/value/generation is admitted in this observation.
	ownerAfter, err := resolveName(ctx, n, p.OwnerName)
	if err != nil || ownerAfter != owner {
		closeObservation()
		return nil, ErrRefused
	}
	requesterAfter, err := resolveName(ctx, n, p.RequesterName)
	if err != nil || requesterAfter != requester {
		closeObservation()
		return nil, ErrRefused
	}
	var after tip
	if err := call(ctx, n, "getblockchaininfo", &after); err != nil || after != before {
		closeObservation()
		return nil, ErrRefused
	}
	// Last public check includes mempool spends, after names, tip and CLI.
	if err := checkSeal(ctx, n, *o.Swarma.Seal, owner.Address, before.Hash); err != nil {
		closeObservation()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		closeObservation()
		return nil, err
	}
	return &Observation{"verified-lab-observation", facts.CertificateID, facts.RequestID, certHash, anchor.Blockhash}, nil
}

func checkSeal(ctx context.Context, n Node, p point, address, best string) error {
	var seal *struct {
		Bestblock     string `json:"bestblock"`
		Confirmations int    `json:"confirmations"`
		Script        script `json:"scriptPubKey"`
	}
	if err := call(ctx, n, "gettxout", &seal, p.TxID, p.Vout, true); err != nil {
		return err
	}
	if seal == nil || seal.Confirmations < 1 || seal.Bestblock != best || seal.Script.Address != address {
		return ErrRefused
	}
	return nil
}

type verification struct {
	Verdict       string                                          `json:"verdict"`
	CertificateID string                                          `json:"certificate_id"`
	RequestID     string                                          `json:"request_id"`
	Action        string                                          `json:"action"`
	Target        struct{ Organization, Name, Visibility string } `json:"target"`
	ValidAt       time.Time                                       `json:"valid_at"`
	ExpiresAt     time.Time                                       `json:"expires_at"`
}

type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func privateRoot(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	st, err := os.Lstat(path)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return false
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(owner.Uid) == os.Getuid()
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, ErrRefused
	}
	return b.Buffer.Write(p)
}

func verifyCLI(ctx context.Context, p Policy, owner, requester string, cert, req []byte, at time.Time) (*verification, error) {
	expectedOwner := p.ExpectedOwner
	if expectedOwner == "" {
		expectedOwner = "@alexis:gr.relux.works"
	}
	if !filepath.IsAbs(p.PrivateRoot) || filepath.Clean(p.PrivateRoot) != p.PrivateRoot || !filepath.IsAbs(p.CLI) || !digest(p.CLIHash) {
		return nil, ErrRefused
	}
	if !privateRoot(p.PrivateRoot) {
		return nil, ErrRefused
	}
	binary, err := os.Open(p.CLI)
	if err != nil {
		return nil, ErrRefused
	}
	h := sha256.New()
	_, err = io.Copy(h, io.LimitReader(binary, 64<<20))
	binary.Close()
	if err != nil || hex.EncodeToString(h.Sum(nil)) != p.CLIHash {
		return nil, ErrRefused
	}
	dir, err := os.MkdirTemp(p.PrivateRoot, "observation-")
	if err != nil {
		return nil, ErrRefused
	}
	defer os.RemoveAll(dir)
	config := map[string]any{
		"type": "grants-local-enrollment-2", "owner_mxid": expectedOwner, "owner_spki": owner, "requester_spki": requester,
		"subject":      map[string]string{"account_mxid": p.Account, "device_id": p.Device},
		"audience":     map[string]string{"deployment_id": p.Deployment, "executor_id": p.Executor},
		"cycle":        map[string]string{"cycle_id": p.Cycle, "runtime": "codex", "channel": "encrypted-dm"},
		"organization": "relux-works", "name": "matrix-grants-poc-261031", "state_dir": filepath.Join(dir, "ABSENT-STATE"), "gh_path": filepath.Join(dir, "ABSENT-PROVIDER"),
	}
	raw, err := json.Marshal(config)
	if err != nil {
		return nil, ErrRefused
	}
	for name, content := range map[string][]byte{"config.json": raw, "certificate.json": cert, "request.json": req} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0600); err != nil {
			return nil, ErrRefused
		}
	}
	args := []string{"grants", "verify", "--config", filepath.Join(dir, "config.json"), "--certificate", filepath.Join(dir, "certificate.json"), "--request", filepath.Join(dir, "request.json"), "--at", at.UTC().Format(time.RFC3339)}
	if p.ExpectedOwner != "" {
		args = append(args, "--owner-mxid", expectedOwner)
	}
	cmd := exec.CommandContext(ctx, p.CLI, args...)
	cmd.Env = []string{"HOME=" + dir, "TMPDIR=" + dir, "XDG_CACHE_HOME=" + dir, "PATH=/nonexistent"}
	cmd.Dir = dir
	out := &cappedBuffer{limit: 8192}
	diag := &cappedBuffer{limit: 8192}
	cmd.Stdout = out
	cmd.Stderr = diag
	// CLI diagnostics are deliberately not exposed: even an unexpected provider
	// failure must not copy host paths or private configuration into a verdict.
	if err := cmd.Run(); err != nil {
		return nil, ErrRefused
	}
	var facts verification
	if err := uniqueJSON(out.Bytes(), 8192, &facts); err != nil {
		return nil, err
	}
	if facts.Verdict != "accepted" || facts.CertificateID == "" || facts.RequestID == "" || facts.Action != "repository.create" || facts.Target.Organization != "relux-works" || facts.Target.Name != "matrix-grants-poc-261031" || facts.Target.Visibility != "private" || !facts.ValidAt.Equal(at) || !facts.ExpiresAt.After(at) {
		return nil, fmt.Errorf("%w: CLI facts", ErrRefused)
	}
	return &facts, nil
}
