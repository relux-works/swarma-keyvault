package namecoinwrapper

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Test-only signer, following the existing main local_verify_test.go domains
// and low-S DER algorithm. Keys exist only in this isolated test process.
// No private serialization, production issuer or Enclave fallback is present.
func signed(t *testing.T, key *ecdsa.PrivateKey, domain, kind string, payload []byte) []byte {
	t.Helper()
	h := sha256.Sum256(append([]byte(domain+"\n"), payload...))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(key.Params().N), 1)) > 0 {
		s.Sub(key.Params().N, s)
	}
	sig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal(err)
	}
	return marshal(t, map[string]string{"type": kind, "payload": base64.RawURLEncoding.EncodeToString(payload), "signature": base64.RawURLEncoding.EncodeToString(sig)})
}
func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func keypair(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k, b
}

type fakeNode struct {
	data    map[string]json.RawMessage
	calls   []string
	mutate  func(string, []any)
	unknown string
}

func callKey(method string, args ...any) string {
	b, _ := json.Marshal(args)
	return method + ":" + string(b)
}
func (n *fakeNode) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n.calls = append(n.calls, callKey(method, args...))
	if n.mutate != nil {
		n.mutate(method, args)
	}
	if n.unknown == method {
		return nil, errors.New("UNKNOWN")
	}
	raw, ok := n.data[callKey(method, args...)]
	if !ok {
		return nil, errors.New("unexpected read")
	}
	return bytes.Clone(raw), nil
}
func (n *fakeNode) set(t *testing.T, method string, v any, args ...any) {
	if method == "name_show" && len(args) == 1 {
		args = append(args, map[string]any{"nameEncoding": "ascii", "valueEncoding": "ascii", "allowExpired": false})
	}
	n.data[callKey(method, args...)] = marshal(t, v)
}

type fixture struct {
	n                            *fakeNode
	p                            Policy
	at                           time.Time
	owner, requester             *ecdsa.PrivateKey
	ownerDER, requesterDER       []byte
	certificate, request         []byte
	operation                    map[string]any
	ownerName, requesterName     nameShow
	ownerRecord, requesterRecord map[string]any
	anchor, requesterTX          map[string]any
	seal                         point
	best, block                  string
}

func fresh(t *testing.T) *fixture {
	t.Helper()
	cli := os.Getenv("LAB_KEYVAULT_CLI")
	if cli == "" {
		t.Fatal("LAB_KEYVAULT_CLI must name a separately built unchanged dffe3ac5 CLI")
	}
	b, err := os.ReadFile(cli)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{at: time.Date(2026, 11, 7, 14, 0, 0, 0, time.UTC), best: strings.Repeat("a", 64), block: strings.Repeat("b", 64), seal: point{strings.Repeat("c", 64), 0}}
	f.owner, f.ownerDER = keypair(t)
	f.requester, f.requesterDER = keypair(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	f.p = Policy{OwnerName: "d/alexis-sim", RequesterName: "d/ivan-agent-sim", Account: "@ivan-agent-sim:example.invalid", Device: "LAB", Deployment: "lab", Executor: "ivan-agent-sim", Cycle: "codex-dm", CLI: cli, CLIHash: hash(b), PrivateRoot: root}
	f.p.AnchorTxID, f.p.AnchorBlock, f.p.SealTxID, f.p.SealVout = strings.Repeat("d", 64), f.block, f.seal.TxID, f.seal.Vout
	subject := map[string]string{"account_mxid": f.p.Account, "device_id": f.p.Device}
	audience := map[string]string{"deployment_id": f.p.Deployment, "executor_id": f.p.Executor}
	cycle := map[string]string{"cycle_id": f.p.Cycle, "runtime": "codex", "channel": "encrypted-dm"}
	draft := map[string]any{"audience": audience, "certificate_id": "alexis-sim-to-ivan-agent-sim", "cycles": []any{cycle}, "expires_at": f.at.Add(time.Hour).Format(time.RFC3339), "not_before": f.at.Add(-time.Minute).Format(time.RFC3339), "name": "matrix-grants-poc-261031", "organization": "relux-works", "subject": subject}
	// Actual unchanged CLI local-prepare takes the two separate public DER files.
	for name, raw := range map[string][]byte{"owner.der": f.ownerDER, "requester.der": f.requesterDER, "plan.json": marshal(t, draft)} {
		if err := os.WriteFile(filepath.Join(root, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(cli, "grants", "local-prepare", "--plan", filepath.Join(root, "plan.json"), "--owner-mxid", "@alexis:gr.relux.works", "--issuer-spki-der", filepath.Join(root, "owner.der"), "--requester-spki-der", filepath.Join(root, "requester.der"))
	cmd.Env = []string{"HOME=" + root, "TMPDIR=" + root, "PATH=/nonexistent"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	payload, err := cmd.Output()
	if err != nil {
		t.Fatalf("unchanged prepare failed: %v %s", err, stderr.String())
	}
	f.certificate = signed(t, f.owner, "swarma-grants/local-certificate/1", "grants-signed-local-certificate-1", payload)
	f.operation = map[string]any{"type": "grants-local-operation-1", "request_id": "local-lab-request", "certificate_id": draft["certificate_id"], "entry_id": "repo-create", "cycle_id": f.p.Cycle, "operation_use_id": "codex-dm/create", "subject": subject, "audience": audience, "action": "repository.create", "target": map[string]string{"organization": "relux-works", "name": "matrix-grants-poc-261031", "visibility": "private"}, "expires_at": f.at.Add(30 * time.Minute).Format(time.RFC3339)}
	f.resign(t)
	f.ownerRecord = map[string]any{"swarma": map[string]any{"keyvault_owner_spki": base64.RawURLEncoding.EncodeToString(f.ownerDER), "keyvault_certificate_sha256": hash(f.certificate), "keyvault_seal": f.seal}}
	f.requesterRecord = map[string]any{"swarma": map[string]any{"keyvault_requester_spki": base64.RawURLEncoding.EncodeToString(f.requesterDER)}}
	f.ownerName = nameShow{Name: f.p.OwnerName, Value: string(marshal(t, f.ownerRecord)), TxID: strings.Repeat("d", 64), Vout: 0, Address: "LAB-OWNER", ExpiresIn: 1000, Height: 99, NameEncoding: "ascii", ValueEncoding: "ascii"}
	f.requesterName = nameShow{Name: f.p.RequesterName, Value: string(marshal(t, f.requesterRecord)), TxID: strings.Repeat("e", 64), Vout: 0, Address: "LAB-REQUESTER", ExpiresIn: 1000, Height: 99, NameEncoding: "ascii", ValueEncoding: "ascii"}
	f.n = &fakeNode{data: map[string]json.RawMessage{}}
	f.refreshNames(t)
	f.n.set(t, "getblockchaininfo", tip{"regtest", f.best, 100, false})
	f.n.set(t, "getblockhash", RegtestGenesis, 0)
	f.n.set(t, "getblockhash", f.block, 99)
	f.n.set(t, "getblockheader", map[string]any{"height": 99, "confirmations": 2}, f.block)
	f.n.set(t, "gettxout", map[string]any{"bestblock": f.best, "confirmations": 3, "scriptPubKey": map[string]string{"address": "LAB-OWNER"}}, f.seal.TxID, f.seal.Vout, true)
	return f
}
func (f *fixture) resign(t *testing.T) {
	f.request = signed(t, f.requester, "swarma-grants/local-request/2", "grants-local-request-2", marshal(t, f.operation))
}
func (f *fixture) refreshNames(t *testing.T) {
	f.ownerName.Value = string(marshal(t, f.ownerRecord))
	f.requesterName.Value = string(marshal(t, f.requesterRecord))
	f.n.set(t, "name_show", f.ownerName, f.p.OwnerName)
	f.n.set(t, "name_show", f.requesterName, f.p.RequesterName)
	makeTX := func(n nameShow) map[string]any {
		return map[string]any{"txid": n.TxID, "blockhash": f.block, "confirmations": 2, "vout": []any{map[string]any{"n": 0, "scriptPubKey": map[string]any{"address": n.Address, "nameOp": map[string]string{"op": "name_update", "name": n.Name, "value": n.Value, "name_encoding": "ascii", "value_encoding": "ascii"}}}, map[string]any{"n": 1, "scriptPubKey": map[string]string{"hex": "6a20" + hash(f.certificate)}}}}
	}
	f.anchor = makeTX(f.ownerName)
	f.requesterTX = makeTX(f.requesterName)
	f.n.set(t, "getrawtransaction", f.anchor, f.ownerName.TxID, true)
	f.n.set(t, "getrawtransaction", f.requesterTX, f.requesterName.TxID, true)
}
func (f *fixture) verify(t *testing.T, v *Verifier, want bool) *Observation {
	t.Helper()
	result, err := v.Verify(context.Background(), f.n, f.p, f.certificate, f.request, f.at)
	if want {
		if err != nil || result == nil || result.Verdict != "verified-lab-observation" || result.CertificateSHA256 != hash(f.certificate) {
			t.Fatalf("positive: %v %+v", err, result)
		}
	} else if err == nil || result != nil {
		t.Fatalf("negative admitted: %v %+v", err, result)
	}
	return result
}

func TestThinSlice(t *testing.T) {
	f := fresh(t)
	v := &Verifier{}
	a := f.verify(t, v, true)
	if a.CertificateID != "alexis-sim-to-ivan-agent-sim" || a.RequestID != "local-lab-request" {
		t.Fatal(a)
	}
	// This repeatable observation carries no admission reservation or effect.
	original := bytes.Clone(f.n.data[callKey("gettxout", f.seal.TxID, 0, true)])
	f.n.set(t, "gettxout", nil, f.seal.TxID, 0, true) // mempool spend: include_mempool=true
	f.verify(t, v, false)
	// A new verifier using the same policy root cannot reopen after a reorg.
	f.verify(t, &Verifier{}, false)
	f.n.set(t, "getblockchaininfo", tip{"regtest", strings.Repeat("f", 64), 101, false}) // first block final
	f.verify(t, v, false)
	f.n.data[callKey("gettxout", f.seal.TxID, 0, true)] = original // reorg/restoration cannot reopen this session
	f.n.set(t, "getblockchaininfo", tip{"regtest", f.best, 100, false})
	f.verify(t, v, false)
	if _, err := os.Stat(filepath.Join(f.p.PrivateRoot, "ABSENT-STATE")); !os.IsNotExist(err) {
		t.Fatal("execution state appeared")
	}
	entries, err := os.ReadDir(f.p.PrivateRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "observation-") {
			t.Fatal("private observation not cleaned")
		}
	}
}

func TestCausalRefusals(t *testing.T) {
	cases := map[string]func(*fixture){
		"substitute-new-seal": func(f *fixture) {
			f.ownerRecord["swarma"].(map[string]any)["keyvault_seal"] = point{strings.Repeat("f", 64), 0}
			f.refreshNames(t)
		},
		"substitute-new-anchor":     func(f *fixture) { f.ownerName.TxID = strings.Repeat("f", 64); f.refreshNames(t) },
		"wrong-pinned-anchor-block": func(f *fixture) { f.p.AnchorBlock = strings.Repeat("f", 64) },
		"owner-pin-rotation-no-stale-fallback": func(f *fixture) {
			_, der := keypair(t)
			f.ownerRecord["swarma"].(map[string]any)["keyvault_owner_spki"] = base64.RawURLEncoding.EncodeToString(der)
			f.refreshNames(t)
		},
		"requester-pin-rotation": func(f *fixture) {
			_, der := keypair(t)
			f.requesterRecord["swarma"].(map[string]any)["keyvault_requester_spki"] = base64.RawURLEncoding.EncodeToString(der)
			f.refreshNames(t)
		},
		"unknown-own-node": func(f *fixture) { f.n.unknown = "name_show" },
		"unknown-seal":     func(f *fixture) { f.n.unknown = "gettxout" },
		"stale-node-IBD":   func(f *fixture) { f.n.set(t, "getblockchaininfo", tip{"regtest", f.best, 100, true}) },
		"wrong-genesis":    func(f *fixture) { f.n.set(t, "getblockhash", strings.Repeat("0", 64), 0) },
		"mainnet-excluded": func(f *fixture) { f.n.set(t, "getblockchaininfo", tip{"main", f.best, 100, false}) },
		"expired-name":     func(f *fixture) { f.ownerName.Expired = true; f.n.set(t, "name_show", f.ownerName, f.p.OwnerName) },
		"missing-expiry": func(f *fixture) {
			f.requesterName.ExpiresIn = 0
			f.n.set(t, "name_show", f.requesterName, f.p.RequesterName)
		},
		"wrong-name-identity": func(f *fixture) {
			f.ownerName.Name = f.p.RequesterName
			f.n.set(t, "name_show", f.ownerName, f.p.OwnerName)
		},
		"unconfirmed-anchor": func(f *fixture) {
			f.anchor["confirmations"] = 0
			f.n.set(t, "getrawtransaction", f.anchor, f.ownerName.TxID, true)
		},
		"anchor-reorg": func(f *fixture) { f.n.set(t, "getblockhash", strings.Repeat("0", 64), 99) },
		"wrong-seal-owner": func(f *fixture) {
			f.n.set(t, "gettxout", map[string]any{"bestblock": f.best, "confirmations": 3, "scriptPubKey": map[string]string{"address": "OTHER"}}, f.seal.TxID, 0, true)
		},
		"wrong-anchor-hash": func(f *fixture) {
			f.ownerRecord["swarma"].(map[string]any)["keyvault_certificate_sha256"] = strings.Repeat("0", 64)
			f.refreshNames(t)
		},
		"missing-op-return": func(f *fixture) {
			f.anchor["vout"] = f.anchor["vout"].([]any)[:1]
			f.n.set(t, "getrawtransaction", f.anchor, f.ownerName.TxID, true)
		},
		"request-signature": func(f *fixture) {
			other, _ := keypair(t)
			f.request = signed(t, other, "swarma-grants/local-request/2", "grants-local-request-2", marshal(t, f.operation))
		},
		"signed-wrong-subject": func(f *fixture) {
			f.operation["subject"] = map[string]string{"account_mxid": "@other:example.invalid", "device_id": "LAB"}
			f.resign(t)
		},
		"signed-wrong-audience": func(f *fixture) {
			f.operation["audience"] = map[string]string{"deployment_id": "other", "executor_id": "ivan-agent-sim"}
			f.resign(t)
		},
		"signed-wrong-certificate": func(f *fixture) { f.operation["certificate_id"] = "different"; f.resign(t) },
		"signed-wrong-action":      func(f *fixture) { f.operation["action"] = "repository.delete"; f.resign(t) },
		"signed-wrong-target": func(f *fixture) {
			f.operation["target"] = map[string]string{"organization": "relux-works", "name": "other", "visibility": "private"}
			f.resign(t)
		},
		"expired-request":     func(f *fixture) { f.operation["expires_at"] = f.at.Format(time.RFC3339); f.resign(t) },
		"expired-certificate": func(f *fixture) { f.at = f.at.Add(2 * time.Hour) },
		"binary-pin":          func(f *fixture) { f.p.CLIHash = strings.Repeat("0", 64) },
		"private-root-permissions": func(f *fixture) {
			if err := os.Chmod(f.p.PrivateRoot, 0755); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := fresh(t)
			f.verify(t, &Verifier{}, true)
			change(f)
			f.verify(t, &Verifier{}, false)
		})
	}
}

func TestMidObservationChanges(t *testing.T) {
	for _, kind := range []string{"seal-spend-during-cli", "tip-change", "name-change"} {
		t.Run(kind, func(t *testing.T) {
			f := fresh(t)
			reads := 0
			f.n.mutate = func(method string, args []any) {
				if kind == "seal-spend-during-cli" && method == "gettxout" {
					reads++
					if reads == 2 {
						f.n.set(t, "gettxout", nil, f.seal.TxID, 0, true)
					}
				}
				if kind == "tip-change" && method == "getblockchaininfo" {
					reads++
					if reads == 2 {
						f.n.set(t, method, tip{"regtest", strings.Repeat("f", 64), 101, false})
					}
				}
				if kind == "name-change" && method == "name_show" && args[0] == f.p.OwnerName {
					reads++
					if reads == 2 {
						f.ownerName.TxID = strings.Repeat("f", 64)
						f.n.set(t, method, f.ownerName, f.p.OwnerName)
					}
				}
			}
			f.verify(t, &Verifier{}, false)
		})
	}
}

func TestRecordBoundsAndEncoding(t *testing.T) {
	f := fresh(t)
	for _, size := range []int{520, 521} {
		base := string(marshal(t, f.ownerRecord))
		padded := base[:len(base)-1] + `,"padding":"` + strings.Repeat("x", size-len(base)-13) + `"}`
		if len(padded) != size {
			t.Fatalf("fixture length %d wanted %d", len(padded), size)
		}
		var r record
		err := uniqueJSON([]byte(padded), 520, &r)
		if (err == nil) != (size == 520) {
			t.Fatalf("record bound %d: %v", size, err)
		}
	}
	good := base64.RawURLEncoding.EncodeToString(f.ownerDER)
	for name, value := range map[string]string{"padding": good + "=", "standard-base64": base64.StdEncoding.EncodeToString(f.ownerDER), "trailing-bits": good[:121] + "B", "not-DER": strings.Repeat("A", 122)} {
		t.Run(name, func(t *testing.T) {
			if _, err := public(value); err == nil {
				t.Fatal("bad key accepted")
			}
		})
	}
	for _, raw := range []string{`{"swarma":{},"swarma":{}}`, `{"swarma":{},"swarm\u0061":{}}`, `{"swarma":{"keyvault_owner_spki":"x","keyvault_owner_spki":"y"}}`, `{} {}`, strings.Repeat("[", 25) + strings.Repeat("]", 25)} {
		var r record
		if uniqueJSON([]byte(raw), 520, &r) == nil {
			t.Fatal("ambiguous/overdeep record accepted")
		}
	}
	// Exact canonical DER is round-tripped; both keys remain independently read.
	if b, err := public(good); err != nil || !bytes.Equal(b, f.ownerDER) {
		t.Fatal(err)
	}
}

func TestVerifyDoesNotTakeSPKIFlags(t *testing.T) {
	f := fresh(t)
	cmd := exec.Command(f.p.CLI, "grants", "verify", "--issuer-spki-der", "not-a-real-file", "--requester-spki-der", "not-a-real-file")
	cmd.Env = []string{"HOME=" + f.p.PrivateRoot, "PATH=/nonexistent"}
	var out, diag bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &diag
	err := cmd.Run()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 2 || out.Len() != 0 || !strings.Contains(diag.String(), "--config FILE") {
		t.Fatalf("actual verify interface: %v %q %q", err, out.String(), diag.String())
	}
}

func TestFullRecordBounds(t *testing.T) {
	for _, size := range []int{520, 521} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			f := fresh(t)
			f.ownerRecord["padding"] = ""
			f.ownerRecord["padding"] = strings.Repeat("x", size-len(marshal(t, f.ownerRecord)))
			f.refreshNames(t)
			if len(f.ownerName.Value) != size {
				t.Fatal("bound fixture")
			}
			f.verify(t, &Verifier{}, size == 520)
		})
	}
	for _, size := range []int{4096, 4097} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			f := fresh(t)
			raw := marshal(t, f.ownerName)
			f.n.data[callKey("name_show", f.p.OwnerName, nameOptions())] = append(raw, bytes.Repeat([]byte{' '}, size-len(raw))...)
			f.verify(t, &Verifier{}, size == 4096)
		})
	}
}

func TestExactPublicFieldNames(t *testing.T) {
	for _, key := range []string{"KEYVAULT_OWNER_SPKI", "keyvault_Owner_spki", "owner_spki"} {
		t.Run(key, func(t *testing.T) {
			f := fresh(t)
			m := f.ownerRecord["swarma"].(map[string]any)
			m[key] = m["keyvault_owner_spki"]
			delete(m, "keyvault_owner_spki")
			f.refreshNames(t)
			f.verify(t, &Verifier{}, false)
		})
	}
}

func TestCertificateSignatureAndTimeBoundaries(t *testing.T) {
	t.Run("hash-anchored-but-wrong-signer", func(t *testing.T) {
		f := fresh(t)
		var env map[string]string
		if err := json.Unmarshal(f.certificate, &env); err != nil {
			t.Fatal(err)
		}
		payload, err := base64.RawURLEncoding.DecodeString(env["payload"])
		if err != nil {
			t.Fatal(err)
		}
		other, _ := keypair(t)
		f.certificate = signed(t, other, "swarma-grants/local-certificate/1", "grants-signed-local-certificate-1", payload)
		f.ownerRecord["swarma"].(map[string]any)["keyvault_certificate_sha256"] = hash(f.certificate)
		f.refreshNames(t)
		f.verify(t, &Verifier{}, false)
	})
	t.Run("before-certificate-lower-bound", func(t *testing.T) { f := fresh(t); f.at = f.at.Add(-2 * time.Minute); f.verify(t, &Verifier{}, false) })
	t.Run("request-expiry-exclusive", func(t *testing.T) {
		f := fresh(t)
		f.at = f.at.Add(30*time.Minute - time.Second)
		f.verify(t, &Verifier{}, true)
		f.at = f.at.Add(time.Second)
		f.verify(t, &Verifier{}, false)
	})
}
