package namecoinwrapper

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	watch "github.com/relux-works/swarma-keyvault/lab/sealwatch"
)

// Only newly generated test keys enter these files. The outer offline sandbox
// and t.TempDir cleanup remove them; no existing owner custody is available.
func signerRun(t *testing.T, root string, args ...string) []byte {
	t.Helper()
	signer := os.Getenv("LAB_TEST_SIGNER")
	if signer == "" {
		t.Fatal("LAB_TEST_SIGNER must name the separately built explicit-owner lab signer")
	}
	cmd := exec.Command(signer, args...)
	cmd.Env = []string{"HOME=" + root, "TMPDIR=" + root, "PATH=/nonexistent"}
	var errout bytes.Buffer
	cmd.Stderr = &errout
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("actual lab signer refused: %v %s", err, errout.String())
	}
	return out
}

type mirrorWatchRPC struct{ node *fakeNode }

func (r mirrorWatchRPC) Call(ctx context.Context, method string, args ...any) (io.ReadCloser, error) {
	raw, err := r.node.Call(ctx, method, args...)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(raw)), nil
}

// The same reverse certificate digest and exact seal feed the unchanged
// watcher. Public transaction inputs drive the states, not supplied verdicts.
func TestMirrorSealWatcherLifecycle(t *testing.T) {
	f := freshDirection(t, true)
	now := time.Now()
	b := watch.Binding{Seal: watch.Point{TxID: f.seal.TxID, Vout: uint32(f.seal.Vout)}, SealScript: "51", Anchor: watch.Anchor{Tip: watch.Tip{Height: 99, Hash: f.block}, TxID: f.p.AnchorTxID}, Commitment: hash(f.certificate), Genesis: RegtestGenesis, Chain: "regtest", StartTip: watch.Tip{Height: 100, Hash: f.best}, Deadline: now.Add(time.Minute), ProofValidUntil: f.at.Add(time.Hour), LastBlockAt: now.Add(-time.Minute)}
	l := watch.DefaultLimits()
	l.Polls = 1
	f.n.set(t, "getblockchaininfo", map[string]any{"chain": "regtest", "blocks": 100, "headers": 100, "bestblockhash": f.best, "initialblockdownload": false})
	f.n.set(t, "getblockhash", f.best, 100)
	f.n.set(t, "getrawtransaction", f.anchor, f.p.AnchorTxID, true, f.block)
	f.n.set(t, "getrawmempool", []string{}, false)
	for _, pool := range []bool{false, true} {
		f.n.set(t, "gettxout", map[string]any{"bestblock": f.best, "confirmations": 3, "scriptPubKey": map[string]string{"address": "LAB-OWNER", "hex": "51"}}, f.seal.TxID, f.seal.Vout, pool)
	}
	observe := func(want string) watch.Verdict {
		t.Helper()
		v := watch.New(mirrorWatchRPC{f.n}).Watch(context.Background(), b, l)
		if v.State != want || v.Commitment != hash(f.certificate) || v.Seal != b.Seal || v.PrivilegedCommandsAllowed {
			t.Fatalf("watch state: %+v want %s", v, want)
		}
		t.Logf("state=%s reason=%s digest=%s seal=%s:%d", v.State, v.Reason, v.Commitment, v.Seal.TxID, v.Seal.Vout)
		return v
	}
	f.verify(t, &Verifier{}, true)
	observe(watch.Unspent)
	original := map[string]json.RawMessage{}
	for k, raw := range f.n.data {
		original[k] = bytes.Clone(raw)
	}
	spendID := strings.Repeat("f", 64)
	spend := map[string]any{"txid": spendID, "vin": []any{map[string]any{"txid": f.seal.TxID, "vout": f.seal.Vout}}}
	f.n.set(t, "getrawmempool", []string{spendID}, false)
	f.n.set(t, "getrawtransaction", spend, spendID, true)
	f.n.set(t, "gettxout", nil, f.seal.TxID, f.seal.Vout, true)
	b.Prior = observe(watch.Suspend)
	f.verify(t, &Verifier{}, false)
	newer := strings.Repeat("1", 64)
	f.n.set(t, "getblockchaininfo", map[string]any{"chain": "regtest", "blocks": 101, "headers": 101, "bestblockhash": newer, "initialblockdownload": false})
	f.n.set(t, "getblockhash", newer, 101)
	f.n.set(t, "getblock", map[string]any{"hash": newer, "height": 101, "tx": []any{map[string]any{"txid": strings.Repeat("2", 64), "vin": []any{map[string]any{"coinbase": "00"}}}, spend}}, newer, 2)
	b.Prior = observe(watch.FinalRevoked)
	f.verify(t, &Verifier{}, false)
	f.n.data = original
	observe(watch.Unknown)
	f.operation["request_id"] = "fresh-after-final-spend"
	f.request = signerRequest(t, f, f.p.PrivateRoot)
	f.verify(t, &Verifier{}, false)
}

func writeSyntheticKey(t *testing.T, root, name string, key *ecdsa.PrivateKey) string {
	t.Helper()
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

func signerCertificate(t *testing.T, f *fixture, root string, payload []byte, owner string) []byte {
	t.Helper()
	path := filepath.Join(root, "prepared.json")
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(append([]byte("swarma-grants/local-certificate/1\n"), payload...))
	key := writeSyntheticKey(t, root, "owner.pk8", f.owner)
	args := []string{"certificate", "--payload", path, "--digest", hex.EncodeToString(digest[:]), "--key", key, "--owner-spki", filepath.Join(root, "owner.der"), "--requester-spki", filepath.Join(root, "requester.der")}
	// Same reverse bytes refuse under the original default before key access.
	cmd := exec.Command(os.Getenv("LAB_TEST_SIGNER"), args...)
	cmd.Env = []string{"HOME=" + root, "TMPDIR=" + root, "PATH=/nonexistent"}
	if out, err := cmd.Output(); err == nil || len(out) != 0 {
		t.Fatal("reverse signer inferred the payload owner")
	}
	return signerRun(t, root, append(args, "--owner-mxid", owner)...)
}

func signerRequest(t *testing.T, f *fixture, root string) []byte {
	t.Helper()
	path := filepath.Join(root, "operation.json")
	if err := os.WriteFile(path, marshal(t, f.operation), 0600); err != nil {
		t.Fatal(err)
	}
	digest := signerRun(t, root, "prepare-request", "--payload", path, "--requester-spki", filepath.Join(root, "requester.der"))
	key := writeSyntheticKey(t, root, "requester.pk8", f.requester)
	return signerRun(t, root, "request", "--payload", path, "--digest", string(digest), "--key", key, "--requester-spki", filepath.Join(root, "requester.der"))
}

func TestMirrorActualSignerVerifierPolicy(t *testing.T) {
	f := freshDirection(t, true)
	good := f.p
	f.verify(t, &Verifier{}, true)
	for _, owner := range []string{"", "@alexis:example.invalid", "@other:example.invalid", "invalid", "@ivan:bad host", "@ivan:example.invalid\n"} {
		f.p.ExpectedOwner = owner
		f.verify(t, &Verifier{}, false)
		f.p = good
		f.verify(t, &Verifier{}, true)
	}
	for _, field := range []string{"names", "owner-pin", "requester-pin", "digest", "seal", "subject", "audience", "expiry"} {
		t.Run(field, func(t *testing.T) {
			f := freshDirection(t, true)
			f.verify(t, &Verifier{}, true)
			switch field {
			case "names":
				f.p.OwnerName, f.p.RequesterName = f.p.RequesterName, f.p.OwnerName
			case "owner-pin":
				f.ownerRecord["swarma"].(map[string]any)["keyvault_owner_spki"] = base64.RawURLEncoding.EncodeToString(f.requesterDER)
				f.refreshNames(t)
			case "requester-pin":
				f.requesterRecord["swarma"].(map[string]any)["keyvault_requester_spki"] = base64.RawURLEncoding.EncodeToString(f.ownerDER)
				f.refreshNames(t)
			case "digest":
				f.ownerRecord["swarma"].(map[string]any)["keyvault_certificate_sha256"] = strings.Repeat("0", 64)
				f.refreshNames(t)
			case "seal":
				f.p.SealVout++
			case "subject":
				f.p.Account = "@wrong:example.invalid"
			case "audience":
				f.p.Executor = "wrong"
			case "expiry":
				f.at = f.at.Add(2 * time.Hour)
			}
			f.verify(t, &Verifier{}, false)
		})
	}
}

func TestMirrorLifecycleRefusesRestoration(t *testing.T) {
	for _, state := range []string{"mempool-spend", "confirmed-spend", "owner-generation"} {
		t.Run(state, func(t *testing.T) {
			f := freshDirection(t, true)
			v := &Verifier{}
			f.verify(t, v, true)
			original := map[string]json.RawMessage{}
			for k, raw := range f.n.data {
				original[k] = bytes.Clone(raw)
			}
			if state == "owner-generation" {
				f.ownerName.TxID = strings.Repeat("f", 64)
				f.ownerName.Height = 101
				f.refreshNames(t)
				newer := strings.Repeat("1", 64)
				f.anchor["blockhash"] = newer
				f.n.set(t, "getrawtransaction", f.anchor, f.ownerName.TxID, true)
				f.n.set(t, "getblockheader", map[string]any{"height": 101, "confirmations": 1}, newer)
				f.n.set(t, "getblockhash", newer, 101)
				f.n.set(t, "getblockchaininfo", tip{"regtest", newer, 101, false})
				f.n.set(t, "gettxout", map[string]any{"bestblock": newer, "confirmations": 4, "scriptPubKey": map[string]string{"address": "LAB-OWNER"}}, f.seal.TxID, 0, true)
			} else {
				f.n.set(t, "gettxout", nil, f.seal.TxID, f.seal.Vout, true)
				if state == "confirmed-spend" {
					f.n.set(t, "getblockchaininfo", tip{"regtest", strings.Repeat("f", 64), 101, false})
				}
			}
			f.verify(t, v, false)
			f.n.data = original
			f.operation["request_id"] = "fresh-after-restoration"
			f.request = signerRequest(t, f, f.p.PrivateRoot)
			f.verify(t, &Verifier{}, false)
		})
	}
}

// Exercise the existing labcompose JSON Policy parser and public read pipe as
// a real process. Replies come from the same inert synthetic transcript; there
// is no Core, node transport, live freshness or provider/admission claim.
func TestMirrorPublicPipe(t *testing.T) {
	for _, mode := range []string{"explicit", "omitted", "wrong", "swapped-names"} {
		t.Run(mode, func(t *testing.T) {
			f := freshDirection(t, true)
			want := mode == "explicit"
			switch mode {
			case "omitted":
				f.p.ExpectedOwner = ""
			case "wrong":
				f.p.ExpectedOwner = "@alexis:example.invalid"
			case "swapped-names":
				f.p.OwnerName, f.p.RequesterName = f.p.RequesterName, f.p.OwnerName
			}
			root := f.p.PrivateRoot
			certPath, reqPath := filepath.Join(root, "certificate.json"), filepath.Join(root, "request.json")
			for path, raw := range map[string][]byte{certPath: f.certificate, reqPath: f.request} {
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(root, "bridge.json")
			raw := marshal(t, map[string]any{"Mode": "verify", "Policy": f.p, "Certificate": certPath, "Request": reqPath, "At": f.at})
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			binary := os.Getenv("LAB_COMPOSE")
			if binary == "" {
				t.Fatal("LAB_COMPOSE must name the separately built candidate bridge")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, path)
			cmd.Env = []string{"HOME=" + root, "TMPDIR=" + root, "PATH=/nonexistent"}
			in, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
			scanner := bufio.NewScanner(out)
			complete := false
			for scanner.Scan() {
				var message struct {
					Done     bool   `json:"done"`
					Verified bool   `json:"verified"`
					RPC      string `json:"rpc"`
					Params   []any  `json:"params"`
				}
				if err := json.Unmarshal(scanner.Bytes(), &message); err != nil {
					t.Fatal(err)
				}
				if message.Done {
					complete = true
					if message.Verified != want {
						t.Fatalf("process verification=%v want %v", message.Verified, want)
					}
					break
				}
				if message.RPC == "" || len(f.n.calls) >= 256 {
					t.Fatal("invalid/unbounded public read pipe")
				}
				reply, err := f.n.Call(ctx, message.RPC, message.Params...)
				if err := json.NewEncoder(in).Encode(map[string]any{"result": reply, "failed": err != nil}); err != nil {
					t.Fatal(err)
				}
			}
			_ = in.Close()
			if err := scanner.Err(); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Wait(); err != nil {
				t.Fatal(err)
			}
			if !complete {
				t.Fatal("bridge did not return a bounded result")
			}
			t.Logf("mode=%s verified=%v public_reads=%d", mode, want, len(f.n.calls))
		})
	}
}
