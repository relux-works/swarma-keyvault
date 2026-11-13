//go:build darwin || linux

package namecoinprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinpsbt"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

func g1Read(t *testing.T, parts ...string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func g1Hash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func g1Write(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func g1Fixture(t *testing.T, release, slot string) (Args, time.Time, string, []byte) {
	t.Helper()
	account, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(account.HomeDir, ".namecoin-process-public-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	phase := "reservation"
	if slot == "C" || slot == "D" {
		phase = "reveal"
	}
	profile := g1Read(t, "..", "namecoinpsbt", "testdata", "native-selection", release+"-"+phase+".json")
	config, err := namecoinpsbt.DecodeNativeSelection(profile)
	if err != nil {
		t.Fatal(err)
	}
	raw := g1Read(t, "..", "namecoinwire", "testdata", release, slot+"-request.json")
	a, err := ParseArgs(argvFixture(SignPSBT))
	if err != nil {
		t.Fatal(err)
	}
	a.ProfilePath = filepath.Join(dir, "profile.json")
	a.ProfileSHA256 = g1Hash(profile)
	a.AccountPinPath = filepath.Join(dir, "account-pin.json")
	a.RequestPath = filepath.Join(dir, "request.json")
	a.RequestSHA256 = g1Hash(raw)
	a.OutputPath = filepath.Join(dir, "new-result.json")
	g1Write(t, a.ProfilePath, profile)
	g1Write(t, a.AccountPinPath, g1Read(t, "..", "namecoinpsbt", "testdata", release, "account-pin.json"))
	g1Write(t, a.RequestPath, raw)
	if phase == "reveal" {
		a.RevealPinPath = filepath.Join(dir, "reveal.json")
		g1Write(t, a.RevealPinPath, config.Selection.RevealValuesPin)
	}
	return a, time.Unix(int64(config.Selection.Policy.CreatedAt)+1, 0), dir, raw
}

func g1Tree(t *testing.T, dir string) map[string]string {
	t.Helper()
	m := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		value := info.Mode().String()
		if info.Mode().IsRegular() {
			value += g1Hash(g1Read(t, path))
		}
		m[path] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func g1Code(t *testing.T, err error, code namecoinwire.Code) {
	t.Helper()
	f, ok := err.(namecoinwire.Failure)
	if !ok || f.Code() != code {
		t.Fatalf("want %s, got %v", code, err)
	}
	if code == namecoinwire.OutcomeUnknown && (f.Status() != "UNKNOWN" || f.Exit() != 1) {
		t.Fatal("historical uncertainty downgraded")
	}
}
func g1Empty(t *testing.T, p Prepared) {
	t.Helper()
	if p.Mode() != "" || len(p.InputBytes()) != 0 || len(p.ProfileBytes()) != 0 || len(p.PinBytes()) != 0 || len(p.Attempt().Descriptor()) != 0 {
		t.Fatal("partial candidate after refusal")
	}
}

// All eight unchanged public fixture requests produce the full frozen review
// frame and owned inputs. No output, journal or helper capability is supplied.
func TestFrozenSigningFiles(t *testing.T) {
	for _, release := range []string{"two-stage", "all-four-before-release"} {
		for _, slot := range []string{"A", "B", "C", "D"} {
			t.Run(release+"/"+slot, func(t *testing.T) {
				a, now, dir, raw := g1Fixture(t, release, slot)
				before := g1Tree(t, dir)
				p, err := PrepareSigningFiles(a, now)
				if err != nil {
					t.Fatal(err)
				}
				frameHex := bytes.TrimSpace(g1Read(t, "..", "namecoinwire", "testdata", release, slot+"-review-frame.hex"))
				frame, err := hex.DecodeString(string(frameHex))
				if err != nil {
					t.Fatal(err)
				}
				if p.Mode() != SignPSBT || !bytes.Equal(p.InputBytes(), raw) || !bytes.Equal(p.Attempt().ReviewFrame(), frame) || g1Hash(p.ProfileBytes()) != a.ProfileSHA256 {
					t.Fatal("changed frozen context")
				}
				if !reflect.DeepEqual(before, g1Tree(t, dir)) {
					t.Fatal("preparation wrote files")
				}
				profile, pin, input := p.ProfileBytes(), p.PinBytes(), p.InputBytes()
				profile[0] ^= 1
				pin[0] ^= 1
				input[0] ^= 1
				selection := p.NativeSelection()
				if len(selection.Selection.RevealValuesPin) > 0 {
					selection.Selection.RevealValuesPin[0] ^= 1
				}
				g1Write(t, a.ProfilePath, []byte("changed"))
				g1Write(t, a.AccountPinPath, []byte("changed"))
				g1Write(t, a.RequestPath, []byte("changed"))
				if !bytes.Equal(p.InputBytes(), raw) || !bytes.Equal(p.Attempt().ReviewFrame(), frame) || g1Hash(p.ProfileBytes()) != a.ProfileSHA256 || bytes.Equal(p.PinBytes(), pin) || reflect.DeepEqual(p.NativeSelection(), selection) && len(selection.Selection.RevealValuesPin) > 0 {
					t.Fatal("borrowed or reread frozen input")
				}
			})
		}
	}
}

// Role-specific admission and semantic failures return no partial candidate,
// preserve all fixture/output bytes, and keep independent hashes separate.
func TestSigningPreflightRefusals(t *testing.T) {
	tests := []struct {
		name, slot string
		code       namecoinwire.Code
		change     func(*testing.T, *Args)
	}{
		{"request-digest", "A", namecoinwire.InvalidRequest, func(t *testing.T, a *Args) { a.RequestSHA256 = strings.Repeat("0", 64) }},
		{"profile-hash-is-not-request-hash", "A", namecoinwire.InvalidRequest, func(t *testing.T, a *Args) { a.RequestSHA256 = a.ProfileSHA256 }},
		{"request-hash-is-not-profile-hash", "A", namecoinwire.PolicyRefused, func(t *testing.T, a *Args) { a.ProfileSHA256 = a.RequestSHA256 }},
		{"profile-digest", "A", namecoinwire.PolicyRefused, func(t *testing.T, a *Args) { a.ProfileSHA256 = strings.Repeat("0", 64) }},
		{"wrong-native-selection", "A", namecoinwire.PolicyRefused, func(t *testing.T, a *Args) {
			c, _ := namecoinpsbt.DecodeNativeSelection(g1Read(t, a.ProfilePath))
			c.Selection.Network = "namecoin-mainnet"
			b, _ := json.Marshal(c)
			g1Write(t, a.ProfilePath, b)
			a.ProfileSHA256 = g1Hash(b)
		}},
		{"wrong-pin", "A", namecoinwire.AccountMismatch, func(t *testing.T, a *Args) { g1Write(t, a.AccountPinPath, []byte("{}")) }},
		{"wrong-group", "A", namecoinwire.AccountMismatch, func(t *testing.T, a *Args) { a.Group = "other/recovery@1" }},
		{"profile-mode", "A", namecoinwire.PolicyRefused, func(t *testing.T, a *Args) {
			if err := os.Chmod(a.ProfilePath, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"pin-mode", "A", namecoinwire.AccountMismatch, func(t *testing.T, a *Args) {
			if err := os.Chmod(a.AccountPinPath, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"request-mode", "A", namecoinwire.InvalidRequest, func(t *testing.T, a *Args) {
			if err := os.Chmod(a.RequestPath, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"A-reveal-option", "A", namecoinwire.IntentMismatch, func(t *testing.T, a *Args) {
			a.RevealPinPath = filepath.Join(filepath.Dir(a.RequestPath), "absent-reveal")
		}},
		{"B-reveal-option", "B", namecoinwire.IntentMismatch, func(t *testing.T, a *Args) {
			a.RevealPinPath = filepath.Join(filepath.Dir(a.RequestPath), "absent-reveal")
		}},
		{"C-missing-reveal", "C", namecoinwire.IntentMismatch, func(t *testing.T, a *Args) { a.RevealPinPath = "" }},
		{"D-reveal-mismatch", "D", namecoinwire.IntentMismatch, func(t *testing.T, a *Args) {
			b := g1Read(t, a.RevealPinPath)
			b[0] ^= 1
			g1Write(t, a.RevealPinPath, b)
		}},
		{"reveal-mode", "C", namecoinwire.IntentMismatch, func(t *testing.T, a *Args) {
			if err := os.Chmod(a.RevealPinPath, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"invalid-args-first", "A", namecoinwire.InvalidRequest, func(t *testing.T, a *Args) {
			a.Timeout = 0
			a.ProfilePath = filepath.Join(filepath.Dir(a.RequestPath), "absent-profile")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, now, dir, _ := g1Fixture(t, "two-stage", tt.slot)
			tt.change(t, &a)
			g1Write(t, a.OutputPath, []byte("existing result is untouched"))
			before := g1Tree(t, dir)
			p, err := PrepareSigningFiles(a, now)
			g1Code(t, err, tt.code)
			g1Empty(t, p)
			if !reflect.DeepEqual(before, g1Tree(t, dir)) {
				t.Fatal("forbidden file mutation")
			}
		})
	}
}

// Library-valid raw requests at 2 MiB-1 and 2 MiB proceed to the caller's next
// stage; 2 MiB+1 refuses before that stage. Whitespace is transport-size data,
// not a maximum canonical producer/result witness (the separate F4 work).
func TestRawRequestInclusiveCapBeforeNextStage(t *testing.T) {
	a, now, dir, original := g1Fixture(t, "two-stage", "A")
	starts := 0
	for _, n := range []int{2097151, 2097152, 2097153} {
		raw := append(bytes.Clone(original), bytes.Repeat([]byte{' '}, n-len(original))...)
		if _, err := namecoinwire.Decode(raw); err != nil {
			t.Fatal("control must remain library-valid", err)
		}
		g1Write(t, a.RequestPath, raw)
		a.RequestSHA256 = g1Hash(raw)
		before := g1Tree(t, dir)
		p, err := PrepareSigningFiles(a, now)
		if n <= 2097152 {
			if err != nil || !bytes.Equal(p.InputBytes(), raw) {
				t.Fatal(n, err)
			}
			starts++
		} else {
			g1Code(t, err, namecoinwire.InvalidRequest)
			g1Empty(t, p)
			if starts != 2 {
				t.Fatal("negative control changed next-stage count")
			}
		}
		if !reflect.DeepEqual(before, g1Tree(t, dir)) {
			t.Fatal("size check mutated files")
		}
	}
	if starts != 2 {
		t.Fatal(starts)
	}
}

// Decoded-size neighbors reach only the early transport predicate, not semantic
// PSBT admission. The oversized control must fail invalid_request before the
// existing packet parser; no maximum-shape or native execution claim is made.
func TestDecodedPSBTLimitPredicateAndPreflight(t *testing.T) {
	a, now, _, original := g1Fixture(t, "two-stage", "A")
	var r namecoinwire.Request
	if err := json.Unmarshal(original, &r); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{1048575, 1048576, 1048577} {
		r.PSBT = base64.StdEncoding.EncodeToString(make([]byte, n))
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > MaxProcessRequestBytes {
			t.Fatal("other size predicate masked PSBT control")
		}
		err = CheckRequestLimits(raw)
		if n <= 1048576 {
			if err != nil {
				t.Fatal(n, err)
			}
		} else {
			g1Code(t, err, namecoinwire.InvalidRequest)
			g1Write(t, a.RequestPath, raw)
			a.RequestSHA256 = g1Hash(raw)
			p, err := PrepareSigningFiles(a, now)
			g1Code(t, err, namecoinwire.InvalidRequest)
			g1Empty(t, p)
		}
	}
	for _, raw := range [][]byte{nil, []byte("not-json"), bytes.Repeat([]byte{' '}, MaxProcessRequestBytes+1)} {
		g1Code(t, CheckRequestLimits(raw), namecoinwire.InvalidRequest)
	}
}

func g1ReconcileArgs(t *testing.T, a Args, release, slot string) Args {
	t.Helper()
	a.Mode = Reconcile
	a.RequestPath = ""
	a.RequestSHA256 = ""
	a.RevealPinPath = ""
	a.QueryPath = filepath.Join(filepath.Dir(a.ProfilePath), "query.json")
	g1Write(t, a.QueryPath, g1Read(t, "..", "namecoinwire", "testdata", release, slot+"-reconcile-query.json"))
	return a
}

// All eight descriptors reconstruct after expiry without a fresh signing clock;
// supplied canonical bytes still grant no authentic journal membership.
func TestHistoricalReconcilePreparation(t *testing.T) {
	for _, release := range []string{"two-stage", "all-four-before-release"} {
		for _, slot := range []string{"A", "B", "C", "D"} {
			t.Run(release+"/"+slot, func(t *testing.T) {
				a, now, dir, _ := g1Fixture(t, release, slot)
				sign, err := PrepareSigningFiles(a, now)
				if err != nil {
					t.Fatal(err)
				}
				fresh, err := PrepareSigningFiles(a, now.Add(48*time.Hour))
				g1Code(t, err, namecoinwire.RequestExpired)
				g1Empty(t, fresh)
				rargs := g1ReconcileArgs(t, a, release, slot)
				before := g1Tree(t, dir)
				r, err := PrepareReconcileFiles(rargs)
				if err != nil {
					t.Fatal(err)
				}
				descriptor := sign.Attempt().Descriptor()
				p, err := r.WithDescriptor(descriptor)
				if err != nil {
					t.Fatal(err)
				}
				if p.Mode() != Reconcile || !bytes.Equal(p.InputBytes(), descriptor) || p.Attempt().Commitment() != sign.Attempt().Commitment() {
					t.Fatal("changed historical descriptor")
				}
				g1Code(t, p.Attempt().Candidate().Admit(p.Attempt().Selection(), now.Add(48*time.Hour)), namecoinwire.RequestExpired)
				descriptor[0] ^= 1
				q := r.Query()
				q.RequestID = strings.Repeat("0", 64)
				if !bytes.Equal(p.InputBytes(), sign.Attempt().Descriptor()) || r.Query().RequestID == q.RequestID || !reflect.DeepEqual(before, g1Tree(t, dir)) {
					t.Fatal("mutable query/descriptor or forbidden writes")
				}
			})
		}
	}
}

// Missing/corrupt history stays UNKNOWN; explicit valid query-ID substitutions
// reach intent_mismatch. File and selected-profile failures retain their roles.
func TestHistoricalReconcileRefusals(t *testing.T) {
	a, now, dir, _ := g1Fixture(t, "two-stage", "A")
	sign, err := PrepareSigningFiles(a, now)
	if err != nil {
		t.Fatal(err)
	}
	a = g1ReconcileArgs(t, a, "two-stage", "A")
	r, err := PrepareReconcileFiles(a)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := sign.Attempt().Descriptor()
	bad := bytes.Clone(descriptor)
	bad[0] ^= 1
	before := g1Tree(t, dir)
	for _, raw := range [][]byte{nil, bad, descriptor[:len(descriptor)-1], append(bytes.Clone(descriptor), 0)} {
		p, err := r.WithDescriptor(raw)
		g1Code(t, err, namecoinwire.OutcomeUnknown)
		g1Empty(t, p)
	}
	for _, field := range []string{"request", "plan", "slot"} {
		q := r.Query()
		switch field {
		case "request":
			q.RequestID = strings.Repeat("0", 64)
		case "plan":
			q.PlanSHA256 = strings.Repeat("0", 64)
		case "slot":
			q.Slot = "B"
		}
		raw, _ := json.Marshal(q)
		g1Write(t, a.QueryPath, raw)
		changed, err := PrepareReconcileFiles(a)
		if err != nil {
			t.Fatal(err)
		}
		p, err := changed.WithDescriptor(descriptor)
		g1Code(t, err, namecoinwire.IntentMismatch)
		g1Empty(t, p)
	}
	// Restore only this test's query before comparing non-writing descriptor checks.
	g1ReconcileArgs(t, a, "two-stage", "A")
	if !reflect.DeepEqual(before, g1Tree(t, dir)) {
		t.Fatal("historical preparation mutated files")
	}
	for _, raw := range [][]byte{[]byte("{}"), []byte(`{"schema":"keyvault-namecoin-reconcile/2","request_id":"x"}`)} {
		g1Write(t, a.QueryPath, raw)
		_, err := PrepareReconcileFiles(a)
		g1Code(t, err, namecoinwire.InvalidRequest)
	}
	g1ReconcileArgs(t, a, "two-stage", "A")
	if err := os.Chmod(a.QueryPath, 0644); err != nil {
		t.Fatal(err)
	}
	_, err = PrepareReconcileFiles(a)
	g1Code(t, err, namecoinwire.InvalidRequest)
	if err := os.Chmod(a.QueryPath, 0600); err != nil {
		t.Fatal(err)
	}
	c, _ := namecoinpsbt.DecodeNativeSelection(g1Read(t, a.ProfilePath))
	c.Selection.Policy.Revision = "different-policy"
	c.Sidecar.Binding.Policy = "different-policy"
	raw, _ := json.Marshal(c)
	g1Write(t, a.ProfilePath, raw)
	a.ProfileSHA256 = g1Hash(raw)
	changed, err := PrepareReconcileFiles(a)
	if err != nil {
		t.Fatal(err)
	}
	p, err := changed.WithDescriptor(descriptor)
	g1Code(t, err, namecoinwire.PolicyRefused)
	g1Empty(t, p)
}

// Initialization prepares only public profile/pin bytes and the supplied digest;
// no output, transaction ACK, state absence or consent is established.
func TestInitializationPublicPreparationOnly(t *testing.T) {
	a, _, dir, _ := g1Fixture(t, "two-stage", "A")
	a.Mode = InitializeJournal
	a.RequestPath = ""
	a.RequestSHA256 = ""
	a.OutputPath = ""
	a.AdoptionPlanSHA256 = strings.Repeat("a", 64)
	before := g1Tree(t, dir)
	p, err := PrepareInitializationFiles(a)
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode() != InitializeJournal || len(p.InputBytes()) != 0 || len(p.Attempt().Descriptor()) != 0 || p.AdoptionPlanSHA256() != a.AdoptionPlanSHA256 || !reflect.DeepEqual(before, g1Tree(t, dir)) {
		t.Fatal("initialization implied a private operation")
	}
	for _, mode := range []Mode{SignPSBT, Reconcile, Mode("unsupported")} {
		changed := a
		changed.Mode = mode
		p, err := PrepareInitializationFiles(changed)
		g1Code(t, err, namecoinwire.InvalidRequest)
		g1Empty(t, p)
	}
}

// Strict base64 errors reach unsupported_psbt even near the decoded ceiling;
// encoded length alone must not relabel them as decoded oversize. These public
// envelopes are transport controls, not valid maximum transaction shapes.
func TestStrictDecodedSizeBeforeSemantics(t *testing.T) {
	a, now, dir, original := g1Fixture(t, "two-stage", "A")
	if _, err := PrepareSigningFiles(a, now); err != nil {
		t.Fatal("valid full preparation control", err)
	}
	var r namecoinwire.Request
	if err := json.Unmarshal(original, &r); err != nil {
		t.Fatal(err)
	}
	canonical := base64.StdEncoding.EncodeToString(make([]byte, MaxProcessPSBTBytes-1))
	if err := CheckRequestLimits([]byte(`{"psbt":"` + canonical + `"}`)); err != nil {
		t.Fatal("nearby canonical size control", err)
	}
	for _, psbt := range []string{
		canonical[:64] + "\n\n\n\n\n\n\n\n\n\n" + canonical[64:],
		strings.Repeat("!", base64.StdEncoding.EncodedLen(MaxProcessPSBTBytes+1)),
		"AB==", "AA=", "AA==\r\n", "!AAA",
	} {
		r.PSBT = psbt
		raw, err := json.Marshal(r)
		if err != nil || len(raw) > MaxProcessRequestBytes {
			t.Fatal("plant must reach base64 decoding within raw ceiling", err)
		}
		g1Write(t, a.RequestPath, raw)
		a.RequestSHA256 = g1Hash(raw)
		before := g1Tree(t, dir)
		p, err := PrepareSigningFiles(a, now)
		g1Code(t, err, namecoinwire.UnsupportedPSBT)
		g1Empty(t, p)
		if !reflect.DeepEqual(before, g1Tree(t, dir)) {
			t.Fatal("base64 refusal mutated input or created output")
		}
	}
}

// Raw and strictly decoded oversize win over later expiry, intent and policy
// failures. Earlier profile/pin admission still wins. Each semantic mutation
// first reaches its own exact code with the ordinary valid-sized request.
func TestSizeRefusalPrecedence(t *testing.T) {
	for _, semantic := range []struct {
		name   string
		code   namecoinwire.Code
		change func(*namecoinwire.Request, *time.Time)
	}{
		{"expiry", namecoinwire.RequestExpired, func(_ *namecoinwire.Request, now *time.Time) { *now = now.Add(48 * time.Hour) }},
		{"intent", namecoinwire.IntentMismatch, func(r *namecoinwire.Request, _ *time.Time) { r.PlanSHA256 = strings.Repeat("0", 64) }},
		{"policy", namecoinwire.PolicyRefused, func(r *namecoinwire.Request, _ *time.Time) {
			// Keep the manifest commitment valid while changing the request's
			// selected release policy. The independent profile stays fixed.
			var plan map[string]json.RawMessage
			if err := json.Unmarshal([]byte(r.ManifestUTF8), &plan); err != nil {
				panic(err)
			}
			var policy map[string]json.RawMessage
			if err := json.Unmarshal(plan["policy"], &policy); err != nil {
				panic(err)
			}
			policy["revision"] = json.RawMessage(`"different-policy"`)
			plan["policy"], _ = json.Marshal(policy)
			manifest, _ := json.Marshal(plan)
			r.ManifestUTF8 = string(manifest)
			r.PlanSHA256 = namecoinwire.PlanDigest(manifest)
			r.ReservationPlanSHA256 = r.PlanSHA256
		}},
	} {
		t.Run(semantic.name, func(t *testing.T) {
			a, now, dir, original := g1Fixture(t, "two-stage", "A")
			if _, err := PrepareSigningFiles(a, now); err != nil {
				t.Fatal("valid control", err)
			}
			var r namecoinwire.Request
			if err := json.Unmarshal(original, &r); err != nil {
				t.Fatal(err)
			}
			semantic.change(&r, &now)
			mutated, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			g1Write(t, a.RequestPath, mutated)
			a.RequestSHA256 = g1Hash(mutated)
			p, err := PrepareSigningFiles(a, now)
			g1Code(t, err, semantic.code)
			g1Empty(t, p)
			for _, size := range []string{"raw", "decoded"} {
				t.Run(size, func(t *testing.T) {
					raw := bytes.Clone(mutated)
					if size == "raw" {
						raw = append(raw, bytes.Repeat([]byte{' '}, MaxProcessRequestBytes+1-len(raw))...)
					} else {
						oversized := r
						oversized.PSBT = base64.StdEncoding.EncodeToString(make([]byte, MaxProcessPSBTBytes+1))
						raw, err = json.Marshal(oversized)
						if err != nil || len(raw) > MaxProcessRequestBytes {
							t.Fatal("decoded plant masked by raw cap", err)
						}
					}
					g1Write(t, a.RequestPath, raw)
					a.RequestSHA256 = g1Hash(raw)
					before := g1Tree(t, dir)
					p, err := PrepareSigningFiles(a, now)
					g1Code(t, err, namecoinwire.InvalidRequest)
					g1Empty(t, p)
					if !reflect.DeepEqual(before, g1Tree(t, dir)) {
						t.Fatal("size refusal mutated files")
					}
					badProfile := a
					badProfile.ProfileSHA256 = strings.Repeat("0", 64)
					_, err = PrepareSigningFiles(badProfile, now)
					g1Code(t, err, namecoinwire.PolicyRefused)
					badPin := a
					badPin.AccountPinPath = filepath.Join(dir, "missing-pin")
					_, err = PrepareSigningFiles(badPin, now)
					g1Code(t, err, namecoinwire.AccountMismatch)
				})
			}
		})
	}
}

// The size predicate does not replace closed-wire syntax admission. Malformed
// outer shape with malformed base64 keeps invalid_request, while the full
// valid-shaped malformed-base64 controls above reach unsupported_psbt.
func TestSizePredicatePreservesClosedSyntaxRefusal(t *testing.T) {
	a, now, dir, original := g1Fixture(t, "two-stage", "A")
	if _, err := PrepareSigningFiles(a, now); err != nil {
		t.Fatal("valid control", err)
	}
	for _, change := range []func(map[string]json.RawMessage){
		func(r map[string]json.RawMessage) { delete(r, "schema") },
		func(r map[string]json.RawMessage) { r["extra"] = json.RawMessage(`"unexpected"`) },
		func(r map[string]json.RawMessage) { r["schema"] = json.RawMessage(`"unsupported"`) },
	} {
		var r map[string]json.RawMessage
		if err := json.Unmarshal(original, &r); err != nil {
			t.Fatal(err)
		}
		change(r)
		r["psbt"] = json.RawMessage(`"AA="`)
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		g1Write(t, a.RequestPath, raw)
		a.RequestSHA256 = g1Hash(raw)
		before := g1Tree(t, dir)
		p, err := PrepareSigningFiles(a, now)
		g1Code(t, err, namecoinwire.InvalidRequest)
		g1Empty(t, p)
		if !reflect.DeepEqual(before, g1Tree(t, dir)) {
			t.Fatal("syntax refusal mutated files")
		}
	}
}
