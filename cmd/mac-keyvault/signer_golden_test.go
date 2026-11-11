package main

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"math/big"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/signertest"
)

var updateStartupGolden = flag.Bool("update", false, "rewrite the signer-v1 startup golden responses from the current CLI output")

// goldenCorpusDir is the shared corpus, reached from this package's
// directory.
var goldenCorpusDir = filepath.Join("..", "..", "internal", "keyvault", signertest.Dir)

// startupSetups are the environments a startup fixture may name in its
// setup field; every fixture runs against a store that holds test/guard
// so a refusal is proven to happen before the store is consulted.
var startupSetups = map[string]func(t *testing.T){
	"lock-path-unavailable": func(t *testing.T) {
		previous := vaultLock
		vaultLock = func() (keyvault.FileLock, error) {
			return keyvault.FileLock{}, errors.New("no writable state directory: HOME is unset")
		}
		t.Cleanup(func() { vaultLock = previous })
	},
}

// The startup hello of `signer serve` is pinned byte for byte through the
// production entry point run(): for every startup fixture of the shared
// corpus (usage ×5, foreign_label ×2, invalid_service, invalid_purpose
// ×2, invalid_kind, failure) the recorded args produce exactly one stdout
// line equal to the fixture's response, the recorded exit code, an empty
// stderr and zero store calls — the store holding test/guard is never
// consulted by a refused start. Run with -update to regenerate; review
// the diff, never the run.
func TestRunSignerServeStartupGolden(t *testing.T) {
	fixtures, err := signertest.Load(goldenCorpusDir)
	if err != nil {
		t.Fatal(err)
	}
	list := fixtures[signertest.StartupSession]
	if len(list) == 0 {
		t.Fatal("the corpus has no startup fixtures")
	}
	for _, f := range list {
		t.Run(filepath.Base(f.Path), func(t *testing.T) {
			store := newMemStore(tl("guard", 1))
			useStore(t, store)
			if f.Setup != "" {
				setup, ok := startupSetups[f.Setup]
				if !ok {
					t.Fatalf("%s: unknown setup %q", f.Path, f.Setup)
				}
				setup(t)
			}
			previous := stdinReader
			stdinReader = strings.NewReader(`{"id":1,"op":"describe"}` + "\n")
			t.Cleanup(func() { stdinReader = previous })
			var stdout, stderr bytes.Buffer
			code := run(f.Args, &stdout, &stderr)
			if strings.Count(stdout.String(), "\n") != 1 || stderr.Len() != 0 {
				t.Fatalf("stdout must be exactly one hello line with an empty stderr; stdout %q stderr %q", stdout.String(), stderr.String())
			}
			line := strings.TrimSuffix(stdout.String(), "\n")
			if *updateStartupGolden {
				if err := signertest.Save(f, line); err != nil {
					t.Fatal(err)
				}
				return
			}
			if f.Response == nil {
				t.Fatalf("%s: no response recorded; run with -update", f.Path)
			}
			if line != *f.Response {
				t.Errorf("%s (%s):\n got: %s\nwant: %s", f.Path, f.Note, line, *f.Response)
			}
			if code != *f.Exit {
				t.Errorf("%s: exit %d, want %d", f.Path, code, *f.Exit)
			}
			if store.touched() {
				t.Errorf("%s: a refused start reached the store: lists=%d signs=%d", f.Path, store.lists, len(store.signs))
			}
		})
	}
}

// streamCodeDrivers produces, through the production entry point
// run(signer serve ...), every error code a contract-1 stream can carry:
// the store shape (record, public half, backend answers) and the stdin
// lines that provoke it. The table is keyed by code so it can be compared
// with the registry in both directions.
func streamCodeDrivers(t *testing.T) map[string]func(t *testing.T) (args []string, stdin string) {
	t.Helper()
	label := tl("codes", 1)
	digest := digestHex("stream codes")
	sign := func(extra string) string { return `{"id":1,"op":"sign","digest":"` + digest + `"` + extra + `}` + "\n" }
	verify := func(sig string) string {
		return `{"id":1,"op":"verify","digest":"` + digest + `","signature":"` + sig + `"}` + "\n"
	}
	serve := []string{"--address", "test/codes"}
	// withRecord installs test/codes with the record adjusted and returns
	// the store for further shaping.
	withRecord := func(t *testing.T, adjust func(rec *keyvault.Record, item *keyvault.Item)) *memStore {
		store := newMemStore(label)
		item := store.keys[label]
		rec := store.record(t, label)
		adjust(&rec, &item)
		if bytes.Equal(item.Tag, store.keys[label].Tag) {
			// The record was adjusted, not the tag: re-encode it.
			tag, err := keyvault.EncodeRecord(rec)
			if err != nil {
				t.Fatal(err)
			}
			item.Tag = tag
		}
		store.keys[label] = item
		useStore(t, store)
		return store
	}
	plain := func(t *testing.T) *memStore {
		store := newMemStore(label)
		useStore(t, store)
		return store
	}
	// signedBy signs digest with the store's key through run(sign) and
	// returns the DER hex, so verify drivers have a genuine signature.
	signedBy := func(t *testing.T) string {
		code, resp, raw := runJSON(t, "sign", "test/codes", "--digest", digest)
		if code != exitOK {
			t.Fatalf("sign: %s", raw)
		}
		result := resp.Result.(map[string]any)
		return result["signature"].(string)
	}
	return map[string]func(t *testing.T) ([]string, string){
		signerclient.CodeUsage:          func(t *testing.T) ([]string, string) { plain(t); return nil, "" },
		signerclient.CodeForeignLabel:   func(t *testing.T) ([]string, string) { plain(t); return []string{"--address", label}, "" },
		signerclient.CodeInvalidService: func(t *testing.T) ([]string, string) { plain(t); return []string{"--address", "Test/codes"}, "" },
		signerclient.CodeInvalidPurpose: func(t *testing.T) ([]string, string) { plain(t); return []string{"--address", "test/Codes"}, "" },
		signerclient.CodeInvalidKind:    func(t *testing.T) ([]string, string) { plain(t); return append(serve, "--kind", "bogus"), "" },
		signerclient.CodeFailure: func(t *testing.T) ([]string, string) {
			plain(t)
			startupSetups["lock-path-unavailable"](t)
			return serve, ""
		},
		signerclient.CodeNotFound: func(t *testing.T) ([]string, string) { plain(t); return []string{"--address", "test/absent"}, "" },
		signerclient.CodeSecurity: func(t *testing.T) ([]string, string) {
			plain(t).signE = &keyvault.StatusError{Op: "SecKeyCreateSignature", Status: -25293}
			return serve, sign("")
		},
		signerclient.CodeMissingEntitlement: func(t *testing.T) ([]string, string) {
			plain(t).signE = &keyvault.StatusError{Op: "SecKeyCreateSignature", Status: -34018}
			return serve, sign("")
		},
		signerclient.CodeMetadataUnknown: func(t *testing.T) ([]string, string) {
			withRecord(t, func(_ *keyvault.Record, item *keyvault.Item) { item.Tag = []byte("not a record") })
			return serve, sign("")
		},
		signerclient.CodeUnsupportedPrimitive: func(t *testing.T) ([]string, string) {
			// The memory store serves the keychain only, so an enclave
			// record is a primitive this backend does not serve.
			withRecord(t, func(rec *keyvault.Record, _ *keyvault.Item) { rec.Store = keyvault.StoreEnclave })
			return serve, sign("")
		},
		signerclient.CodeUsageRefused: func(t *testing.T) ([]string, string) {
			withRecord(t, func(rec *keyvault.Record, _ *keyvault.Item) { rec.Usages = []string{"verify"} })
			return serve, sign("")
		},
		signerclient.CodeExpired: func(t *testing.T) ([]string, string) {
			withRecord(t, func(rec *keyvault.Record, _ *keyvault.Item) {
				notAfter := keyvault.NewTime(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
				rec.Validity.NotAfter = &notAfter
			})
			return serve, sign("")
		},
		signerclient.CodeInvalidDigest: func(t *testing.T) ([]string, string) {
			plain(t)
			return serve, `{"id":1,"op":"sign","digest":"abcd"}` + "\n"
		},
		signerclient.CodeInvalidSignature: func(t *testing.T) ([]string, string) { plain(t); return serve, verify("3000") },
		signerclient.CodeHighSRefused: func(t *testing.T) ([]string, string) {
			plain(t)
			sig, err := keyvault.ParseSignature(hexBytes(t, signedBy(t)), keyvault.FormatSignatureDERLowS)
			if err != nil {
				t.Fatal(err)
			}
			highS, err := keyvault.Signature{R: sig.R, S: new(big.Int).Sub(elliptic.P256().Params().N, sig.S)}.Encode(keyvault.FormatSignatureDERLowS)
			if err != nil {
				t.Fatal(err)
			}
			return serve, verify(hex.EncodeToString(highS))
		},
		signerclient.CodeSignatureInvalid: func(t *testing.T) ([]string, string) {
			plain(t)
			tampered := hexBytes(t, signedBy(t))
			tampered[len(tampered)-1] ^= 0x01
			return serve, verify(hex.EncodeToString(tampered))
		},
		signerclient.CodeInvalidPublicKey: func(t *testing.T) ([]string, string) {
			withRecord(t, func(_ *keyvault.Record, item *keyvault.Item) { item.SPKI = []byte("not an spki") })
			return serve, verify("3006020101020101")
		},
		signerclient.CodeBadRequest: func(t *testing.T) ([]string, string) {
			plain(t)
			return serve, `{"id":1,"op":"describe","allow_high_s":false}` + "\n"
		},
		signerclient.CodeMissingID: func(t *testing.T) ([]string, string) { plain(t); return serve, `{"op":"describe"}` + "\n" },
		signerclient.CodeUnknownOp: func(t *testing.T) ([]string, string) { plain(t); return serve, `{"id":1,"op":"rotate"}` + "\n" },
	}
}

// The declared stream error set is derived from production, not from a
// list compared with itself (review rev2 F1, repeat of rev1 F2): for
// every code the registry declares for the stream, a driver provokes it
// through run(signer serve ...) — the startup hello or a response — and
// the code production emits must (1) equal the driver's key, (2) be
// declared for the stream by signerclient.ErrorContract and (3) carry at
// least one byte-exact golden fixture in the shared corpus; and the set of
// driver keys must equal the declared set in both directions, so a code
// declared without a production path, or produced without a declaration,
// fails here. The ratio is logged as n of m.
func TestSignerStreamCodesEmittedByProduction(t *testing.T) {
	drivers := streamCodeDrivers(t)
	declared := signerclient.StreamErrorCodes()
	fixtures, err := signertest.Load(goldenCorpusDir)
	if err != nil {
		t.Fatal(err)
	}
	startup, server, err := signertest.ErrorCodes(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for code := range drivers {
		keys = append(keys, code)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != strings.Join(declared, ",") {
		t.Fatalf("driver codes %v differ from the declared stream set %v", keys, declared)
	}
	emitted := 0
	for _, code := range keys {
		t.Run(code, func(t *testing.T) {
			args, stdin := drivers[code](t)
			previous := stdinReader
			stdinReader = strings.NewReader(stdin)
			t.Cleanup(func() { stdinReader = previous })
			var stdout, stderr bytes.Buffer
			run(append([]string{"signer", "serve"}, args...), &stdout, &stderr)
			if stderr.Len() != 0 {
				t.Fatalf("stderr: %s", stderr.String())
			}
			lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
			var got string
			for _, line := range lines {
				var resp signerclient.Response
				if err := json.Unmarshal([]byte(line), &resp); err != nil {
					t.Fatalf("not a response: %v: %s", err, line)
				}
				if resp.Error != nil {
					got = resp.Error.Code
				}
			}
			if got != code {
				t.Fatalf("production emitted %q, driver expected %q:\n%s", got, code, stdout.String())
			}
			if !signerclient.IsStreamCode(got) {
				t.Fatalf("production emitted %q, which ErrorContract does not declare for the stream", got)
			}
			if len(startup[got])+len(server[got]) == 0 {
				t.Fatalf("production emitted %q, which has no byte-exact golden fixture in %s", got, goldenCorpusDir)
			}
			emitted++
		})
	}
	t.Logf("%d of %d declared stream codes emitted by production, declared and golden-covered", emitted, len(declared))
}
