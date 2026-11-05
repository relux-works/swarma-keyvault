package grants

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The child fixture validates the complete original invocation and the selected
// configuration root. It emits only local inert projection bytes, never Matrix.
func runA2AProjectionFixture(mode string) int {
	want := []string{"--profile", "fixture-connection", "--as", "alice", "read", "!fixture:test.local", "--event", "$fixture-event", "--verification-input", "--json"}
	if !reflect.DeepEqual(os.Args[1:], want) || os.Getenv("A2A_CONFIG_DIR") != os.Getenv("KEYVAULT_A2A_EXPECT_CONFIG") {
		return 92
	}
	f, err := os.OpenFile(os.Getenv("KEYVAULT_A2A_PROJECTION_CALLS"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return 93
	}
	_, err = f.WriteString("observe\n")
	if f.Close() != nil || err != nil {
		return 94
	}
	raw, err := os.ReadFile(os.Getenv("KEYVAULT_A2A_PROJECTION_BYTES"))
	if err != nil {
		return 95
	}
	switch mode {
	case "success":
		_, _ = os.Stdout.Write(raw)
	case "failure-after-output":
		_, _ = os.Stdout.Write(raw)
		_, _ = os.Stderr.WriteString("inert diagnostic must not escape")
		return 17
	case "partial":
		_, _ = os.Stdout.Write(raw[:len(raw)/2])
	case "stdout-limit":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte{'x'}, 98305))
	case "stderr-limit":
		_, _ = os.Stdout.Write(raw)
		_, _ = os.Stderr.Write(bytes.Repeat([]byte{'x'}, 8193))
	case "wait":
		time.Sleep(time.Minute)
	case "orphan-pipe":
		holdInheritedPipes()
	default:
		return 96
	}
	return 0
}

func a2aExecutorFixture(t *testing.T) (*a2aFixture, *A2AExecutor, map[string]any, string, string) {
	t.Helper()
	f, _, x, p := a2aDockingReceiver(t)
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hash := a2aHash(raw)
	c := map[string]any{"type": "grants-a2a-executor-config-1", "owner_mxid": "@owner:example.invalid", "owner_spki": base64.RawURLEncoding.EncodeToString(f.ownerDER), "owner_spki_sha256": a2aHash(f.ownerDER), "audience": x.Audience, "room_id": x.RoomID, "topic": x.Topic, "thread_root": x.ThreadRoot, "declared_from": x.DeclaredFrom, "declared_to": x.DeclaredTo,
		"key_registry": base64.RawURLEncoding.EncodeToString(requestTestBytes(t, f.keyRegistry)), "key_registry_sha256": a2aHash(requestTestBytes(t, f.keyRegistry)), "grant_registry": base64.RawURLEncoding.EncodeToString(requestTestBytes(t, f.grantsRegistry)), "grant_registry_sha256": a2aHash(requestTestBytes(t, f.grantsRegistry)), "state_dir": state, "state_epoch": strings.Repeat("ab", 32), "a2a_path": path, "a2a_sha256": hash, "a2a_identity": "alice", "a2a_connection": "fixture-connection", "a2a_config_dir": filepath.Join(dir, "own config root"), "gh_path": path, "gh_sha256": hash}
	e, err := ParseA2AExecutor(requestTestBytes(t, c))
	if err != nil {
		t.Fatal("valid executor configuration", err)
	}
	e.now = func() time.Time { return f.now }
	raw, err = os.ReadFile(filepath.Join("testdata", "a2a-post-explicit-re.json"))
	if err != nil {
		t.Fatal(err)
	}
	var w map[string]any
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	w["body"] = strings.SplitN(w["body"].(string), "\n\n", 2)[0] + "\n\n" + string(f.event(t).Body)
	projection := filepath.Join(dir, "projection.json")
	if err := os.WriteFile(projection, a2aObservedBytes(t, w, p), 0600); err != nil {
		t.Fatal(err)
	}
	calls, providerCalls := filepath.Join(dir, "projection-calls"), filepath.Join(dir, "provider-calls")
	t.Setenv("KEYVAULT_A2A_PROJECTION_FIXTURE", "success")
	t.Setenv("KEYVAULT_A2A_PROJECTION_CALLS", calls)
	t.Setenv("KEYVAULT_A2A_PROJECTION_BYTES", projection)
	t.Setenv("KEYVAULT_A2A_EXPECT_CONFIG", c["a2a_config_dir"].(string))
	t.Setenv("KEYVAULT_A2A_GH_FIXTURE", "success")
	t.Setenv("KEYVAULT_A2A_GH_CALLS", providerCalls)
	// Existing ambient selection cannot replace the explicit own config root.
	t.Setenv("A2A_CONFIG_DIR", filepath.Join(dir, "unselected"))
	return f, e, c, calls, providerCalls
}

func a2aNoFixtureCall(t *testing.T, name string) {
	t.Helper()
	if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unexpected process fixture call", name, err)
	}
}

// Read-only verification observes one event without initializing state or calling
// the provider. Explicit init is separate. Execution reobserves the selected
// event once and dispatches one typed process; replay cannot dispatch again.
func TestA2AExecutorProcessDocking(t *testing.T) {
	_, e, _, calls, providerCalls := a2aExecutorFixture(t)
	if _, err := e.Verify(context.Background(), "$fixture-event"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(e.state.Directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("verify initialized state", err)
	}
	a2aNoFixtureCall(t, providerCalls)
	if err := e.InitializeState(); err != nil {
		t.Fatal(err)
	}
	before := a2aJournalBytes(t, NewA2AMediator(e.receiver, e.state, e.ghPath))
	if err := e.InitializeState(); !errors.Is(err, ErrA2AState) {
		t.Fatal("init replaced existing state", err)
	}
	if !bytes.Equal(before, a2aJournalBytes(t, NewA2AMediator(e.receiver, e.state, e.ghPath))) {
		t.Fatal("reinit changed journal")
	}
	result, err := e.Execute(context.Background(), "$fixture-event")
	if err != nil || result == nil || result.State != "succeeded" {
		t.Fatal("valid process path", result, err)
	}
	if _, err := e.Execute(context.Background(), "$fixture-event"); !errors.Is(err, ErrA2AUseHeld) {
		t.Fatal("replay not held", err)
	}
	b, err := os.ReadFile(calls)
	if err != nil || string(b) != "observe\nobserve\nobserve\n" {
		t.Fatal("projection retry or missing invocation", err, string(b))
	}
	b, err = os.ReadFile(providerCalls)
	if err != nil || string(b) != "create\n" {
		t.Fatal("provider duplicated", err, string(b))
	}
}

// A completed but failed process, partial JSON, output overruns and interrupted
// observation never become authentication input or consume initialized state.
func TestA2AExecutorProjectionRefusals(t *testing.T) {
	for _, mode := range []string{"failure-after-output", "partial", "stdout-limit", "stderr-limit", "wait"} {
		t.Run(mode, func(t *testing.T) {
			_, e, _, calls, providerCalls := a2aExecutorFixture(t)
			if err := e.InitializeState(); err != nil {
				t.Fatal(err)
			}
			m := NewA2AMediator(e.receiver, e.state, e.ghPath)
			before := a2aJournalBytes(t, m)
			t.Setenv("KEYVAULT_A2A_PROJECTION_FIXTURE", mode)
			ctx := context.Background()
			if mode == "wait" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
			}
			want := ErrA2AProjection
			if mode == "partial" {
				want = ErrA2AContext
			}
			if result, err := e.Execute(ctx, "$fixture-event"); !errors.Is(err, want) || result != nil {
				t.Fatal("failed observation accepted/wrong refusal", result, err, "wanted", want)
			}
			a2aNoFixtureCall(t, providerCalls)
			if !bytes.Equal(before, a2aJournalBytes(t, m)) {
				t.Fatal("projection failure wrote state")
			}
			b, err := os.ReadFile(calls)
			if err != nil || string(b) != "observe\n" {
				t.Fatal("projection count", err, string(b))
			}
		})
	}
}

// A successful observation cannot implicitly create missing use state.
func TestA2AExecutorMissingState(t *testing.T) {
	_, e, _, _, providerCalls := a2aExecutorFixture(t)
	if result, err := e.Execute(context.Background(), "$fixture-event"); !errors.Is(err, ErrA2AState) || result != nil {
		t.Fatal("missing state accepted", result, err)
	}
	a2aNoFixtureCall(t, providerCalls)
	entries, err := os.ReadDir(e.state.Directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("execute initialized state", err)
	}
}

// An unsuccessful provider process is UNKNOWN and holds its one-use allowance;
// a new projection read on replay cannot start another provider process.
func TestA2AExecutorUnknownHeld(t *testing.T) {
	_, e, _, _, calls := a2aExecutorFixture(t)
	if err := e.InitializeState(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYVAULT_A2A_GH_FIXTURE", "process-failure")
	if out, err := e.Execute(context.Background(), "$fixture-event"); !errors.Is(err, ErrA2AUnknown) || out == nil || out.State != "unknown" {
		t.Fatal("unknown process outcome", out, err)
	}
	if _, err := e.Execute(context.Background(), "$fixture-event"); !errors.Is(err, ErrA2AUseHeld) {
		t.Fatal("unknown use released", err)
	}
	b, err := os.ReadFile(calls)
	if err != nil || string(b) != "create\n" {
		t.Fatal("unknown retried provider", err, string(b))
	}
}

// Provider pin drift refuses before projection or use-state access.
func TestA2AExecutorProviderPinDrift(t *testing.T) {
	_, e, _, calls, providerCalls := a2aExecutorFixture(t)
	e.ghHash = strings.Repeat("0", 64)
	if out, err := e.Execute(context.Background(), "$fixture-event"); !errors.Is(err, ErrA2AConfig) || out != nil {
		t.Fatal("provider pin drift accepted", out, err)
	}
	a2aNoFixtureCall(t, calls)
	a2aNoFixtureCall(t, providerCalls)
	entries, err := os.ReadDir(e.state.Directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("pin drift changed state", err)
	}
}

// These neighboring observations are syntactically complete and correctly
// framed but carry no valid authority. Each refuses for its own predicate (the
// framing check is asserted to pass first; for event/room the unmutated record
// parses). Every refusal preserves an initialized journal and provider count.
func TestA2AExecutorUntrustedEventRefusals(t *testing.T) {
	for _, mode := range []string{"sender", "event", "room", "signature", "scope"} {
		t.Run(mode, func(t *testing.T) {
			f, e, _, _, providerCalls := a2aExecutorFixture(t)
			if err := e.InitializeState(); err != nil {
				t.Fatal(err)
			}
			m := NewA2AMediator(e.receiver, e.state, e.ghPath)
			before := a2aJournalBytes(t, m)
			path := os.Getenv("KEYVAULT_A2A_PROJECTION_BYTES")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var p map[string]any
			if err := json.Unmarshal(raw, &p); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "sender":
				p["sender_mxid"] = "@bob:foreign.invalid"
			case "event":
				p["returned_event_id"] = "$another"
			case "room":
				p["returned_room_id"] = "!another:test.local"
			case "signature", "scope":
				content, _ := base64.RawURLEncoding.DecodeString(p["content_base64"].(string))
				var w map[string]any
				if err := json.Unmarshal(content, &w); err != nil {
					t.Fatal(err)
				}
				body := string(f.event(t).Body)
				if mode == "signature" {
					var v map[string]any
					json.Unmarshal([]byte(body), &v)
					v["signature"] = "AA"
					body = string(requestTestBytes(t, v))
				} else {
					f.request["resource"] = "github:relux-works/other"
					body = string(f.event(t).Body)
				}
				w["body"] = strings.SplitN(w["body"].(string), "\n\n", 2)[0] + "\n\n" + body
				p["content_base64"] = base64.RawURLEncoding.EncodeToString(requestTestBytes(t, w))
			}
			written := a2aFramed(requestTestBytes(t, p))
			if _, ok := a2aRecordFrame(written); !ok {
				t.Fatal("control refused by framing, not by its own predicate")
			}
			if err := os.WriteFile(path, written, 0600); err != nil {
				t.Fatal(err)
			}
			want := map[string]error{"sender": ErrA2ANoGrant, "event": ErrA2AContext, "room": ErrA2AContext, "signature": errSignatureInvalid, "scope": errResourceMismatch}[mode]
			if out, err := e.Execute(context.Background(), "$fixture-event"); !errors.Is(err, want) || out != nil {
				t.Fatal("untrusted event accepted or refused for another reason", out, err, "wanted", want)
			}
			if mode == "event" || mode == "room" {
				expected := e.observation
				expected.EventID = "$fixture-event"
				if _, err := ParseA2AObservation(raw, expected); err != nil {
					t.Fatal("unmutated neighbor refused", err)
				}
			}
			if !bytes.Equal(before, a2aJournalBytes(t, m)) {
				t.Fatal("refusal changed journal")
			}
			a2aNoFixtureCall(t, providerCalls)
		})
	}
}

// Closed config/pin failures have a valid neighbor. Parse alone never opens a
// file or launches processes; executable drift/link checks fail before launch.
func TestA2AExecutorConfigRefusals(t *testing.T) {
	_, e, c, calls, providerCalls := a2aExecutorFixture(t)
	for _, key := range []string{"owner_spki_sha256", "key_registry_sha256", "grant_registry_sha256", "state_epoch", "a2a_path", "a2a_identity", "declared_to", "thread_root", "extra", "type"} {
		t.Run(key, func(t *testing.T) {
			bad := map[string]any{}
			for k, v := range c {
				bad[k] = v
			}
			switch key {
			case "owner_spki_sha256", "key_registry_sha256", "grant_registry_sha256", "state_epoch":
				bad[key] = strings.Repeat("0", 64)
			case "a2a_path":
				bad[key] = "relative"
			case "thread_root":
				bad[key] = "root"
			default:
				bad[key] = "unselected"
			}
			if _, err := ParseA2AExecutor(requestTestBytes(t, bad)); !errors.Is(err, ErrA2AConfig) {
				t.Fatal("bad config accepted", key, err)
			}
			if _, err := ParseA2AExecutor(requestTestBytes(t, c)); err != nil {
				t.Fatal("valid config neighbor", err)
			}
		})
	}
	raw := requestTestBytes(t, c)
	for _, bad := range [][]byte{append(append([]byte{}, raw...), raw...), bytes.Replace(raw, []byte(`"type":`), []byte(`"type":"duplicate","type":`), 1), bytes.Replace(raw, []byte(`"type":`), []byte(`"Type":`), 1)} {
		if _, err := ParseA2AExecutor(bad); !errors.Is(err, ErrA2AConfig) {
			t.Fatal("ambiguous config accepted", err)
		}
	}
	e.a2aHash = strings.Repeat("0", 64)
	if _, err := e.Verify(context.Background(), "$fixture-event"); !errors.Is(err, ErrA2AProjection) {
		t.Fatal("bad executable pin accepted", err)
	}
	a2aNoFixtureCall(t, calls)
	a2aNoFixtureCall(t, providerCalls)
	link := filepath.Join(t.TempDir(), "linked-executable")
	if err := os.Symlink(c["a2a_path"].(string), link); err != nil {
		t.Fatal(err)
	}
	if err := checkA2APinnedExecutable(link, c["a2a_sha256"].(string)); !errors.Is(err, ErrA2AConfig) {
		t.Fatal("symlink executable accepted", err)
	}
	if !a2aAbsolutePath("/tmp/own directory/публичный") || a2aAbsolutePath("/tmp/x/../y") || a2aAbsolutePath("/tmp/bad\npath") {
		t.Fatal("path compatibility boundary")
	}
}

// The executable checker rejects nonregular/unsafe forms without blocking on
// an open. Its positive control is the current test binary, never a live tool.
func TestA2APinnedExecutablePredicates(t *testing.T) {
	_, _, c, _, _ := a2aExecutorFixture(t)
	if err := checkA2APinnedExecutable(c["a2a_path"].(string), c["a2a_sha256"].(string)); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "inert")
	if err := os.WriteFile(path, []byte("inert"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0644, 0777} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := checkA2APinnedExecutable(path, a2aHash([]byte("inert"))); !errors.Is(err, ErrA2AConfig) {
			t.Fatal("unsafe executable accepted", mode, err)
		}
	}
	if err := checkA2APinnedExecutable(dir, strings.Repeat("0", 64)); !errors.Is(err, ErrA2AConfig) {
		t.Fatal("directory accepted", err)
	}
}
