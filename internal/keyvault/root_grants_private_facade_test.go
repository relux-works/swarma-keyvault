package keyvault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func rootGrantsRequest44(t *testing.T, schema string) []byte {
	t.Helper()
	metadata, pair := rootGrantsTestPair(t, schema)
	// Literal ordered wire expectation, independent of the new production
	// request struct. A mutually wrong encoder/decoder cannot bless its order.
	pairRaw := rootGrantsOrderedJSON13(t, rootGrantsRaw13(t, pair), rootGrantsPairOrder13)
	object := map[string]any{"protocol": "keyvault-root-grants-private/1", "engine": "namecoin-root-grants-engine/1",
		"profile": "namecoin-landlord-root/1", "mode": "attach", "pair_metadata": metadata, "pair": json.RawMessage(pairRaw),
		"service": "example-root", "version": 1, "created": "2026-01-02T03:04:05Z"}
	return rootGrantsOrderedJSON13(t, rootGrantsRaw13(t, object),
		[]string{"protocol", "engine", "profile", "mode", "pair_metadata", "pair", "service", "version", "created"})
}

// Test-only exact object-level writer. Unlike substring replacement, a root
// "version" mutation cannot accidentally change the nested pair version.
func rootGrantsObject44(t *testing.T, fields map[string]json.RawMessage, order []string) []byte {
	t.Helper()
	var out bytes.Buffer
	out.WriteByte('{')
	count := 0
	for _, key := range order {
		value, ok := fields[key]
		if !ok {
			continue
		}
		if count > 0 {
			out.WriteByte(',')
		}
		out.Write(rootGrantsRaw13(t, key))
		out.WriteByte(':')
		out.Write(value)
		count++
	}
	out.WriteByte('}')
	return out.Bytes()
}

func rootGrantsSession44(t *testing.T) *RootGrantsPrivateSession {
	t.Helper()
	s, err := OpenRootGrantsPrivate(context.Background(), rootGrantsRequest44(t, "keyvault-recovery/2"))
	if err != nil {
		t.Fatal("canonical public fixture refused")
	}
	t.Cleanup(s.Close)
	return s
}

// PRIVATE TEST ONLY composition: the production facade Prepare is never called.
// Real engine phases and numbered grammar receive disposable published words;
// no reader/phrase/test hook is exposed by the production facade.
func rootGrantsPrepare44(s *RootGrantsPrivateSession, terminal rootGrantsLineIO) (RootGrantsPreparationPublic, error) {
	if err := s.engine.startInput(); err != nil {
		return RootGrantsPreparationPublic{}, err
	}
	ctx, stop, err := rootGrantsInputBudget(s.engine.state.ctx)
	if err != nil {
		s.engine.close()
		return RootGrantsPreparationPublic{}, err
	}
	defer stop()
	phrase, err := readRootGrantsNumbered(ctx, terminal)
	if err != nil {
		s.engine.close()
		return RootGrantsPreparationPublic{}, err
	}
	return s.engine.finishInput(phrase)
}

// Claim: actual canonical v1/v2 public requests construct the engine, own exact
// metadata despite caller mutation and expose no tty/private operation at Open.
// Limits: pure constructor/software source; not authenticated native admission.
func TestRootGrantsFacade44CanonicalOwnership(t *testing.T) {
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		raw := rootGrantsRequest44(t, schema)
		var request rootGrantsPrivateRequest
		if json.Unmarshal(raw, &request) != nil {
			t.Fatal("public fixture invalid")
		}
		s, err := OpenRootGrantsPrivate(context.Background(), raw)
		if err != nil {
			t.Fatal("legitimate retained schema refused")
		}
		t.Cleanup(s.Close)
		clear(raw)
		if !bytes.Equal(s.engine.state.input.pairMetadata, request.PairMetadata) || s.engine.state.input.pair != request.Pair {
			t.Fatal("constructor retained caller-owned bytes or changed full pair")
		}
		if s.engine.state.phase != rootGrantsEngineNew || s.engine.state.prepared != nil {
			t.Fatal("constructor performed private preparation")
		}
	}
}

// Claim: canonical closed/null/alias/order/bounds and full retained bindings
// refuse beside valid v1/v2 controls, before a session/tty exists. Every nested
// pair field has a null and independently changed binding control.
// Limits: no real Prepare/tty/native/C framing or qualification is exercised.
func TestRootGrantsFacade44RequestRefusals(t *testing.T) {
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		valid := rootGrantsRequest44(t, schema)
		var fields map[string]json.RawMessage
		if json.Unmarshal(valid, &fields) != nil {
			t.Fatal("public fixture invalid")
		}
		cases := map[string][]byte{"empty": nil, "null": []byte("null"), "array": []byte("[]"), "trailing": append(bytes.Clone(valid), '\n'),
			"leading": append([]byte{' '}, valid...), "second-object": append(bytes.Clone(valid), []byte("{}")...),
			"oversize": bytes.Repeat([]byte{' '}, 262145), "at-limit-invalid": bytes.Repeat([]byte{' '}, 262144),
			"unknown": append(bytes.Clone(valid[:len(valid)-1]), []byte(",\"unknown\":\"\"}")...)}
		rootOrder := []string{"protocol", "engine", "profile", "mode", "pair_metadata", "pair", "service", "version", "created"}
		for key := range fields {
			copyFields := func() map[string]json.RawMessage {
				out := make(map[string]json.RawMessage)
				for k, v := range fields {
					out[k] = v
				}
				return out
			}
			null := copyFields()
			null[key] = json.RawMessage("null")
			cases["null-"+key] = rootGrantsObject44(t, null, rootOrder)
			missing := copyFields()
			delete(missing, key)
			cases["missing-"+key] = rootGrantsObject44(t, missing, rootOrder)
			alias := copyFields()
			delete(alias, key)
			alias[strings.ToUpper(key)] = fields[key]
			var aliasOrder, duplicateOrder []string
			for _, k := range rootOrder {
				if k == key {
					aliasOrder = append(aliasOrder, strings.ToUpper(k))
				} else {
					aliasOrder = append(aliasOrder, k)
				}
				duplicateOrder = append(duplicateOrder, k)
				if k == key {
					duplicateOrder = append(duplicateOrder, k)
				}
			}
			cases["alias-"+key] = rootGrantsObject44(t, alias, aliasOrder)
			cases["duplicate-"+key] = rootGrantsObject44(t, fields, duplicateOrder)
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(valid, &object) != nil {
			t.Fatal("public request invalid")
		}
		var pair map[string]json.RawMessage
		if json.Unmarshal(object["pair"], &pair) != nil {
			t.Fatal("public pair invalid")
		}
		for key, value := range pair {
			for _, mode := range []string{"null", "changed"} {
				clone := make(map[string]json.RawMessage)
				for k, v := range pair {
					clone[k] = v
				}
				replacement := json.RawMessage("null")
				if mode == "changed" {
					if len(value) > 0 && value[0] == '"' {
						replacement = json.RawMessage("\"changed\"")
					} else {
						replacement = json.RawMessage("2147483647")
					}
				}
				clone[key] = replacement
				ordered := rootGrantsOrderedJSON13(t, rootGrantsRaw13(t, clone), rootGrantsPairOrder13)
				cases["pair-"+mode+"-"+key] = bytes.Replace(valid, object["pair"], ordered, 1)
			}
		}
		order := []string{"engine", "protocol", "profile", "mode", "pair_metadata", "pair", "service", "version", "created"}
		cases["reordered"] = rootGrantsOrderedJSON13(t, valid, order)
		var request rootGrantsPrivateRequest
		if json.Unmarshal(valid, &request) != nil {
			t.Fatal("public fixture invalid")
		}
		for _, mode := range []string{"zero-version", "large-version", "created", "metadata", "metadata-whitespace", "base64-crlf", "base64-extra-padding"} {
			q := request
			switch mode {
			case "zero-version":
				q.Version = 0
			case "large-version":
				q.Version = 2147483648
			case "created":
				q.Created = "2026-01-02T03:04:05+00:00"
			case "metadata":
				q.PairMetadata = []byte("null")
			case "metadata-whitespace":
				q.PairMetadata = append(bytes.Clone(q.PairMetadata), '\n')
			}
			raw := rootGrantsRaw13(t, q)
			if mode == "base64-crlf" || mode == "base64-extra-padding" {
				encoded := base64.StdEncoding.EncodeToString(request.PairMetadata)
				bad := encoded + "="
				if mode == "base64-crlf" {
					bad = encoded[:4] + "\r\n" + encoded[4:]
				}
				raw = bytes.Replace(raw, rootGrantsRaw13(t, encoded), rootGrantsRaw13(t, bad), 1)
			}
			cases[mode] = raw
		}
		for name, raw := range cases {
			t.Run(schema+"/"+name, func(t *testing.T) {
				s, err := OpenRootGrantsPrivate(context.Background(), raw)
				if err == nil || s != nil {
					if s != nil {
						s.Close()
					}
					t.Fatal("forbidden request constructed session")
				}
				if name == "oversize" {
					rootGrantsWantRefusal(t, err, "limit_exceeded")
				}
			})
		}
		for _, key := range []string{"protocol", "engine", "profile", "mode"} {
			raw := bytes.Replace(valid, fields[key], []byte("\"unsupported/99\""), 1)
			s, err := OpenRootGrantsPrivate(context.Background(), raw)
			if s != nil {
				s.Close()
				t.Fatal("unsupported mode/version accepted")
			}
			code := "unsupported_version"
			if key == "mode" {
				code = "unsupported_operation"
			}
			rootGrantsWantRefusal(t, err, code)
		}
	}
}

// Claim: actual facade Seal consumes privately prepared published input and
// returns ONLY canonical public record/envelope; independent test-only open
// checks KVG1 correspondence. Wrong phase/wrap/blob and replay return no result.
// Limits: synthetic wrapping point/blob, software crypto; NOT native policy.
func TestRootGrantsFacade44SealedPlumbing(t *testing.T) {
	s := rootGrantsSession44(t)
	view, err := rootGrantsPrepare44(s, &rootGrantsLines28{lines: rootGrantsNumbered28([]byte(recoveryFixturePhrase), []byte{'\n'})})
	if err != nil {
		t.Fatal("published numbered fixture refused")
	}
	owned := rootGrantsEnginePrepared28(s.engine)
	r, _ := rootGrantsRecordFixture13(t, "keyvault-recovery/2")
	sealed, err := s.Seal(r.WrappingPoint, []byte{1})
	if err != nil {
		t.Fatal("public facade seal failed")
	}
	record, err := ParseRootGrantsRecord(sealed.Record)
	if err != nil || record.PublicKey != view.Root.PublicKey || record.Pair != view.Pair {
		t.Fatal("public record changed preparation")
	}
	envelope, err := ParseRootGrantsEnvelope(sealed.Envelope, record)
	if err != nil {
		t.Fatal("canonical sealed envelope refused")
	}
	plain, err := rootGrantsOpen28(envelope, record, 3)
	if err != nil {
		t.Fatal("independent private binding check failed")
	}
	plain.clear()
	rootGrantsPreparedCleared28(t, owned)
	raw := rootGrantsRaw13(t, sealed)
	if len(raw) > 131072 || !bytes.HasPrefix(raw, []byte("{\"record\":{")) || bytes.Contains(raw, []byte("stored")) {
		t.Fatal("sealed public output shape changed")
	}
	if result, err := s.Seal(r.WrappingPoint, []byte{1}); err == nil || len(result.Record)+len(result.Envelope) != 0 {
		t.Fatal("consumed session resealed")
	}
	for _, mode := range []string{"wrong-phase", "point", "blob", "old-wrap"} {
		q := rootGrantsSession44(t)
		point, blob := r.WrappingPoint, []byte{1}
		if mode != "wrong-phase" {
			if _, err := rootGrantsPrepare44(q, &rootGrantsLines28{lines: rootGrantsNumbered28([]byte(recoveryFixturePhrase), []byte{'\n'})}); err != nil {
				t.Fatal("paired valid input refused")
			}
		}
		switch mode {
		case "point":
			point = []byte{4}
		case "blob":
			blob = nil
		case "old-wrap":
			old, err := parseRecoveryRecord(q.engine.state.input.pairMetadata)
			if err != nil {
				t.Fatal("public pair invalid")
			}
			point = old.Nostr.WrappingPoint
		}
		owned := rootGrantsEnginePrepared28(q.engine)
		if result, err := q.Seal(point, blob); err == nil || len(result.Record)+len(result.Envelope) != 0 {
			t.Fatal("forbidden seal returned result")
		}
		rootGrantsPreparedCleared28(t, owned)
	}
}

// Claim: facade is opaque, no private input/getter/callback API, errors use the
// closed fixed-code allowlist, input_canceled stays distinct from context cancel
// and timeout, copied-session duplicate/Close races cannot revive preparation.
// Limits: no actual Prepare invocation, C enum/copy/panic/handle or native tests.
func TestRootGrantsFacade44SurfaceErrorsAndConcurrency(t *testing.T) {
	s := rootGrantsSession44(t)
	alias := *s
	for _, value := range []any{s, alias, RootGrantsPrivateSession{}} {
		if fmt.Sprintf("%#v", value) != "<private-root-grants-session>" {
			t.Fatal("session formatted state")
		}
		if raw, err := json.Marshal(value); err == nil || len(raw) != 0 {
			t.Fatal("session serialized state")
		}
	}
	typ := reflect.TypeOf(RootGrantsPrivateSession{})
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).PkgPath == "" {
			t.Fatal("session exposes state field")
		}
	}
	allowed := map[string]bool{"Prepare": true, "Seal": true, "Close": true, "Format": true, "MarshalJSON": true}
	pt := reflect.TypeOf(s)
	for i := 0; i < pt.NumMethod(); i++ {
		if !allowed[pt.Method(i).Name] {
			t.Fatal("unexpected public session operation")
		}
	}
	prepare, ok := pt.MethodByName("Prepare")
	if !ok || prepare.Type.NumIn() != 1 {
		t.Fatal("Prepare accepts external input")
	}
	seal, ok := pt.MethodByName("Seal")
	if !ok || seal.Type.NumIn() != 3 || seal.Type.In(1) != reflect.TypeOf([]byte{}) || seal.Type.In(2) != reflect.TypeOf([]byte{}) {
		t.Fatal("Seal has a private or callback input")
	}
	output := reflect.TypeOf(RootGrantsPrivateSealed{})
	if output.NumField() != 2 || output.Field(0).Name != "Record" || output.Field(1).Name != "Envelope" ||
		output.Field(0).Type != reflect.TypeOf(json.RawMessage{}) || output.Field(1).Type != reflect.TypeOf(json.RawMessage{}) {
		t.Fatal("sealed result gained private or authority fields")
	}
	for _, code := range []string{"input_canceled", "canceled", "timeout", "unsupported_version", "unsupported_operation"} {
		rootGrantsWantRefusal(t, rootGrantsPrivateError(recoveryRefuse(code)), code)
	}
	for _, err := range []error{errors.New("PUBLIC_DIAGNOSTIC_MUST_NOT_ESCAPE"), recoveryRefuse("unknown"), (*Refusal)(nil), &Refusal{Code: "recovery_canceled", Message: "PUBLIC_DIAGNOSTIC_MUST_NOT_ESCAPE", Status: 99}} {
		fixed := rootGrantsPrivateError(err)
		if strings.Contains(fixed.Error(), "PUBLIC_DIAGNOSTIC") || strings.Contains(fixed.Error(), "OSStatus") {
			t.Fatal("raw error escaped")
		}
	}
	_, err := rootGrantsPrepare44(s, &rootGrantsLines28{})
	rootGrantsWantRefusal(t, rootGrantsPrivateError(err), "input_canceled")
	q := rootGrantsSession44(t)
	if _, err := rootGrantsPrepare44(q, &rootGrantsLines28{lines: rootGrantsNumbered28([]byte(recoveryFixturePhrase), []byte{'\n'})}); err != nil {
		t.Fatal("paired input refused")
	}
	owned := rootGrantsEnginePrepared28(q.engine)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); q.Close() }()
	}
	wg.Wait()
	rootGrantsPreparedCleared28(t, owned)
	q.Close()
	alias.Close()
	s.Close()
	if result, err := q.Seal(nil, nil); err == nil || len(result.Record)+len(result.Envelope) != 0 {
		t.Fatal("closed session revived")
	}
}

// Claim: copied facade instances share one finite prepared engine; concurrent
// duplicate Seal calls can produce at most one canonical sealed completion,
// then private preparation is cleared. The ordinary single-call valid control
// is TestRootGrantsFacade44SealedPlumbing. Limits: software-only, no C/native.
func TestRootGrantsFacade44ConcurrentSeal(t *testing.T) {
	s := rootGrantsSession44(t)
	if _, err := rootGrantsPrepare44(s, &rootGrantsLines28{lines: rootGrantsNumbered28([]byte(recoveryFixturePhrase), []byte{'\n'})}); err != nil {
		t.Fatal("paired valid preparation failed")
	}
	owned := rootGrantsEnginePrepared28(s.engine)
	r, _ := rootGrantsRecordFixture13(t, "keyvault-recovery/2")
	start := make(chan struct{})
	results := make(chan bool, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		alias := *s
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result, err := alias.Seal(r.WrappingPoint, []byte{1})
			if err != nil && len(result.Record)+len(result.Envelope) != 0 {
				t.Error("failed concurrent phase returned result")
			}
			results <- err == nil
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	success := 0
	for ok := range results {
		if ok {
			success++
		}
	}
	if success > 1 {
		t.Fatal("copied sessions sealed more than once")
	}
	rootGrantsAwaitClear44(t, s.engine)
	rootGrantsPreparedCleared28(t, owned)
}
