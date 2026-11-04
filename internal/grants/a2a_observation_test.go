package grants

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func a2aObservedFixture(t *testing.T, reply bool) (*a2aFixture, *A2AReceiver, A2AObservationContext, map[string]any, map[string]any) {
	t.Helper()
	f := a2aFixtureForTest(t)
	r, e := f.receiver(t)
	x := A2AObservationContext{Audience: e.RecipientMXID, RoomID: e.RoomID, EventID: e.EventID, Topic: e.Topic, ThreadRoot: "$thread:example.invalid", DeclaredFrom: "requester", DeclaredTo: "receiver"}
	header := map[string]any{"v": 1, "type": "message", "slug": x.Topic, "topic": x.ThreadRoot, "from": x.DeclaredFrom, "to": []any{x.DeclaredTo}, "at": "2026-11-04T14:00:00Z", "kind": "request"}
	relation := map[string]any{"rel_type": "m.thread", "event_id": x.ThreadRoot, "m.in_reply_to": map[string]any{"event_id": x.ThreadRoot}}
	humanReply := "-"
	if reply {
		header["re"] = x.ThreadRoot
		humanReply = x.ThreadRoot
	} else {
		relation["is_falling_back"] = true
	}
	wrapper := map[string]any{"msgtype": "m.text", "body": "- from: requester\n- to: receiver\n- at: 2026-11-04T14:00:00Z\n- re: " + humanReply + "\n- kind: request\n\n" + string(e.Body), "ai.relux.a2a": header, "m.mentions": map[string]any{"user_ids": []any{x.Audience}}, "m.relates_to": relation}
	projection := map[string]any{"type": "a2a.event-verification-input/1", "observation_status": "observed", "requested_room_id": x.RoomID, "requested_event_id": x.EventID, "returned_event_id": x.EventID, "sender_mxid": e.SenderMXID, "receiver_mxid": x.Audience, "receiver_identity_source": "selected-stored-session", "event_type": "m.room.message", "returned_room_id_present": true, "returned_room_id": x.RoomID, "room_context_source": "returned-room-and-original-endpoint"}
	return f, r, x, wrapper, projection
}

func a2aObservedBytes(t *testing.T, wrapper, projection map[string]any) []byte {
	t.Helper()
	projection["content_base64"] = base64.RawURLEncoding.EncodeToString(requestTestBytes(t, wrapper))
	return requestTestBytes(t, projection)
}

// Both actual formatter shapes are admitted: explicit reply omits false;
// no-re uses true fallback and the human '-' line. Public extraction preserves
// the exact signed bytes, then the independently signed request verifies.
// These are contract fixtures, not executed Source formatter conformance.
func TestA2AObservationValidNeighbors(t *testing.T) {
	for _, reply := range []bool{false, true} {
		for _, returned := range []bool{false, true} {
			f, r, x, w, p := a2aObservedFixture(t, reply)
			if !returned {
				delete(p, "returned_room_id")
				p["returned_room_id_present"] = false
				p["room_context_source"] = "authenticated-room-scoped-endpoint"
			}
			want := []byte(strings.SplitN(w["body"].(string), "\n\n", 2)[1])
			raw := append([]byte(" \n"), a2aObservedBytes(t, w, p)...)
			raw = append(raw, '\n')
			e, err := ParseA2AObservation(raw, x)
			if err != nil || !bytes.Equal(e.Body, want) {
				t.Fatal("valid exact extraction", err)
			}
			if _, err := r.Verify(e, f.now); err != nil {
				t.Fatal("valid signed control", err)
			}
		}
	}
}

// Each malformed observation/wrapper refuses before it can become a verifier
// input. An unchanged signed neighbor still passes after every rejection.
func TestA2AObservationRefusals(t *testing.T) {
	modes := []string{"projection-extra", "status", "returned-id", "requested-id", "wrong-room", "absent-room-lie", "absent-room-null", "presence-type", "identity-source", "receiver", "encrypted", "short-sender", "empty-localpart", "spaced-sender", "content-type", "msgtype", "missing-header", "header-extra", "header-v-type", "header-v-fraction", "header-from", "header-to", "header-time", "header-kind", "header-root", "header-slug", "re-empty", "re-null", "mention-extra", "mention-wrong", "thread-root", "reply-target", "reply-false-flag", "no-re-missing-flag", "prefix-missing", "prefix-doubled", "prefix-spoofed", "prefix-crlf", "envelope-fence", "envelope-extra", "envelope-lf", "envelope-space"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			f, r, x, w, p := a2aObservedFixture(t, true)
			h := w["ai.relux.a2a"].(map[string]any)
			rel := w["m.relates_to"].(map[string]any)
			switch mode {
			case "projection-extra":
				p["Sender"] = p["sender_mxid"]
			case "status":
				p["observation_status"] = "unknown"
			case "returned-id":
				p["returned_event_id"] = "$other"
			case "requested-id":
				p["requested_event_id"] = "$other"
			case "wrong-room":
				p["returned_room_id"] = "!other"
			case "absent-room-lie":
				delete(p, "returned_room_id")
				p["returned_room_id_present"] = false
			case "absent-room-null":
				p["returned_room_id"] = nil
				p["returned_room_id_present"] = false
				p["room_context_source"] = "authenticated-room-scoped-endpoint"
			case "presence-type":
				p["returned_room_id_present"] = "true"
			case "identity-source":
				p["receiver_identity_source"] = "fresh-whoami"
			case "receiver":
				p["receiver_mxid"] = "@other:example.invalid"
			case "encrypted":
				p["event_type"] = "m.room.encrypted"
			case "short-sender":
				p["sender_mxid"] = "requester"
			case "empty-localpart":
				p["sender_mxid"] = "@:example.invalid"
			case "spaced-sender":
				p["sender_mxid"] = "@request er:example.invalid"
			case "content-type":
				w = nil
			case "msgtype":
				w["msgtype"] = "m.notice"
			case "missing-header":
				delete(w, "ai.relux.a2a")
			case "header-extra":
				h["reply_by"] = "2026-11-04T15:00:00Z"
			case "header-v-type":
				h["v"] = "1"
			case "header-v-fraction":
				h["v"] = json.Number("1.0")
			case "header-from":
				h["from"] = "spoof"
			case "header-to":
				h["to"] = []any{"receiver", "other"}
			case "header-time":
				h["at"] = "yesterday"
			case "header-kind":
				h["kind"] = "notice"
			case "header-root":
				h["topic"] = "$other"
			case "header-slug":
				h["slug"] = "other"
			case "re-empty":
				h["re"] = ""
			case "re-null":
				h["re"] = nil
			case "mention-extra":
				w["m.mentions"] = map[string]any{"user_ids": []any{x.Audience}, "room": true}
			case "mention-wrong":
				w["m.mentions"] = map[string]any{"user_ids": []any{"@other:example.invalid"}}
			case "thread-root":
				rel["event_id"] = "$other"
			case "reply-target":
				rel["m.in_reply_to"] = map[string]any{"event_id": "$other"}
			case "reply-false-flag":
				rel["is_falling_back"] = false
			case "no-re-missing-flag":
				delete(h, "re")
			case "prefix-missing":
				w["body"] = string(f.event(t).Body)
			case "prefix-doubled":
				w["body"] = w["body"].(string) + w["body"].(string)
			case "prefix-spoofed":
				w["body"] = strings.Replace(w["body"].(string), "- from: requester", "- from: spoof", 1)
			case "prefix-crlf":
				w["body"] = strings.ReplaceAll(w["body"].(string), "\n", "\r\n")
			case "envelope-fence":
				w["body"] = strings.Replace(w["body"].(string), "\n\n", "\n\n```json\n", 1) + "\n```"
			case "envelope-extra":
				w["body"] = w["body"].(string) + "{}"
			case "envelope-lf":
				w["body"] = w["body"].(string) + "\n"
			case "envelope-space":
				w["body"] = w["body"].(string) + " "
			}
			if _, err := ParseA2AObservation(a2aObservedBytes(t, w, p), x); err == nil {
				t.Fatal("malformed observation accepted", mode)
			}
			_, _, _, goodW, goodP := a2aObservedFixture(t, true)
			// Use the original fixture's signed bytes so the valid control matches
			// this receiver, rather than another freshly generated signing key.
			goodW["body"] = strings.Split(goodW["body"].(string), "\n\n")[0] + "\n\n" + string(f.event(t).Body)
			e, err := ParseA2AObservation(a2aObservedBytes(t, goodW, goodP), x)
			if err != nil {
				t.Fatal("valid extraction neighbor", err)
			}
			if _, err := r.Verify(e, f.now); err != nil {
				t.Fatal("valid signed neighbor", err)
			}
		})
	}
}

// Strict decoding detects duplicate decoded keys at every depth and refuses
// invalid scalar encodings without silently repairing them. Valid Unicode,
// escaped aliases without a duplicate, and JSON whitespace remain supported.
func TestA2AObservationStrictJSON(t *testing.T) {
	valid := []string{"{}", " {\"x\":\"é\"} \n", "{\"x\":\"\\ud83d\\ude00\"}", "{\"\\u0078\":1}"}
	invalid := []string{"", "{}{}", "{}x", "{\"x\":1,\"x\":2}", "{\"x\":1,\"\\u0078\":2}", "{\"x\":{\"a\":1,\"a\":2}}", "{\"x\":[{\"a\":1,\"a\":2}]}", "{\"x\":\"\\ud800\"}", "{\"x\":\"\\udc00\"}", "{\"x\":\"\\ud800\\u0041\"}", string([]byte{'"', 0xff, '"'})}
	for _, raw := range valid {
		if _, err := strictA2AJSON([]byte(raw), 65536); err != nil {
			t.Fatal("valid JSON", raw, err)
		}
	}
	for _, raw := range invalid {
		if _, err := strictA2AJSON([]byte(raw), 65536); err == nil {
			t.Fatal("invalid JSON accepted", raw)
		}
	}
	if _, err := strictA2AJSON([]byte(strings.Repeat("[", 18)+"0"+strings.Repeat("]", 18)), 65536); err == nil {
		t.Fatal("depth accepted")
	}
}

// A static wrapper with an invalid inner signature extracts without gaining
// authorization. Neither declarations nor extraction bypass signature checks.
func TestA2AObservationInertEnvelope(t *testing.T) {
	f, r, x, w, p := a2aObservedFixture(t, true)
	inert := "{\"payload\":\"e30\",\"request\":\"e30\",\"signature\":\"AA\",\"type\":\"grants-a2a-envelope-1\"}"
	w["body"] = strings.Split(w["body"].(string), "\n\n")[0] + "\n\n" + inert
	e, err := ParseA2AObservation(a2aObservedBytes(t, w, p), x)
	if err != nil || string(e.Body) != inert {
		t.Fatal("inert extraction", err)
	}
	if _, err := r.Verify(e, f.now); err == nil {
		t.Fatal("inert extraction authorized")
	}
	p["sender_mxid"] = "requester"
	if _, err := ParseA2AObservation(a2aObservedBytes(t, w, p), x); !errors.Is(err, ErrA2ASenderUnavailable) {
		t.Fatal("alias not refused", err)
	}
}

// The inclusive content limit admits an intact signed neighbor. Oversize,
// redaction, malformed encoding and duplicate records refuse without repair.
func TestA2AObservationBoundsAndRecords(t *testing.T) {
	f, r, x, w, p := a2aObservedFixture(t, true)
	content := requestTestBytes(t, w)
	content = append(append(append([]byte{}, content[:1]...), bytes.Repeat([]byte{' '}, 65536-len(content))...), content[1:]...)
	if len(content) != 65536 {
		t.Fatal("bad boundary fixture")
	}
	p["content_base64"] = base64.RawURLEncoding.EncodeToString(content)
	good := requestTestBytes(t, p)
	e, err := ParseA2AObservation(good, x)
	if err != nil {
		t.Fatal("inclusive content limit", err)
	}
	if _, err := r.Verify(e, f.now); err != nil {
		t.Fatal("signed boundary neighbor", err)
	}
	for _, bad := range [][]byte{append(append([]byte{'{'}, ' '), content[1:]...), []byte("{}"), []byte("null"), []byte("[]"), []byte(""), []byte("{\"body\":\"\\ud800\"}")} {
		p["content_base64"] = base64.RawURLEncoding.EncodeToString(bad)
		if _, err := ParseA2AObservation(requestTestBytes(t, p), x); err == nil {
			t.Fatal("invalid content accepted", len(bad))
		}
	}
	p["content_base64"] = base64.RawURLEncoding.EncodeToString(requestTestBytes(t, w)) + "="
	if _, err := ParseA2AObservation(requestTestBytes(t, p), x); err == nil {
		t.Fatal("padded base64 accepted")
	}
	good = a2aObservedBytes(t, w, p)
	for _, bad := range [][]byte{append(append([]byte{}, good...), good...), bytes.Replace(good, []byte("{"), []byte("{\"type\":\"a2a.event-verification-input/1\","), 1), bytes.Replace(good, []byte("{"), []byte("{\"\\u0074ype\":\"a2a.event-verification-input/1\","), 1), bytes.Repeat([]byte{' '}, 98305)} {
		if _, err := ParseA2AObservation(bad, x); err == nil {
			t.Fatal("invalid projection record accepted")
		}
	}
}

// A matching human From declaration cannot substitute for the actual account.
// Extraction is not enrollment, and reposting the same valid envelope from an
// ungranted account is refused by the receiver before any dispatch capability.
func TestA2AObservationDeclaredSenderIsNotAuthority(t *testing.T) {
	f, r, x, w, p := a2aObservedFixture(t, true)
	p["sender_mxid"] = "@requester:foreign.invalid"
	e, err := ParseA2AObservation(a2aObservedBytes(t, w, p), x)
	if err != nil {
		t.Fatal("full actual sender extraction", err)
	}
	if _, err := r.Verify(e, f.now); !errors.Is(err, ErrA2ANoGrant) {
		t.Fatal("declaration substituted for actual sender", err)
	}
	x.DeclaredFrom = "requester\n- kind: request"
	if _, err := ParseA2AObservation(a2aObservedBytes(t, w, p), x); err == nil {
		t.Fatal("configured header injection accepted")
	}
}
