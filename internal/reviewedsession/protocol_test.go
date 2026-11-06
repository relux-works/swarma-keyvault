package reviewedsession

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestStrictJSONAmbiguities(t *testing.T) {
	valid := []byte(` {"a":{"b":[0,1,-1,true,null,"escaped\"value"]}} `)
	if _, err := strictObject(valid, inputMax); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		`{"a":1,"a":2}`, `{"a":1,"\u0061":2}`, `{"a":{"b":1,"b":2}}`,
		`{"a":1} {}`, `{"a":1}x`, `[]`, `null`, `1`, `{"a":1.0}`, `{"a":1e0}`, `{"a":-0}`, `{"a":01}`,
		`{"a":"\ud800"}`, `{"a":"\udc00"}`, `{"a":"\ud83d\ude00"}`, `{"a":"\u0000"}`,
		`{"a":"` + string([]byte{0xff}) + `"}`, `{"a":"\q"}`, `{"a":NaN}`, `{"a":Infinity}`, `{"a":}`, `{"a":1,}`,
		strings.Repeat(`{"a":`, 18) + `0` + strings.Repeat(`}`, 18),
	} {
		t.Run(s, func(t *testing.T) {
			if _, err := strictObject([]byte(s), inputMax); err == nil {
				t.Fatal("accepted ambiguous syntax")
			}
		})
	}
	if _, err := strictObject(valid, len(valid)-1); err == nil {
		t.Fatal("ignored cap")
	}
}

func TestInputClosedProfileSpecificPaths(t *testing.T) {
	for _, p := range []profile{repository, localRepository, a2aCertificate, muGrantMac} {
		paths := map[string]any{"payload_path": "/public/payload"}
		if p == muGrantMac {
			paths = map[string]any{"spec_path": "spec.json", "subject_attestation_path": "subject.json", "publisher_attestation_path": "publisher.json"}
		}
		m := map[string]any{"schema": "kv-reviewed-input/1", "profile": string(p), "inputs": paths}
		good, _ := json.Marshal(m)
		if got, err := parseInput(good); err != nil || got.profile != p {
			t.Fatal(got, err)
		}
		for _, mutation := range []func(map[string]any){
			func(m map[string]any) { m["schema"] = "kv-reviewed-input/2" },
			func(m map[string]any) { delete(m, "profile") },
			func(m map[string]any) { m["profile"] = "publisher" },
			func(m map[string]any) { m["inputs"] = nil },
			func(m map[string]any) { m["reason"] = "anything" },
			func(m map[string]any) { m["inputs"].(map[string]any)["extra_path"] = "x" },
			func(m map[string]any) {
				for k := range m["inputs"].(map[string]any) {
					m["inputs"].(map[string]any)[k] = "-"
				}
			},
			func(m map[string]any) {
				for k := range m["inputs"].(map[string]any) {
					m["inputs"].(map[string]any)[k] = ""
				}
			},
		} {
			var copy map[string]any
			_ = json.Unmarshal(good, &copy)
			mutation(copy)
			raw, _ := json.Marshal(copy)
			if _, err := parseInput(raw); err == nil {
				t.Fatal("accepted bad input", string(raw))
			}
		}
	}
}

type shortWriter struct {
	calls   int
	failure error
}

func (w *shortWriter) Write(p []byte) (int, error) { w.calls++; return len(p) - 1, w.failure }

func TestFramesAreBoundedExactAndNeverRetried(t *testing.T) {
	payload := []byte(`{"type":"test"}`)
	var b bytes.Buffer
	if err := writeFrame(&b, payload, commitMax); err != nil {
		t.Fatal(err)
	}
	good := bytes.Clone(b.Bytes())
	got, err := framePayload(good, commitMax)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal(got, err)
	}
	got[0] = 'x'
	if bytes.Equal(good[4:], got) {
		t.Fatal("returned caller alias")
	}
	for _, raw := range [][]byte{nil, good[:3], good[:len(good)-1], append(bytes.Clone(good), 0), append(bytes.Clone(good), good...), {0, 0, 0, 0}, {255, 255, 255, 255}} {
		if _, err := framePayload(raw, commitMax); err == nil {
			t.Fatal("accepted extra/partial frame")
		}
	}
	bad := bytes.Clone(good)
	binary.BigEndian.PutUint32(bad[:4], commitMax+1)
	if _, err := framePayload(bad, commitMax); err == nil {
		t.Fatal("oversized prefix")
	}
	for _, failure := range []error{nil, errors.New("failed write")} {
		w := &shortWriter{failure: failure}
		err := writeFrame(w, payload, commitMax)
		if err == nil || w.calls != 1 {
			t.Fatal("retried/accepted partial frame", w.calls, err)
		}
		if failure == nil && !errors.Is(err, io.ErrShortWrite) {
			t.Fatal(err)
		}
	}
	if writeFrame(nil, payload, commitMax) == nil || writeFrame(&b, nil, commitMax) == nil || writeFrame(&b, payload, 1) == nil {
		t.Fatal("invalid frame write accepted")
	}
}
