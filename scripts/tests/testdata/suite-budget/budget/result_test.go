//go:build darwin || linux

package budget

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"
	"time"
)

type runnerResult struct {
	Reason         string   `json:"reason"`
	Cause          string   `json:"cause"`
	ExitCode       int      `json:"exit_code"`
	RootExit       int      `json:"root_exit"`
	Reaped         bool     `json:"reaped"`
	ElapsedNS      int64    `json:"elapsed_ns"`
	FirstSignal    string   `json:"first_signal"`
	ObservedCauses []string `json:"observed_causes"`
}

// Both hosted witnesses and compatibility controls use this reader. A present
// empty string/zero/false is distinct from a missing, null or mistyped field.
func readResult(raw []byte) (runnerResult, error) {
	var r runnerResult
	fields := map[string]any{
		"reason": &r.Reason, "cause": &r.Cause, "exit_code": &r.ExitCode,
		"root_exit": &r.RootExit, "reaped": &r.Reaped, "elapsed_ns": &r.ElapsedNS,
		"first_signal": &r.FirstSignal, "observed_causes": &r.ObservedCauses,
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return r, errors.New("result must be an object")
	}
	seen := make(map[string]bool)
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return r, errors.New("invalid result key")
		}
		target, known := fields[key]
		if !known || seen[key] {
			return r, errors.New("unknown or duplicate result field")
		}
		seen[key] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return r, err
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return r, fmt.Errorf("null result field %s", key)
		}
		if err := json.Unmarshal(value, target); err != nil {
			return r, fmt.Errorf("invalid result field %s: %w", key, err)
		}
		if key == "observed_causes" {
			var items []json.RawMessage
			if err := json.Unmarshal(value, &items); err != nil {
				return r, err
			}
			for _, item := range items {
				if bytes.Equal(bytes.TrimSpace(item), []byte("null")) {
					return r, errors.New("null observation")
				}
			}
		}
	}
	token, err = d.Token()
	if err != nil || token != json.Delim('}') || len(seen) != len(fields) {
		return r, errors.New("incomplete result object")
	}
	if d.Decode(new(any)) != io.EOF {
		return r, errors.New("trailing result data")
	}
	return r, nil
}

type resultForm struct {
	reason       string
	code, root   int
	min, max     time.Duration
	first        string
	observations []string
}

// Complete records for these three controlled fixtures. Generic supervisor
// competing causes remain legitimate elsewhere, but are not events generated
// by these fixtures. A later distinct signal can precede or follow root Wait;
// signal observation order must still agree with first_signal.
func resultForms(phase string) []resultForm {
	switch phase {
	case "positive":
		return []resultForm{{"success", 0, 0, 3 * work, 2 * time.Minute, "", []string{"success"}}}
	case "deadline":
		return []resultForm{{"deadline", 124, -1, time.Minute, time.Minute + 5*time.Second, "", []string{"deadline", "exit"}}}
	case "native":
		var forms []resultForm
		for _, signals := range [][2]string{{"SIGINT", "SIGTERM"}, {"SIGTERM", "SIGINT"}} {
			for _, observations := range [][]string{
				{"canceled", signals[0], "exit"},
				{"canceled", signals[0], signals[1], "exit"},
				{"canceled", signals[0], "exit", signals[1]},
			} {
				forms = append(forms, resultForm{"canceled", 130, -1, 59 * time.Second, 90 * time.Second, signals[0], observations})
			}
		}
		return forms
	}
	return nil
}

func validateResult(r runnerResult, phase string) error {
	for _, form := range resultForms(phase) {
		if r.Reason == form.reason && r.Cause == form.reason && r.ExitCode == form.code && r.RootExit == form.root && r.Reaped && r.ElapsedNS >= int64(form.min) && r.ElapsedNS < int64(form.max) && r.FirstSignal == form.first && slices.Equal(r.ObservedCauses, form.observations) {
			return nil
		}
	}
	return errors.New("result is not a complete permitted phase record")
}

func validResult(phase string) runnerResult {
	f := resultForms(phase)[0]
	return runnerResult{f.reason, f.reason, f.code, f.root, true, int64(f.min), f.first, append([]string(nil), f.observations...)}
}

func acceptedWire(raw []byte, phase string) error {
	r, err := readResult(raw)
	if err != nil {
		return err
	}
	return validateResult(r, phase)
}

// Each admitted phase/signal sequence passes the exact hosted reader and
// validator, including the two legitimate positions of a later signal.
func TestCompleteResultForms(t *testing.T) {
	for _, phase := range []string{"positive", "deadline", "native"} {
		for i, f := range resultForms(phase) {
			t.Run(fmt.Sprintf("%s/%d", phase, i), func(t *testing.T) {
				r := runnerResult{f.reason, f.reason, f.code, f.root, true, int64(f.min), f.first, f.observations}
				raw, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				if err := acceptedWire(raw, phase); err != nil {
					t.Fatal(err)
				}
				r.ElapsedNS = int64(f.max) - 1
				raw, _ = json.Marshal(r)
				if err := acceptedWire(raw, phase); err != nil {
					t.Fatal(err)
				}
				r.ElapsedNS = int64(f.max)
				raw, _ = json.Marshal(r)
				if acceptedWire(raw, phase) == nil {
					t.Fatal("exclusive elapsed bound accepted")
				}
			})
		}
	}
}

// Required fields reject omission, null and every other JSON type through the
// same actual reader; present zero/false/empty values remain structurally valid.
func TestResultRequiredFields(t *testing.T) {
	raw, _ := json.Marshal(validResult("positive"))
	var base map[string]json.RawMessage
	if err := json.Unmarshal(raw, &base); err != nil {
		t.Fatal(err)
	}
	for key, original := range base {
		cases := map[string]json.RawMessage{"missing": nil, "null": json.RawMessage("null")}
		for _, value := range []string{`"wrong"`, "0", "false", "[]", "{}", "1.5", "9223372036854775808"} {
			var a, b any
			_ = json.Unmarshal(original, &a)
			_ = json.Unmarshal([]byte(value), &b)
			if fmt.Sprintf("%T", a) == fmt.Sprintf("%T", b) && value != "1.5" && value != "9223372036854775808" {
				continue
			}
			cases[value] = json.RawMessage(value)
		}
		for name, value := range cases {
			t.Run(key+"/"+name, func(t *testing.T) {
				if err := acceptedWire(raw, "positive"); err != nil {
					t.Fatal(err)
				}
				fields := make(map[string]json.RawMessage)
				for k, v := range base {
					fields[k] = v
				}
				if value == nil {
					delete(fields, key)
				} else {
					fields[key] = value
				}
				wire, _ := json.Marshal(fields)
				if _, err := readResult(wire); err == nil {
					t.Fatalf("required field corruption accepted: %s", name)
				}
			})
		}
	}
	// These values prove structural presence, not phase acceptance of false reaped.
	for _, wire := range [][]byte{raw, bytes.Replace(raw, []byte(`"reaped":true`), []byte(`"reaped":false`), 1)} {
		if _, err := readResult(wire); err != nil {
			t.Fatal(err)
		}
	}
}

// Known-token contradictions, root/cause/exit mismatches and impossible signal
// sequences fail after real JSON decoding, beside a valid complete neighbour.
func TestResultWireContradictions(t *testing.T) {
	for _, phase := range []string{"positive", "deadline", "native"} {
		valid := validResult(phase)
		mutations := map[string]func(*runnerResult){
			"canceled-observation":       func(r *runnerResult) { r.ObservedCauses = append(r.ObservedCauses, "canceled") },
			"success-observation":        func(r *runnerResult) { r.ObservedCauses = append(r.ObservedCauses, "success") },
			"deadline-observation":       func(r *runnerResult) { r.ObservedCauses = append(r.ObservedCauses, "deadline") },
			"refusal-observation":        func(r *runnerResult) { r.ObservedCauses = append(r.ObservedCauses, "cleanup-refused") },
			"cause":                      func(r *runnerResult) { r.Cause = "exit" },
			"exit-code":                  func(r *runnerResult) { r.ExitCode = 1 },
			"root":                       func(r *runnerResult) { r.RootExit = 7 },
			"not-reaped":                 func(r *runnerResult) { r.Reaped = false },
			"wrong-first":                func(r *runnerResult) { r.FirstSignal = "SIGTERM" },
			"unknown-first":              func(r *runnerResult) { r.FirstSignal = "SIGKILL" },
			"null-observations":          func(r *runnerResult) { r.ObservedCauses = nil },
			"empty-observations":         func(r *runnerResult) { r.ObservedCauses = []string{} },
			"reordered":                  func(r *runnerResult) { r.ObservedCauses = []string{"exit", "SIGINT", "canceled"} },
			"repeated-signal":            func(r *runnerResult) { r.ObservedCauses = []string{"canceled", "SIGINT", "SIGINT", "exit"} },
			"missing-exit":               func(r *runnerResult) { r.ObservedCauses = []string{"canceled", "SIGINT"} },
			"signal-before-cancellation": func(r *runnerResult) { r.ObservedCauses = []string{"SIGINT", "canceled", "exit"} },
		}
		for name, mutate := range mutations {
			t.Run(phase+"/"+name, func(t *testing.T) {
				raw, _ := json.Marshal(valid)
				if err := acceptedWire(raw, phase); err != nil {
					t.Fatal(err)
				}
				bad := valid
				bad.ObservedCauses = append([]string(nil), valid.ObservedCauses...)
				mutate(&bad)
				raw, _ = json.Marshal(bad)
				if acceptedWire(raw, phase) == nil {
					t.Fatal("contradictory complete record accepted")
				}
			})
		}
	}
}

// Strict object syntax and non-null string elements are required independently
// of the phase table. An intact neighbour passes before each corruption.
func TestResultObjectSyntax(t *testing.T) {
	raw, _ := json.Marshal(validResult("positive"))
	bad := map[string][]byte{
		"duplicate":        bytes.Replace(raw, []byte(`"first_signal":""`), []byte(`"first_signal":"","first_signal":""`), 1),
		"unknown":          append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":0}`)...),
		"trailing-object":  append(append([]byte(nil), raw...), []byte(` {}`)...),
		"trailing-garbage": append(append([]byte(nil), raw...), byte('!')),
		"truncated":        raw[:len(raw)-1], "array": []byte("[]"), "null": []byte("null"),
		"null-observation":  bytes.Replace(raw, []byte(`["success"]`), []byte(`[null]`), 1),
		"wrong-observation": bytes.Replace(raw, []byte(`["success"]`), []byte(`[1]`), 1),
	}
	for name, wire := range bad {
		t.Run(name, func(t *testing.T) {
			if err := acceptedWire(raw, "positive"); err != nil {
				t.Fatal(err)
			}
			if _, err := readResult(wire); err == nil {
				t.Fatal("invalid object accepted")
			}
		})
	}
}
