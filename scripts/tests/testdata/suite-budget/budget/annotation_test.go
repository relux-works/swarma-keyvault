package budget

import (
	"bytes"
	"os"
	"regexp"
	"testing"
)

var nativeDeadline = regexp.MustCompile(`(?m)^\d{4}-\d{2}-\d{2}T[^\r\n ]+ ##\[error\]The action 'Healthy binaries must not pass beyond the short aggregate deadline' has timed out after 1 minutes\.\r?$`)

// Only the expected native annotation form qualifies; the workflow separately
// supplies origin through its same-attempt completed-job Actions API read.
// A test-binary alarm, generic failure or a different step/budget cannot pass.
func TestAnnotationContract(t *testing.T) {
	valid := []byte("2026-01-01T00:00:00.000Z ##[error]The action 'Healthy binaries must not pass beyond the short aggregate deadline' has timed out after 1 minutes.\n")
	if !nativeDeadline.Match(valid) {
		t.Fatal("native deadline annotation positive control refused")
	}
	for _, raw := range [][]byte{
		[]byte("panic: test timed out after 45s\n"),
		[]byte("Error: Process completed with exit code 1.\n"),
		bytes.ReplaceAll(valid, []byte("1 minutes"), []byte("2 minutes")),
		bytes.ReplaceAll(valid, []byte("Healthy binaries must not pass beyond the short aggregate deadline"), []byte("different step")),
		bytes.ReplaceAll(valid, []byte("##[error]"), nil),
	} {
		if nativeDeadline.Match(raw) {
			t.Fatal("non-native or unrelated failure accepted as suite deadline")
		}
	}
}

// This reads the completed same-attempt control job through the hosting API.
// PID/outcome checks run in that job before acceptance; native cause is checked
// afterward because an in-progress job's complete log is not yet available.
func TestHostedDeadlineAnnotation(t *testing.T) {
	path := os.Getenv("KEYVAULT_SUITE_JOB_LOG")
	if path == "" {
		t.Skip("requires the completed hosted control job's actual log")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 8<<20 {
		t.Fatal("bounded completed control job log required")
	}
	if !nativeDeadline.Match(raw) {
		t.Fatal("actual control job lacks the native expected suite-deadline annotation")
	}
}
