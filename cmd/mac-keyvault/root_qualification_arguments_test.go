package main

import (
	"errors"
	"strings"
	"testing"
)

// The finite owning cases accept only their exact public contract argv.
// Paired malformed controls cannot reach native code through this parser.
func TestRootQualificationParentArguments(t *testing.T) {
	base := []string{"--json", "root-grants", "qualify-storage", "--case"}
	for name, want := range map[string]rootQualificationCase{"create-project": rootQualificationCreate, "read-project": rootQualificationRead, "foreign-read": rootQualificationForeign, "helper-read": rootQualificationHelper, "cleanup-created": rootQualificationCleanup} {
		args := append(append([]string{}, base...), name)
		if name != "create-project" {
			args = append(args, "--receipt-sha256", strings.Repeat("a", 64))
		}
		got, err := parseRootQualificationArguments(args)
		if err != nil || got.operation != want {
			t.Fatalf("valid %s refused", name)
		}
		for _, extra := range [][]string{{"--service", "other"}, {"--reference", "AQID"}, {"--path", "/public/fixture"}, {"--case", name}, {"--receipt-sha256", strings.Repeat("a", 64)}} {
			if _, err := parseRootQualificationArguments(append(append([]string{}, args...), extra...)); !errors.Is(err, errRootQualification) {
				t.Fatalf("extra args accepted for %s", name)
			}
		}
	}
	for _, args := range [][]string{
		nil, {"root-grants", "qualify-storage", "--case", "create-project"},
		{"--json", "root-grants", "qualify-storage", "--case", "child-read"},
		{"--json", "root-grants", "qualify-storage", "--case=create-project"},
		{"--json", "root-grants", "qualify-storage", "--case", "read-project"},
		{"--json", "root-grants", "qualify-storage", "--case", "read-project", "--receipt-sha256", strings.Repeat("A", 64)},
		{"--json", "root-grants", "qualify-storage", "--case", "read-project", "--receipt-sha256", strings.Repeat("a", 63)},
		{"--json", "root-grants", "qualify-storage", "--receipt-sha256", strings.Repeat("a", 64), "--case", "read-project"},
	} {
		if _, err := parseRootQualificationArguments(args); !errors.Is(err, errRootQualification) {
			t.Fatal("invalid argv accepted")
		}
	}
}
