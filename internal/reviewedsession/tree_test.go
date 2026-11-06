package reviewedsession

import (
	"strings"
	"testing"
)

func TestSafeTreeCompleteFieldPathsAndArrayOrder(t *testing.T) {
	raw := []byte(`{"z":[],"entries":[{"action":"repository.create","target":"<private>"},{"action":"repository.delete","paired_create_entry":"create-1"}],"audience":{"executor_id":"e","deployment_id":"d"},"uses":1,"supersedes":null,"presence":false}`)
	got, err := safeTree(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := "$: object(6)\n" +
		`$["audience"]: object(2)` + "\n" +
		`$["audience"]["deployment_id"]: "d"` + "\n" +
		`$["audience"]["executor_id"]: "e"` + "\n" +
		`$["entries"]: array(2)` + "\n" +
		`$["entries"][1]: object(2)` + "\n" +
		`$["entries"][1]["action"]: "repository.create"` + "\n" +
		`$["entries"][1]["target"]: "\u003cprivate\u003e"` + "\n" +
		`$["entries"][2]: object(2)` + "\n" +
		`$["entries"][2]["action"]: "repository.delete"` + "\n" +
		`$["entries"][2]["paired_create_entry"]: "create-1"` + "\n" +
		`$["presence"]: false` + "\n" +
		`$["supersedes"]: null` + "\n" +
		`$["uses"]: 1` + "\n" +
		`$["z"]: array(0)` + "\n"
	if got != want {
		t.Fatalf("safe tree mismatch\n%s", got)
	}
	// Order of JSON object members does not change disclosure; signed array
	// order does. Neither transformation replaces exact signed bytes.
	reordered := []byte(`{"presence":false,"supersedes":null,"uses":1,"audience":{"deployment_id":"d","executor_id":"e"},"entries":[{"target":"<private>","action":"repository.create"},{"paired_create_entry":"create-1","action":"repository.delete"}],"z":[]}`)
	if second, err := safeTree(reordered); err != nil || second != got {
		t.Fatal("unstable field order", second, err)
	}
}

func TestSafeTreeRefusesExpansionAndAuthorityMarkers(t *testing.T) {
	if _, err := safeString(strings.Repeat("<", reviewMax/2)); err == nil {
		t.Fatal("safe scalar expanded beyond complete body cap")
	}
	for _, raw := range []string{
		`{"data":"signing_digest_sha256=forged"}`,
		`{"session_nonce=forged":"x"}`,
		`{"data":"` + strings.Repeat("<", reviewMax/2) + `"}`,
	} {
		if _, err := safeTree([]byte(raw)); err == nil {
			t.Fatal("unsafe or truncated disclosure accepted")
		}
	}
}
