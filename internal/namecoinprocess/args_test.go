package namecoinprocess

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

func argvFixture(mode Mode) []string {
	a := []string{"namecoin", string(mode), "--process-contract", "1", "--group", "fixture/recovery@1", "--account", "fixture/namecoin@1", "--profile", "/public/profile.json", "--profile-sha256", strings.Repeat("a", 64), "--account-pin", "/public/pin.json", "--timeout-seconds", "1"}
	switch mode {
	case SignPSBT:
		a = append(a, "--request", "/public/request.json", "--request-sha256", strings.Repeat("b", 64), "--output", "/public/new-result.json")
	case Reconcile:
		a = append(a, "--query", "/public/query.json", "--output", "/public/new-result.json")
	case InitializeJournal:
		a = append(a, "--adoption-plan-sha256", strings.Repeat("c", 64))
	}
	return a
}

func replaceArg(argv []string, flag, value string) []string {
	argv = append([]string(nil), argv...)
	for i := 2; i < len(argv); i += 2 {
		if argv[i] == flag {
			argv[i+1] = value
			return argv
		}
	}
	panic("missing test flag")
}

// Every C2 mode accepts separate pairs in arbitrary order and the inclusive
// explicit timeout limits; this parser makes no filesystem or custody claim.
func TestArgsClosedModes(t *testing.T) {
	for _, mode := range []Mode{SignPSBT, Reconcile, InitializeJournal} {
		for _, seconds := range []string{"1", "3600"} {
			argv := replaceArg(argvFixture(mode), "--timeout-seconds", seconds)
			got, err := ParseArgs(argv)
			if err != nil || got.Mode != mode || got.Group != "fixture/recovery@1" || got.Account != "fixture/namecoin@1" || got.Timeout < time.Second || got.Timeout > time.Hour {
				t.Fatal(mode, seconds, got, err)
			}
			reversed := append([]string(nil), argv[:2]...)
			for i := len(argv) - 2; i >= 2; i -= 2 {
				reversed = append(reversed, argv[i], argv[i+1])
			}
			other, err := ParseArgs(reversed)
			if err != nil || !reflect.DeepEqual(got, other) {
				t.Fatal("pair order changed selection", err)
			}
		}
	}
	if a, err := ParseArgs(append(argvFixture(SignPSBT), "--reveal-values-pin", "/public/reveal.json")); err != nil || a.RevealPinPath != "/public/reveal.json" {
		t.Fatal(err)
	}
}

// Malformed grammar and every cross-mode extra option return the independent
// C5 invalid_request/REFUSED/2 line. Near valid cases are exercised above.
func TestArgsRefusals(t *testing.T) {
	base := argvFixture(SignPSBT)
	bad := [][]string{nil, {}, {"namecoin"}, {"sign-psbt"}, append(append([]string(nil), base...), "extra"), append(append([]string(nil), base...), "--json"), append(append([]string(nil), base...), "--unknown", "1"), append(append([]string(nil), base...), "--group", "fixture/recovery@1")}
	for _, mode := range []Mode{SignPSBT, Reconcile, InitializeJournal} {
		a := argvFixture(mode)
		// Removing each required option and using equals-style are separate plants.
		for i := 2; i < len(a); i += 2 {
			bad = append(bad, append(append([]string(nil), a...), a[i], a[i+1]))
			b := append([]string(nil), a[:i]...)
			b = append(b, a[i+2:]...)
			bad = append(bad, b)
			b = append([]string(nil), a[:i]...)
			b = append(b, a[i]+"="+a[i+1])
			b = append(b, a[i+2:]...)
			bad = append(bad, b)
		}
		bad = append(bad, append([]string{"other", string(mode)}, a[2:]...), append([]string{"namecoin", "unsupported"}, a[2:]...))
		for _, seconds := range []string{"0", "3601", "01", "+1", "-1", "1.0", "1e0", " 1", "1 ", "999999999999999999999999", ""} {
			bad = append(bad, replaceArg(a, "--timeout-seconds", seconds))
		}
		bad = append(bad, replaceArg(a, "--process-contract", "2"), replaceArg(a, "--profile-sha256", strings.Repeat("A", 64)), replaceArg(a, "--profile-sha256", strings.Repeat("a", 63)))
		for _, p := range []string{"relative", "/a/../b", "/a//b", "/a/", "/", "/a\x00b"} {
			bad = append(bad, replaceArg(a, "--profile", p))
		}
		for _, g := range []string{"X/recovery@1", "fixture/recovery@0", "fixture/recovery@01", "fixture/namecoin@1", strings.Repeat("a", 41) + "/recovery@1"} {
			bad = append(bad, replaceArg(a, "--group", g))
		}
	}
	for _, mode := range []Mode{Reconcile, InitializeJournal} {
		bad = append(bad, append(argvFixture(mode), "--reveal-values-pin", "/public/reveal.json"))
	}
	for _, pair := range [][]string{{"--output", "/public/out"}, {"--request", "/public/request"}, {"--request-sha256", strings.Repeat("a", 64)}, {"--query", "/public/query"}} {
		bad = append(bad, append(argvFixture(InitializeJournal), pair...))
	}
	bad = append(bad, append(argvFixture(SignPSBT), "--query", "/public/query"), append(argvFixture(Reconcile), "--request", "/public/request"), append(argvFixture(SignPSBT), "--adoption-plan-sha256", strings.Repeat("a", 64)))
	want := "{\"schema\":\"keyvault-namecoin-psbt-error/2\",\"code\":\"invalid_request\",\"status\":\"REFUSED\",\"message\":\"Namecoin signing invalid_request.\"}\n"
	for i, a := range bad {
		got, err := ParseArgs(a)
		f, ok := err.(namecoinwire.Failure)
		if !ok || f.Code() != namecoinwire.InvalidRequest || f.Exit() != 2 || f.Status() != "REFUSED" || string(f.Bytes()) != want || !reflect.DeepEqual(got, Args{}) {
			t.Fatalf("case %d: %+v %v", i, got, err)
		}
	}
}
