package main

import (
	"bytes"
	"flag"
	"io"
	"testing"
)

const fixtureOwnerPrincipal = "@fixture-owner:example.invalid"
const fixtureOwnerService = "north"

func withFixtureOwnerArgs(args []string) []string {
	return append(append([]string{}, args...), "--owner-mxid", fixtureOwnerPrincipal, "--owner-key", fixtureOwnerService+"/grants-owner-v1", "--owner-key-version", "1")
}

// Configured owners produce distinct exact addresses. Required arguments have
// no implicit principal, service, purpose or newest-generation selection.
func TestOwnerFlagsExplicitConfiguration(t *testing.T) {
	for _, principal := range []string{"@owner:example.invalid", "@other:example.invalid"} {
		f := flag.NewFlagSet("owner", flag.ContinueOnError)
		f.SetOutput(io.Discard)
		o := addOwnerFlags(f)
		if err := f.Parse([]string{"--owner-mxid", principal, "--owner-key", "north/grants-owner-v1", "--owner-key-version", "3"}); err != nil {
			t.Fatal(err)
		}
		c, err := o.config()
		if err != nil || c.Principal != principal || c.Address.Service != "north" || c.Address.Version != 3 {
			t.Fatal("explicit owner flags changed")
		}
	}
	for _, args := range [][]string{
		nil, {"--owner-mxid", "@owner:example.invalid"},
		{"--owner-mxid", "@owner:example.invalid", "--owner-key", "north/grants-owner-v1"},
		{"--owner-mxid", "@owner:example.invalid", "--owner-key", "north/grants-owner-v1", "--owner-key-version", "0"},
		{"--owner-mxid", "@owner:example.invalid", "--owner-key", "north/grants-owner-v1", "--owner-key-version", "01"},
		{"--owner-mxid", "@owner:example.invalid", "--owner-key", "north/grants-owner-v2", "--owner-key-version", "1"},
		{"--owner-mxid", "@owner:example.invalid", "--owner-key", "north/grants-owner-v1", "--owner-key-version", "1", "--owner-mxid", "@other:example.invalid"},
	} {
		f := flag.NewFlagSet("owner", flag.ContinueOnError)
		f.SetOutput(io.Discard)
		o := addOwnerFlags(f)
		if err := f.Parse(args); err == nil {
			if _, err := o.config(); err == nil {
				t.Fatal("missing/invalid/duplicate owner config accepted")
			}
		}
	}
}

// Issuance rejects a missing/unsupported owner before reading the payload or
// constructing the fake custody manager. The existing valid issue fixture is
// the adjacent positive control in TestIssueCLI.
func TestIssueMissingOwnerBeforePayloadAndCustody(t *testing.T) {
	args, _, store := issueCLIFixture(t)
	base := append([]string{}, args[:len(args)-6]...)
	for _, extra := range [][]string{nil, {"--owner-mxid", fixtureOwnerPrincipal}, {"--owner-mxid", fixtureOwnerPrincipal, "--owner-key", fixtureOwnerService + "/grants-owner-v2", "--owner-key-version", "1"}} {
		var out, diagnostic bytes.Buffer
		if code := run(append(append([]string{}, base...), extra...), mustNotRead{}, &out, &diagnostic); code != 2 || out.Len() != 0 || store.factories != 0 || store.signs != 0 {
			t.Fatal("invalid owner reached payload/custody")
		}
	}
}
