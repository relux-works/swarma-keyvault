package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/codesignpolicy"
	"github.com/relux-works/swarma-keyvault/internal/rootqualification"
)

func rootQualificationChildArgs49() []string {
	return []string{"--json", "root-grants", "qualify-storage", "--case", "child-read"}
}
func rootQualificationNostrArgs49() []string {
	return []string{"--json", "nostr", "sign", "fixture/nostr", "--version", "1", "--digest", strings.Repeat("0", 64)}
}

// Claim: only exact foreign linker1+closed argv admits the child. The historical
// Nostr zero-digest predicate stays admitted EXACTLY, never as a child route.
// Limit: pure arguments/role policy only; no signing/native/read is performed.
func TestRootQualificationChild49Admission(t *testing.T) {
	child, nostr := rootQualificationChildArgs49(), rootQualificationNostrArgs49()
	if !qualificationInvocation(child) || !qualificationInvocation(nostr) || rootQualificationChildInvocation(nostr) {
		t.Fatal("positive closed child or historical Nostr control refused")
	}
	for _, mark := range []string{"", "1", "0", "2", "true", "01", " 1", "1\n", "1\x00"} {
		if rootQualificationChildAdmitted(mark, child) != (mark == "1") || rootQualificationChildAdmitted(mark, nostr) {
			t.Fatal("ordinary/unknown linker state acquired foreign child role")
		}
	}
	id, err := codesignpolicy.Identifier(codesignpolicy.Qualification)
	if err != nil || id != "works.relux.keyvault.qualification-foreign" || codesignpolicy.Qualification == codesignpolicy.Vault || codesignpolicy.Qualification == codesignpolicy.Helper {
		t.Fatal("fixed distinct foreign certificate role changed")
	}
}

// Claim: aliases, added/smuggled/repeated flags, receipt/path/ref/provider/role
// inputs, parent operations and modified legacy Nostr inputs are NOT the child.
// Limit: no valid child run is invoked here; no C/native override exists.
func TestRootQualificationChild49ClosedArguments(t *testing.T) {
	valid := rootQualificationChildArgs49()
	cases := [][]string{
		nil, {}, {"root-grants", "qualify-storage", "--case", "child-read"},
		{"-json", "root-grants", "qualify-storage", "--case", "child-read"},
		{"--json=true", "root-grants", "qualify-storage", "--case", "child-read"},
		{"--json", "root-grants", "qualify-storage", "--case=child-read"},
		{"--json", "root-grants", "qualify-storage", "--case", "child-read\x00"},
		{"--json", "root-grants", "qualify-storage", "--case", "child-read\n"},
		{"--json", "root-grants", "qualify-storage", "--case", "create-project"},
		{"--json", "root-grants", "qualify-storage", "--case", "read-project"},
		{"--json", "root-grants", "qualify-storage", "--case", "foreign-read"},
		{"--json", "root-grants", "qualify-storage", "--case", "helper-read"},
		{"--json", "root-grants", "qualify-storage", "--case", "cleanup-created"},
		{"--json", "root-grants", "qualify-storage", "--", "child-read"},
	}
	for _, extra := range [][]string{
		{"--json"}, {"--case", "child-read"}, {"--receipt-sha256", strings.Repeat("a", 64)},
		{"--reference", "AQID"}, {"--reference-file", "public-fixture"}, {"--stdin"},
		{"--namespace", rootqualification.Namespace}, {"--service", rootqualification.Namespace},
		{"--account", rootqualification.Account}, {"--role", "qualification"}, {"--provider", "native"}, {"--"},
	} {
		cases = append(cases, append(append([]string{}, valid...), extra...))
	}
	for _, args := range cases {
		if reflect.DeepEqual(args, valid) {
			t.Fatal("no-op argv negative")
		}
		if rootQualificationChildInvocation(args) || rootQualificationChildAdmitted("1", args) || qualificationInvocation(args) {
			t.Fatal("alternate/extended foreign invocation admitted")
		}
	}
	for _, field := range []int{0, 1, 2, 3, 4, 5, 6, 7} {
		args := rootQualificationNostrArgs49()
		args[field] += "different"
		if reflect.DeepEqual(args, rootQualificationNostrArgs49()) {
			t.Fatal("no-op Nostr negative")
		}
		if qualificationInvocation(args) {
			t.Fatal("legacy fixed predicate broadened")
		}
	}
}

// Claim: real run gates ordinary and unknown-linker child attempts and foreign
// nonallowlisted argv before stdin/native, preserving the old usage contract.
// Only negative routes execute; valid child/native entry and watchdog are NEVER
// called by a software test. Limit: no actual signed foreign executable here.
func TestRootQualificationChild49RunRefusalGate(t *testing.T) {
	prior := recoveryQualificationOnly
	t.Cleanup(func() { recoveryQualificationOnly = prior })
	for _, mark := range []string{"", "0", "2", "true", "01", " 1"} {
		recoveryQualificationOnly = mark
		var out, diag bytes.Buffer
		if code := run(rootQualificationChildArgs49(), &out, &diag); code != exitUsage || diag.Len() != 0 {
			t.Fatal("ordinary/unknown linker attempt advanced beyond usage gate")
		}
		if strings.Contains(out.String(), `"result":"access-refused"`) || strings.Contains(out.String(), `"result":"unexpected-access"`) {
			t.Fatal("wrong role returned a native control result")
		}
	}
	recoveryQualificationOnly = "1"
	for _, args := range [][]string{
		append(rootQualificationChildArgs49(), "--reference-file", "public-fixture"),
		append(rootQualificationChildArgs49(), "--case", "child-read"),
		{"--json", "root-grants", "qualify-storage", "--case", "create-project"},
		{"--json", "recovery", "restore"},
	} {
		var out, diag bytes.Buffer
		if code := run(args, &out, &diag); code != exitUsage || diag.Len() != 0 || !strings.Contains(out.String(), "public qualification executable admits only") {
			t.Fatal("foreign extended/private route escaped original linker gate")
		}
	}
}

func rootQualificationLiteral49() []byte {
	return []byte(`{"schema":"keyvault-root-acl-qualification/1","namespace":"works.relux.mac-keyvault.root-acl-qualification.v1","account":"public-marker@1","item_class":"generic-password","persistent_reference":"AQID","receipt_sha256":"` + strings.Repeat("a", 64) + `"}`)
}
func rootQualificationFrame49(body []byte) []byte {
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out[:4], uint32(len(body)))
	copy(out[4:], body)
	return out
}

// Claim: actual codec accepts the contract's literal public request and rejects
// wrong namespace/account/class/ref source, malformed frame and trailing input.
// The codec's own detailed controls are the independent shared contract source;
// this is CLI-boundary test source, not a second parser or native admission.
func TestRootQualificationChild49ClosedWire(t *testing.T) {
	body := rootQualificationLiteral49()
	valid := rootQualificationFrame49(body)
	request, err := rootqualification.ReadRequest(bytes.NewReader(valid))
	if err != nil {
		t.Fatal("literal valid protocol refused")
	}
	defer request.Clear()
	if !bytes.Equal(request.Reference(), []byte{1, 2, 3}) || request.ReceiptSHA256() != strings.Repeat("a", 64) {
		t.Fatal("literal valid protocol fields changed")
	}
	changes := []struct{ name, from, to string }{
		{"root-namespace", rootqualification.Namespace, "works.relux.mac-keyvault.root-grants.v1"},
		{"account", `"account":"public-marker@1"`, `"account":"public-marker@2"`},
		{"class", `"item_class":"generic-password"`, `"item_class":"key"`},
		{"ref-source", `"persistent_reference":"AQID"`, `"persistent_reference":"AQID","reference_file":"public-fixture"`},
		{"ref-path", `"persistent_reference":"AQID"`, `"persistent_reference":"@public-fixture"`},
		{"alias", `"namespace":`, `"Namespace":`},
		{"duplicate", `"account":`, `"account":"public-marker@1","account":`},
		{"empty-ref", `"persistent_reference":"AQID"`, `"persistent_reference":""`},
		{"noncanonical-ref", `"persistent_reference":"AQID"`, `"persistent_reference":"AR=="`},
		{"uppercase-digest", strings.Repeat("a", 64), strings.Repeat("A", 64)},
		{"oversize-ref", `"persistent_reference":"AQID"`, `"persistent_reference":"` + base64.StdEncoding.EncodeToString(make([]byte, rootqualification.MaxReference+1)) + `"`},
	}
	for _, tc := range changes {
		t.Run(tc.name, func(t *testing.T) {
			if bytes.Count(body, []byte(tc.from)) != 1 {
				t.Fatal("mutation is missing/ambiguous")
			}
			bad := bytes.Replace(body, []byte(tc.from), []byte(tc.to), 1)
			if bytes.Equal(bad, body) {
				t.Fatal("no-op wire negative")
			}
			got, err := rootqualification.ReadRequest(bytes.NewReader(rootQualificationFrame49(bad)))
			if !errors.Is(err, rootqualification.ErrProtocol) || len(got.Reference()) != 0 {
				t.Fatal("wrong wire/source admitted")
			}
		})
	}
	frames := [][]byte{nil, valid[:3], valid[:len(valid)-1], append(bytes.Clone(valid), 0), append(bytes.Clone(valid), valid...), rootQualificationFrame49([]byte("null")), rootQualificationFrame49(append(bytes.Clone(body), '\n'))}
	for _, n := range []uint32{0, rootqualification.MaxRequest + 1, ^uint32(0)} {
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], n)
		frames = append(frames, bytes.Clone(h[:]))
	}
	for _, bad := range frames {
		if bytes.Equal(bad, valid) {
			t.Fatal("no-op frame negative")
		}
		got, err := rootqualification.ReadRequest(bytes.NewReader(bad))
		if !errors.Is(err, rootqualification.ErrProtocol) || len(got.Reference()) != 0 {
			t.Fatal("malformed/trailing frame admitted")
		}
	}
}

type rootQualificationFailureWriter49 struct{ zero bool }

func (w rootQualificationFailureWriter49) Write([]byte) (int, error) {
	if w.zero {
		return 0, nil
	}
	return 0, errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
}

// Claim: pure formatting emits only the exact finite JSON+LF, with failures
// nonzero and no diagnostics. Result values here do NOT simulate native reads.
func TestRootQualificationChild49FiniteOutput(t *testing.T) {
	for _, tc := range []struct {
		result rootqualification.Result
		name   string
	}{{rootqualification.AccessRefused, "access-refused"}, {rootqualification.UnexpectedAccess, "unexpected-access"}, {rootqualification.Unqualified, "unqualified"}} {
		var out bytes.Buffer
		if code := rootQualificationChildResponse(&out, tc.result); code != exitOK || out.String() != `{"schema":"keyvault-root-acl-qualification/1","result":"`+tc.name+`"}`+"\n" {
			t.Fatal("finite canonical output changed")
		}
		for _, writer := range []io.Writer{rootQualificationFailureWriter49{}, rootQualificationFailureWriter49{zero: true}} {
			if code := rootQualificationChildResponse(writer, tc.result); code != exitFailure {
				t.Fatal("write failure reported valid protocol")
			}
		}
	}
	for _, bad := range []rootqualification.Result{0, 4, 255} {
		var out bytes.Buffer
		if code := rootQualificationChildResponse(&out, bad); code != exitFailure || out.Len() != 0 {
			t.Fatal("unknown result produced output")
		}
	}
}

// Claim: entry-relative deadline arithmetic is exact and not renewed by a
// phase. The real exit watchdog is checked as source ONLY below; no software
// test schedules os.Exit or waits30s, so this is not a runtime timeout proof.
func TestRootQualificationChild49Deadline(t *testing.T) {
	entered := time.Now()
	deadline := rootQualificationChildDeadline(entered)
	if rootQualificationChildLimit != 30*time.Second || deadline.Sub(entered) != 30*time.Second || !entered.Add(30*time.Second-time.Nanosecond).Before(deadline) || entered.Add(30*time.Second).Before(deadline) {
		t.Fatal("absolute entry deadline changed")
	}
	if rootQualificationChildDeadline(entered) != deadline {
		t.Fatal("deadline renewed")
	}
}

// Source boundary witness: the actual production bridge uses fixed foreign
// role and only stdin; timer/Exit is reachable only from actual main. No live
// native/code/Keychain/TTY or watchdog execution is made by this test.
func TestRootQualificationChild49ProductionBoundary(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	mainSource, child := read("main.go"), read("root_qualification_child.go")
	for _, s := range []string{"entered := time.Now()", "rootQualificationChildAdmitted(recoveryQualificationOnly, os.Args[1:])", "os.Exit(rootQualificationChildProcess(entered))", "rootQualificationChildInvocation(args)", "return runRootQualificationChild(stdout)"} {
		if !strings.Contains(mainSource, s) {
			t.Fatal("actual main/run admission absent")
		}
	}
	if strings.Count(mainSource, "rootQualificationChildProcess(") != 1 {
		t.Fatal("watchdog has another main route")
	}
	if strings.Contains(child, "timer.Stop(") {
		t.Fatal("process watchdog disarmed before actual main exit")
	}
	for _, s := range []string{"rootqualification.ReadRequest(os.Stdin)", "keyvault.RootQualificationMarkerRead(codesignpolicy.Qualification, request)", "result = rootqualification.Unqualified", "rootqualification.WriteResponse(stdout, result)", "time.AfterFunc(time.Until(deadline), func() { os.Exit(exitFailure) })"} {
		if strings.Count(child, s) != 1 {
			t.Fatal("fixed real protocol/native/watchdog source absent or duplicated")
		}
	}
	if strings.Index(child, "rootqualification.ReadRequest(os.Stdin)") > strings.Index(child, "keyvault.RootQualificationMarkerRead(") {
		t.Fatal("native call before closed request")
	}
	entry := child[strings.Index(child, "func runRootQualificationChild("):]
	if strings.Index(entry, `if recoveryQualificationOnly != "1"`) > strings.Index(entry, "rootqualification.ReadRequest(os.Stdin)") || !strings.Contains(entry, `if recoveryQualificationOnly != "1"`) {
		t.Fatal("ordinary vault can enter foreign protocol input")
	}
	// A stat failure or a non-FIFO descriptor must return before any protocol
	// read/native query; this checks actual stdin wiring, not a fake provider.
	pipeRequest := `info, err := os.Stdin.Stat()
	if err != nil || !rootQualificationChildPipeMode(info.Mode()) {
		return exitFailure
	}
	request, err := rootqualification.ReadRequest(os.Stdin)`
	if !strings.Contains(entry, pipeRequest) || strings.Count(entry, "os.Stdin.Stat()") != 1 {
		t.Fatal("actual stdin FIFO stat gate absent or after protocol input")
	}
	// Claim: the actual successful parse immediately installs deferred owned
	// request cleanup before native use; Go defer covers every later return,
	// including native refusal and response failure. This lexical source check
	// does not execute native code or establish runtime/secret-memory erasure.
	ownedRequest := `request, err := rootqualification.ReadRequest(os.Stdin)
	if err != nil {
		return exitFailure // protocol fatal: no OS/parser/reference diagnostics
	}
	defer request.Clear()
	result, err := keyvault.RootQualificationMarkerRead(codesignpolicy.Qualification, request)`
	if !strings.Contains(entry, ownedRequest) || strings.Count(entry, "defer request.Clear()") != 1 {
		t.Fatal("owned request cleanup is not deferred immediately after successful parse before native use")
	}
	for _, s := range []string{"os.Getenv(", "os.Open(", "exec.Command(", "newBackend", "vaultLock", "flag.NewFlagSet", "codesignpolicy.Vault, request", "codesignpolicy.Helper, request", "func init(", "fmt."} {
		if strings.Contains(child, s) {
			t.Fatal("alternate/native fake/input path introduced")
		}
	}
	legacy := `return len(args) == 8 && args[0] == "--json" && args[1] == "nostr" && args[2] == "sign" &&
		strings.HasSuffix(args[3], "/nostr") && args[4] == "--version" && args[5] == "1" &&
		args[6] == "--digest" && args[7] == strings.Repeat("0", 64)`
	if !strings.Contains(mainSource, legacy) {
		t.Fatal("historical fixed Nostr predicate changed")
	}
}

// Claim: an actual isolated anonymous pipe has the admitted FIFO descriptor
// type and carries the unchanged literal canonical request through the actual
// codec. This does not run the foreign child/native call, prove endpoint
// provenance or establish signature/ACL qualification.
func TestRootQualificationChild51PipeMetadata(t *testing.T) {
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal("public fixture pipe unavailable")
	}
	defer rd.Close()
	defer wr.Close()
	for _, f := range []*os.File{rd, wr} {
		info, err := f.Stat()
		if err != nil || !rootQualificationChildPipeMode(info.Mode()) {
			t.Fatal("actual anonymous pipe metadata refused")
		}
	}
	frame := rootQualificationFrame49(rootQualificationLiteral49())
	if len(frame) > 512 {
		t.Fatal("public fixture exceeds minimum pipe capacity")
	}
	// The fixed small public frame fits the pipe; no subprocess or alternate
	// production input API is introduced for this software fixture.
	if n, err := wr.Write(frame); err != nil || n != len(frame) {
		t.Fatal("public fixture pipe write failed")
	}
	if err := wr.Close(); err != nil {
		t.Fatal("public fixture pipe EOF failed")
	}
	request, err := rootqualification.ReadRequest(rd)
	if err != nil {
		t.Fatal("valid parent pipe request refused")
	}
	defer request.Clear()
	reference := request.Reference()
	defer clear(reference)
	if !bytes.Equal(reference, []byte{1, 2, 3}) || request.ReceiptSHA256() != strings.Repeat("a", 64) {
		t.Fatal("valid parent pipe request changed")
	}
}

// Claim: actual isolated regular-file/directory descriptor metadata is not
// admitted, and a closed owned descriptor really fails Stat. Only metadata is
// inspected; no owner stdin, terminal, native operation or watchdog is used.
func TestRootQualificationChild51NonPipeMetadata(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "public-marker-request-")
	if err != nil {
		t.Fatal("public fixture regular file unavailable")
	}
	defer file.Close()
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal("public fixture directory unavailable")
	}
	defer dir.Close()
	for _, f := range []*os.File{file, dir} {
		info, err := f.Stat()
		if err != nil || rootQualificationChildPipeMode(info.Mode()) {
			t.Fatal("non-pipe fixture metadata admitted or unavailable")
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal("public fixture close failed")
	}
	if _, err := file.Stat(); err == nil {
		t.Fatal("closed descriptor did not exercise Stat failure")
	}
}

// Claim: the allowlist admits the FIFO type with legitimate permission bits
// and rejects every other modeled type, including mixed/unknown type bits.
// Pure modes do not inspect a real terminal/socket or prove endpoint origin.
func TestRootQualificationChild51PipeModes(t *testing.T) {
	for _, mode := range []os.FileMode{os.ModeNamedPipe, os.ModeNamedPipe | 0600} {
		if !rootQualificationChildPipeMode(mode) {
			t.Fatal("valid FIFO mode refused")
		}
	}
	for _, mode := range []os.FileMode{0, 0600, os.ModeDir, os.ModeDevice, os.ModeDevice | os.ModeCharDevice, os.ModeSocket, os.ModeSymlink, os.ModeIrregular, os.ModeNamedPipe | os.ModeSocket, os.ModeNamedPipe | os.ModeDir} {
		if mode.Type() == os.ModeNamedPipe {
			t.Fatal("no-op forbidden type fixture")
		}
		if rootQualificationChildPipeMode(mode) {
			t.Fatal("non-FIFO or unknown descriptor type admitted")
		}
	}
}
