package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/rootqualification"
)

type fakeQualificationPublisher struct {
	got         rootqualification.NativeCreation
	publication rootqualification.Publication
	err         error
}

func (f *fakeQualificationPublisher) Publish(_ rootqualification.Candidate, created rootqualification.NativeCreation) (rootqualification.Publication, error) {
	f.got = created
	return f.publication, f.err
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("stderr closed") }

// Claim: a failed native create prints exactly one public stderr line per
// failure, naming the stage id, its fixed name and the OSStatus, for every
// reported stage and for both non-success outcomes (refused and uncertain). The
// expected line is built here from the published schema, not by the code under
// test. Limit: the writer function; the native side is proven by the keyvault
// tests.
func TestDiagnosticLineIsOneFixedPublicLinePerFailure(t *testing.T) {
	for _, stage := range rootqualification.Stages() {
		name, _ := stage.Name()
		for _, outcome := range []rootqualification.CreationOutcome{rootqualification.CreationRefused, rootqualification.CreationUnknown} {
			var out bytes.Buffer
			created := rootqualification.NativeCreation{Outcome: outcome, Diagnostic: rootqualification.Diagnostic{Stage: stage, OSStatus: -25293}}
			writeRootQualificationDiagnostic(&out, "create-project", created)
			want := fmt.Sprintf(`{"schema":"keyvault-root-acl-qualification-diagnostic/1","case":"create-project","stage":%d,"stage_name":%q,"os_status":-25293}`+"\n", int(stage), name)
			if out.String() != want {
				t.Fatalf("stage %d outcome %d: got %q want %q", int(stage), outcome, out.String(), want)
			}
			if strings.Count(out.String(), "\n") != 1 {
				t.Fatalf("stage %d: not exactly one line", int(stage))
			}
		}
	}
}

// Claim (negative controls): nothing is printed on success, with no diagnostic,
// with a diagnostic that names no reported stage, or with a zero status; and an
// unusable writer neither panics nor reports. Beside the positive test above, a
// writer that always prints, or never prints, fails one of them.
func TestDiagnosticLineIsAbsentWhenThereIsNothingToReport(t *testing.T) {
	named := rootqualification.Diagnostic{Stage: rootqualification.StageAdd, OSStatus: -25299}
	cases := []struct {
		name    string
		created rootqualification.NativeCreation
	}{
		{"success with a stale diagnostic", rootqualification.NativeCreation{Outcome: rootqualification.CreationReadback, Diagnostic: named}},
		{"refusal without a diagnostic", rootqualification.NativeCreation{Outcome: rootqualification.CreationRefused}},
		{"unknown without a diagnostic", rootqualification.NativeCreation{Outcome: rootqualification.CreationUnknown}},
		{"reserved stage", rootqualification.NativeCreation{Outcome: rootqualification.CreationRefused, Diagnostic: rootqualification.Diagnostic{Stage: rootqualification.StageReserved, OSStatus: -1}}},
		{"internal projection stage", rootqualification.NativeCreation{Outcome: rootqualification.CreationRefused, Diagnostic: rootqualification.Diagnostic{Stage: 71, OSStatus: -1}}},
		{"named stage with zero status", rootqualification.NativeCreation{Outcome: rootqualification.CreationRefused, Diagnostic: rootqualification.Diagnostic{Stage: rootqualification.StageAdd}}},
	}
	for _, c := range cases {
		var out bytes.Buffer
		writeRootQualificationDiagnostic(&out, "create-project", c.created)
		if out.Len() != 0 {
			t.Errorf("%s: printed %q", c.name, out.String())
		}
	}
	writeRootQualificationDiagnostic(nil, "create-project", rootqualification.NativeCreation{Outcome: rootqualification.CreationRefused, Diagnostic: named})
	writeRootQualificationDiagnostic(failingWriter{}, "create-project", rootqualification.NativeCreation{Outcome: rootqualification.CreationRefused, Diagnostic: named})
}

// Claim: the stdout result of the create case is closed and byte-unchanged: the
// refused, uncertain and created results keep their exact schema, key order and
// terminator. The diagnostic never goes through this writer.
func TestStdoutResultSchemaIsByteUnchanged(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	for _, c := range []struct {
		result string
		exit   int
	}{{"refused", exitRefused}, {"unknown", exitFailure}, {"created", exitOK}} {
		var out bytes.Buffer
		if got := writeRootQualificationParent(&out, "create-project", c.result, digest, c.exit); got != c.exit {
			t.Fatalf("%s: exit %d", c.result, got)
		}
		want := `{"schema":"keyvault-root-acl-qualification-result/1","case":"create-project","result":"` + c.result + `","receipt_sha256":"` + digest + `"}` + "\n"
		if out.String() != want {
			t.Fatalf("%s: stdout changed: %q", c.result, out.String())
		}
	}
}

type finishRun struct {
	result, digest string
	code           int
	gotOutcome     rootqualification.CreationOutcome
}

// finishOnce runs the post-native step once and reports its result triple and the
// outcome the publisher received.
func finishOnce(ctx context.Context, outcome rootqualification.CreationOutcome, nativeErr error, state string, publishErr error,
	diag rootqualification.Diagnostic, writer io.Writer) finishRun {
	publisher := &fakeQualificationPublisher{publication: rootqualification.Publication{SHA256: strings.Repeat("c", 64), State: state}, err: publishErr}
	created := rootqualification.NativeCreation{Outcome: outcome, Reference: []byte{1, 2, 3}, Diagnostic: diag}
	result, digest, code := finishRootQualificationCreate(ctx, publisher, rootqualification.Candidate{}, created, nativeErr, writer)
	return finishRun{result, digest, code, publisher.got.Outcome}
}

// Claim: what happens after the native call does not depend on the diagnostic:
// for every combination of outcome, native error, publication state and publish
// error, the result triple is identical whether a diagnostic is present and
// printed, present with an unusable writer, or absent. The publisher receives the
// outcome the existing rules produce (a deadline downgrades an uncertain or
// created outcome to unknown, never a refusal). Positive controls: the three
// result words each occur.
func TestFinishCreateResultIsIndependentOfTheDiagnostic(t *testing.T) {
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	marked := rootqualification.Diagnostic{Stage: rootqualification.StageBindReleaseRequirementRead, OSStatus: -25293}
	seen := map[string]bool{}
	for _, ctx := range []context.Context{context.Background(), expired} {
		for _, outcome := range []rootqualification.CreationOutcome{rootqualification.CreationRefused, rootqualification.CreationReadback, rootqualification.CreationUnknown} {
			for _, nativeErr := range []error{nil, errors.New("native")} {
				for _, state := range []string{"created", "refused", "unknown"} {
					for _, publishErr := range []error{nil, errors.New("publish")} {
						var printed bytes.Buffer
						plain := finishOnce(ctx, outcome, nativeErr, state, publishErr, rootqualification.Diagnostic{}, nil)
						withLine := finishOnce(ctx, outcome, nativeErr, state, publishErr, marked, &printed)
						brokenWriter := finishOnce(ctx, outcome, nativeErr, state, publishErr, marked, failingWriter{})
						if plain != withLine || plain != brokenWriter {
							t.Fatalf("the diagnostic changed the result: %+v %+v %+v", plain, withLine, brokenWriter)
						}
						wantOutcome := outcome
						if ctx.Err() != nil && outcome != rootqualification.CreationRefused {
							wantOutcome = rootqualification.CreationUnknown
						}
						if plain.gotOutcome != wantOutcome {
							t.Fatalf("publisher outcome %d, the rules give %d", plain.gotOutcome, wantOutcome)
						}
						if wantPrinted := outcome != rootqualification.CreationReadback; (printed.Len() > 0) != wantPrinted {
							t.Fatalf("outcome %d: printed=%v want %v", outcome, printed.Len() > 0, wantPrinted)
						}
						seen[plain.result] = true
					}
				}
			}
		}
	}
	for _, word := range []string{"created", "refused", "unknown"} {
		if !seen[word] {
			t.Fatalf("result %q never occurred, the matrix does not exercise the mapping", word)
		}
	}
}

// Claim: the private reference bytes are cleared after the post-native step, as
// before, whatever the diagnostic says.
func TestFinishCreateClearsTheReference(t *testing.T) {
	ref := []byte{9, 9, 9}
	created := rootqualification.NativeCreation{Outcome: rootqualification.CreationReadback, Reference: ref,
		Diagnostic: rootqualification.Diagnostic{Stage: rootqualification.StageAdd, OSStatus: -1}}
	publisher := &fakeQualificationPublisher{publication: rootqualification.Publication{State: "created"}}
	finishRootQualificationCreate(context.Background(), publisher, rootqualification.Candidate{}, created, nil, nil)
	if !bytes.Equal(ref, []byte{0, 0, 0}) {
		t.Fatalf("reference not cleared: %v", ref)
	}
}
