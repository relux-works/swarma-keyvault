package main

import (
	"context"
	"encoding/json"
	"io"

	"github.com/relux-works/swarma-keyvault/internal/rootqualification"
)

// rootQualificationDiagnosticSchema versions the one public stderr line a failed
// native create prints. The line names the first failing native step and its
// Security OSStatus; it never carries item data, a path or a reference, and it is
// not part of the stdout result or of any receipt.
const rootQualificationDiagnosticSchema = "keyvault-root-acl-qualification-diagnostic/1"

type rootQualificationDiagnosticLine struct {
	Schema    string `json:"schema"`
	Case      string `json:"case"`
	Stage     int    `json:"stage"`
	StageName string `json:"stage_name"`
	OSStatus  int32  `json:"os_status"`
}

// writeRootQualificationDiagnostic prints one line when the native create did not
// succeed and named a reported stage. A write failure is ignored on purpose: the
// diagnostic must never change the result, the receipt or the exit code.
func writeRootQualificationDiagnostic(w io.Writer, operation string, created rootqualification.NativeCreation) {
	if w == nil || created.Outcome == rootqualification.CreationReadback || !created.Diagnostic.Reported() {
		return
	}
	name, _ := created.Diagnostic.Stage.Name()
	raw, err := json.Marshal(rootQualificationDiagnosticLine{
		Schema: rootQualificationDiagnosticSchema, Case: operation,
		Stage: int(created.Diagnostic.Stage), StageName: name, OSStatus: created.Diagnostic.OSStatus,
	})
	if err != nil {
		return
	}
	_, _ = w.Write(append(raw, '\n'))
}

// rootQualificationPublisher is the receipt side of a creation. The reservation
// implements it; a test supplies a fake so the post-native logic runs without a
// Keychain or a receipt directory.
type rootQualificationPublisher interface {
	Publish(rootqualification.Candidate, rootqualification.NativeCreation) (rootqualification.Publication, error)
}

// finishRootQualificationCreate is everything after the native create call: the
// diagnostic line (stderr only), the deadline downgrade, publication and the
// result triple. The triple does not depend on the diagnostic.
func finishRootQualificationCreate(ctx context.Context, publisher rootQualificationPublisher, candidate rootqualification.Candidate,
	created rootqualification.NativeCreation, nativeErr error, diagnostic io.Writer) (string, string, int) {
	defer clear(created.Reference)
	writeRootQualificationDiagnostic(diagnostic, "create-project", created)
	if ctx.Err() != nil && created.Outcome != rootqualification.CreationRefused {
		created.Outcome = rootqualification.CreationUnknown
	}
	publication, publishErr := publisher.Publish(candidate, created)
	if publishErr != nil {
		return "unknown", "", exitFailure
	}
	if nativeErr == nil && publication.State == "created" {
		return "created", publication.SHA256, exitOK
	}
	if publication.State == "refused" {
		return "refused", publication.SHA256, exitRefused
	}
	return "unknown", publication.SHA256, exitFailure
}
