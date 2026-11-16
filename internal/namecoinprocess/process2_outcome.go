package namecoinprocess

import (
	"bytes"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

type process2Evidence struct {
	context                     RunnerContext
	invocation                  Process2Invocation
	binding                     [32]byte
	frameBytes                  int
	frameLength                 int
	writeErr                    bool
	writerCloseOK               bool
	writerJoined                bool
	stdinCloseOK                bool
	childEndsCloseOK            bool
	readerCloseOK               bool
	outputCloseOK               bool
	status                      []byte
	statusEOF                   bool
	statusOverflow              bool
	stdout                      []byte
	stdoutEOF                   bool
	stdoutOverflow              bool
	stderrEOF                   bool
	stderrHadBytes              bool
	result                      []byte
	resultReadbackOK            bool
	waitDone                    bool
	waitExit                    int
	waitErr                     bool
	admitted                    bool
	contextCancelledDuringInput bool
	closeObservations           []process2CloseObservation
}

func unknownProcess2Outcome() Outcome {
	return refusedOutcome(namecoinwire.NewFailure(namecoinwire.OutcomeUnknown, true))
}

func invalidProcess2RequestOutcome() Outcome {
	return refusedOutcome(namecoinwire.NewFailure(namecoinwire.InvalidRequest, false))
}

func process2Outcome(e process2Evidence) Outcome {
	if e.contextCancelledDuringInput || e.context.Mode != RunnerSign || len(e.invocation.argv) == 0 || !e.admitted ||
		e.frameLength < 14+Process2MinMetadataBytes+Process2MinEnvelopeBytes || e.frameLength > Process2MaxCustodyFrameBytes ||
		e.frameBytes != e.frameLength || e.writeErr || !e.writerCloseOK || !e.writerJoined ||
		!e.stdinCloseOK || !e.childEndsCloseOK || !e.readerCloseOK || !e.outputCloseOK ||
		!e.statusEOF || e.statusOverflow || !e.stdoutEOF || e.stdoutOverflow || !e.stderrEOF || e.stderrHadBytes ||
		!e.resultReadbackOK || !e.waitDone || e.waitErr || e.waitExit != 0 {
		return unknownProcess2Outcome()
	}
	if len(e.closeObservations) != 11 {
		return unknownProcess2Outcome()
	}
	for _, observation := range e.closeObservations {
		if !observation.attempted || !observation.ok {
			return unknownProcess2Outcome()
		}
	}
	if ValidateProcess2SuccessStatus(e.status, e.binding, e.result) != nil ||
		len(e.stdout) > 512 || namecoinwire.VerifyAcknowledgement(e.stdout, e.result) != nil {
		return unknownProcess2Outcome()
	}
	outcome, err := verifyProcessResult(e.context, e.stdout, e.result)
	if err != nil || !outcome.Success() || !bytes.Equal(outcome.Result(), e.result) {
		return unknownProcess2Outcome()
	}
	return outcome
}
