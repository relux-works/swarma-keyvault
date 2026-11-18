//go:build darwin && cgo

package keyvault

import (
	"bytes"
	"errors"
	"testing"
)

// Claim: the Darwin caller returns bad_request for request cap+1 before helper
// admission or dispatch; limit: exact raw cap is checked through the shared
// bounded-payload predicate so this test never starts a private helper.
func TestAgentNostrCallRejectsOversizedRequestBeforeAdmission(t *testing.T) {
	if !agentNostrPrivateRequestWithinLimit(bytes.Repeat([]byte{'x'}, 32768)) {
		t.Fatal("exact raw request cap did not pass the bounded-payload layer")
	}
	_, err := agentNostrCall("unwrap-agent-nostr", bytes.Repeat([]byte{'x'}, 32769), AgentNostrPlaintextSize)
	var privateErr *AgentNostrPrivateError
	if !errors.As(err, &privateErr) || privateErr.Code != "bad_request" || privateErr.Dispatched {
		t.Fatal("request cap+1 reached helper admission or lost its pre-dispatch refusal")
	}
}
