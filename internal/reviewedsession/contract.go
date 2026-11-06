package reviewedsession

import "errors"

const (
	inputMax    = 16 * 1024
	readyMax    = 1024 * 1024
	commitMax   = 128 * 1024
	cancelMax   = 1024
	snapshotMax = 512 * 1024
	reviewMax   = 24576
	receiptMax  = 128 * 1024
)

var (
	errSchema      = errors.New("reviewed-session-schema")
	errFrame       = errors.New("reviewed-session-frame")
	errDisplay     = errors.New("reviewed-session-display")
	errBinding     = errors.New("reviewed-session-binding")
	errUnavailable = errors.New("reviewed-session-unavailable: OI-03 through OI-09 require actual custody/admission inputs")
)

type profile string

const (
	repository      profile = "repository-1"
	localRepository profile = "local-repository-1"
	a2aCertificate  profile = "a2a-certificate-1"
	muGrantMac      profile = "mu-grant-mac-1"
)

func (p profile) included() bool {
	switch p {
	case repository, localRepository, a2aCertificate, muGrantMac:
		return true
	}
	return false
}

// A schema name and caller-selected public pins cannot establish protected
// provenance. No code path in this source tranche admits a live workflow.
func workflowAvailability() error { return errUnavailable }
