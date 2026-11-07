package grants

import (
	"bytes"
	"time"

	"github.com/relux-works/swarma-envelope/verifier"
)

// Internal candidate metadata, never a second journal or an effect permit.
// The current message and direct-grant profiles produce IDs and watermark;
// refuse unsupported future plan members rather than silently dropping them.
type linuxVerificationPlan struct {
	message, grant verifier.Plan
	originals      map[string][]byte
	watermark      time.Time
}

func linuxPlanOriginals(message, grant verifier.Plan, request, grantWire []byte) (linuxVerificationPlan, error) {
	var out linuxVerificationPlan
	requestID, err := muRecordID(request, "message/1")
	if err != nil {
		return out, ErrMUState
	}
	grantID, err := muRecordID(grantWire, "grant/1")
	if err != nil {
		return out, ErrMUState
	}
	out.originals = map[string][]byte{}
	for _, p := range []verifier.Plan{message, grant} {
		if len(p.IDs) == 0 || len(p.IDs) > linuxProviderMaxRecords || p.SnapshotJournal != nil || p.Reanchor != nil || p.ActionID != "" {
			return linuxVerificationPlan{}, ErrMUState
		}
		at, err := time.Parse("2006-01-02T15:04:05Z", p.Watermark)
		if err != nil {
			return linuxVerificationPlan{}, ErrMUState
		}
		if at.After(out.watermark) {
			out.watermark = at
		}
		for _, id := range p.IDs {
			var original []byte
			switch id {
			case requestID:
				original = request
			case grantID:
				original = grantWire
			default:
				return linuxVerificationPlan{}, ErrMUState
			}
			if prior, ok := out.originals[id]; ok && !bytes.Equal(prior, original) {
				return linuxVerificationPlan{}, ErrMUState
			}
			out.originals[id] = bytes.Clone(original)
		}
	}
	if _, ok := out.originals[requestID]; !ok {
		return linuxVerificationPlan{}, ErrMUState
	}
	if _, ok := out.originals[grantID]; !ok {
		return linuxVerificationPlan{}, ErrMUState
	}
	message.IDs = append([]string(nil), message.IDs...)
	grant.IDs = append([]string(nil), grant.IDs...)
	out.message, out.grant = message, grant
	return out, nil
}
