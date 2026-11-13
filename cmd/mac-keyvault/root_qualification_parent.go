package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/codesignpolicy"
	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/rootqualification"
)

const rootQualificationParentLimit = 30 * time.Second
const rootQualificationReapGrace = 2 * time.Second

func rootQualificationParentInvocation(args []string) bool {
	_, err := parseRootQualificationArguments(args)
	return err == nil
}

type rootQualificationParentResponse struct {
	Schema        string `json:"schema"`
	Case          string `json:"case"`
	Result        string `json:"result"`
	ReceiptSHA256 string `json:"receipt_sha256"`
}

func writeRootQualificationParent(w io.Writer, operation, result, digest string, exit int) int {
	raw, err := json.Marshal(rootQualificationParentResponse{"keyvault-root-acl-qualification-result/1", operation, result, digest})
	if err != nil {
		return exitFailure
	}
	raw = append(raw, '\n')
	for len(raw) > 0 {
		n, err := w.Write(raw)
		if err != nil || n < 1 || n > len(raw) {
			return exitFailure
		}
		raw = raw[n:]
	}
	return exit
}

// Only actual main enters the owning process. Its original action deadline
// includes code observation, file checks and native work; it is never renewed
// by a phase or child. A separate bounded grace permits TERM/reaping after
// expiry. Hard process exit also bounds a synchronous Security API hang.
func rootQualificationParentProcess(entered time.Time, args []string, stdout io.Writer) int {
	if recoveryQualificationOnly != "" {
		return exitRefused
	}
	parsed, err := parseRootQualificationArguments(args)
	if err != nil {
		return exitUsage
	}
	deadline := entered.Add(rootQualificationParentLimit)
	if !time.Now().Before(deadline) {
		return exitFailure
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	time.AfterFunc(time.Until(deadline.Add(2*rootQualificationReapGrace+time.Second)), func() { os.Exit(exitFailure) })
	result, digest, code := rootQualificationParentCase(ctx, parsed)
	if ctx.Err() != nil {
		code = exitFailure
		if result == "created" || result == "deleted" {
			result = "unknown"
		} else if result != "unknown" && result != "refused" {
			result = "unqualified"
		}
	}
	return writeRootQualificationParent(stdout, args[4], result, digest, code)
}

func rootQualificationParentCase(ctx context.Context, args rootQualificationArguments) (string, string, int) {
	if ctx == nil || ctx.Err() != nil {
		return "unqualified", "", exitFailure
	}
	observed, err := rootqualification.ObserveCandidate(ctx, rootQualificationSourceHead, rootQualificationSourceTree)
	if err != nil {
		return "unqualified", "", exitRefused
	}
	defer observed.Close()
	candidate, err := observed.Candidate()
	if err != nil || keyvault.RootQualificationCode(codesignpolicy.Vault, 0, candidate.Vault.CDHash) != nil || ctx.Err() != nil {
		return "unqualified", "", exitRefused
	}
	if args.operation == rootQualificationCreate {
		reservation, err := rootqualification.ReserveCreation()
		if err != nil {
			return "refused", "", exitRefused
		}
		defer reservation.Close()
		if ctx.Err() != nil {
			return "unqualified", "", exitFailure
		}
		created, nativeErr := keyvault.RootQualificationCreate(reservation)
		return finishRootQualificationCreate(ctx, reservation, candidate, created, nativeErr, rootQualificationDiagnosticOutput)
	}
	loaded, err := rootqualification.LoadCreatedReceipt(args.receiptSHA256, candidate)
	if err != nil {
		return "unqualified", args.receiptSHA256, exitRefused
	}
	defer loaded.Close()
	request, err := loaded.Request()
	if err != nil || ctx.Err() != nil {
		return "unqualified", args.receiptSHA256, exitFailure
	}
	defer request.Clear()
	projection, err := keyvault.RootQualificationSnapshot(request)
	if err != nil || loaded.CheckProjection(projection) != nil || ctx.Err() != nil {
		return "unqualified", args.receiptSHA256, exitRefused
	}
	switch args.operation {
	case rootQualificationRead:
		return "readback", args.receiptSHA256, exitOK
	case rootQualificationForeign, rootQualificationHelper:
		role := codesignpolicy.Qualification
		if args.operation == rootQualificationHelper {
			role = codesignpolicy.Helper
		}
		result, err := rootQualificationControl(ctx, observed, role, request)
		if err != nil || ctx.Err() != nil {
			return "unqualified", args.receiptSHA256, exitFailure
		}
		switch result {
		case rootqualification.AccessRefused:
			return "access-refused", args.receiptSHA256, exitOK
		case rootqualification.UnexpectedAccess:
			return "unexpected-access", args.receiptSHA256, exitRefused
		default:
			return "unqualified", args.receiptSHA256, exitFailure
		}
	case rootQualificationCleanup:
		// Entry is separately attended. The digest binds the reviewed record;
		// it does not claim that bytes supply owner consent or a new grant.
		cleanup, err := loaded.BeginCleanup()
		if err != nil {
			return "refused", args.receiptSHA256, exitRefused
		}
		if ctx.Err() != nil {
			return "unqualified", args.receiptSHA256, exitFailure
		}
		outcome, nativeErr := keyvault.RootQualificationDelete(cleanup)
		if ctx.Err() != nil && outcome != rootqualification.CleanupRefused {
			outcome = rootqualification.CleanupUnknown
		}
		publication, publishErr := cleanup.Publish(outcome)
		if publishErr != nil {
			return "unknown", "", exitFailure
		}
		if nativeErr == nil && outcome == rootqualification.CleanupDeleted {
			return "deleted", publication.SHA256, exitOK
		}
		if outcome == rootqualification.CleanupRefused {
			return "refused", publication.SHA256, exitRefused
		}
		return "unknown", publication.SHA256, exitFailure
	default:
		return "unqualified", "", exitUsage
	}
}
