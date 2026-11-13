package namecoinprocess

import (
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

type Mode string

const (
	SignPSBT          Mode = "sign-psbt"
	Reconcile         Mode = "reconcile"
	InitializeJournal Mode = "initialize-journal"
)

// Args is the public process/1 selection. Paths and hashes assert no native
// provenance; the trusted caller must independently retain its selections.
type Args struct {
	Mode                                                             Mode
	Group, Account                                                   string
	ProfilePath, ProfileSHA256, AccountPinPath                       string
	RequestPath, RequestSHA256, OutputPath, QueryPath, RevealPinPath string
	AdoptionPlanSHA256                                               string
	Timeout                                                          time.Duration
}

// ParseArgs consumes argv after the executable, including the namecoin prefix.
// It has no I/O, output or helper capability and admits no implicit defaults.
func ParseArgs(argv []string) (Args, error) {
	var a Args
	if len(argv) < 2 || argv[0] != "namecoin" || (len(argv)-2)%2 != 0 {
		return Args{}, namecoinwire.ErrInvalidRequest
	}
	a.Mode = Mode(argv[1])
	seen := make(map[string]bool)
	for i := 2; i < len(argv); i += 2 {
		flag, value := argv[i], argv[i+1]
		if seen[flag] || value == "" {
			return Args{}, namecoinwire.ErrInvalidRequest
		}
		seen[flag] = true
		switch flag {
		case "--process-contract":
			if value != "1" {
				return Args{}, namecoinwire.ErrInvalidRequest
			}
		case "--group":
			a.Group = value
		case "--account":
			a.Account = value
		case "--profile":
			a.ProfilePath = value
		case "--profile-sha256":
			a.ProfileSHA256 = value
		case "--account-pin":
			a.AccountPinPath = value
		case "--request":
			a.RequestPath = value
		case "--request-sha256":
			a.RequestSHA256 = value
		case "--output":
			a.OutputPath = value
		case "--query":
			a.QueryPath = value
		case "--reveal-values-pin":
			a.RevealPinPath = value
		case "--adoption-plan-sha256":
			a.AdoptionPlanSHA256 = value
		case "--timeout-seconds":
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > 3600 || strconv.Itoa(n) != value {
				return Args{}, namecoinwire.ErrInvalidRequest
			}
			a.Timeout = time.Duration(n) * time.Second
		default:
			return Args{}, namecoinwire.ErrInvalidRequest
		}
	}
	if !seen["--process-contract"] || a.validate() != nil {
		return Args{}, namecoinwire.ErrInvalidRequest
	}
	return a, nil
}

func (a Args) validate() error {
	bad := namecoinwire.ErrInvalidRequest
	if !identity(a.Group, "recovery") || !identity(a.Account, "namecoin") || !absoluteFile(a.ProfilePath) || !hashString(a.ProfileSHA256) || !absoluteFile(a.AccountPinPath) || a.Timeout < time.Second || a.Timeout > time.Hour || a.Timeout%time.Second != 0 {
		return bad
	}
	switch a.Mode {
	case SignPSBT:
		if !absoluteFile(a.RequestPath) || !hashString(a.RequestSHA256) || !absoluteFile(a.OutputPath) || a.QueryPath != "" || a.AdoptionPlanSHA256 != "" || a.RevealPinPath != "" && !absoluteFile(a.RevealPinPath) {
			return bad
		}
	case Reconcile:
		if !absoluteFile(a.QueryPath) || !absoluteFile(a.OutputPath) || a.RequestPath != "" || a.RequestSHA256 != "" || a.RevealPinPath != "" || a.AdoptionPlanSHA256 != "" {
			return bad
		}
	case InitializeJournal:
		if !hashString(a.AdoptionPlanSHA256) || a.RequestPath != "" || a.RequestSHA256 != "" || a.OutputPath != "" || a.QueryPath != "" || a.RevealPinPath != "" {
			return bad
		}
	default:
		return bad
	}
	return nil
}

func absoluteFile(s string) bool {
	return filepath.IsAbs(s) && filepath.Clean(s) == s && s != "/" && !strings.ContainsRune(s, 0)
}

func hashString(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// identity follows the existing recovery/namecoin wire grammar. File-byte
// preparation separately binds these labels to the existing selected profile.
func identity(s, purpose string) bool {
	parts := strings.Split(s, "/")
	if len(parts) != 2 || len(parts[0]) < 1 || len(parts[0]) > 40 || !strings.HasPrefix(parts[1], purpose+"@") {
		return false
	}
	for _, c := range []byte(parts[0]) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	v := strings.TrimPrefix(parts[1], purpose+"@")
	n, err := strconv.ParseUint(v, 10, 31)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == v
}
