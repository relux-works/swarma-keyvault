package grants

import (
	"bytes"
	"strconv"
	"strings"
)

// LocalProviderAttempt is an unauthenticated local observation. An HTTP response
// means the selected subprocess emitted a complete HTTP header block; it does
// not attest that the subprocess contacted GitHub. Neither process start nor an
// unknown outcome establishes that a request left the host. Diagnostics are
// fixed codes; stderr, response bodies and arbitrary headers are never copied.
type LocalProviderAttempt struct {
	Classification string `json:"classification"`
	HTTPStatus     int    `json:"http_status,omitempty"`
	RequestID      string `json:"request_id,omitempty"`
	Diagnostic     string `json:"diagnostic"`
}

const localHTTPHeaderLimit = 16384

// gh api --include emits resp.Proto, status, sorted headers, a blank line and
// the original body. Accept CRLF and LF, HTTP/1.x and Go's HTTP/2.0 spelling.
// Body-only receipts stay compatible without inventing status or request ID.
func parseLocalHTTPResponse(raw []byte) ([]byte, *LocalProviderAttempt) {
	if !bytes.HasPrefix(raw, []byte("HTTP/")) {
		return raw, nil
	}
	end := bytes.Index(raw, []byte("\r\n\r\n"))
	separator := 4
	if end < 0 {
		end, separator = bytes.Index(raw, []byte("\n\n")), 2
	}
	if end < 0 || end+separator > localHTTPHeaderLimit {
		return nil, nil
	}
	header := string(raw[:end])
	if strings.Contains(header, "\r") {
		header = strings.ReplaceAll(header, "\r\n", "\n")
	}
	lines := strings.Split(header, "\n")
	if len(lines) > 128 {
		return nil, nil
	}
	for _, line := range lines {
		if len(line) > 1024 || !localHTTPFieldValue(line) {
			return nil, nil
		}
	}
	if !localHTTPPrintable(lines[0]) {
		return nil, nil
	}
	status := strings.SplitN(lines[0], " ", 3)
	if len(status) < 2 || (status[0] != "HTTP/1.0" && status[0] != "HTTP/1.1" && status[0] != "HTTP/2.0") || len(status[1]) != 3 {
		return nil, nil
	}
	for _, c := range status[1] {
		if c < '0' || c > '9' {
			return nil, nil
		}
	}
	code, err := strconv.Atoi(status[1])
	if err != nil || code < 200 || code > 599 {
		return nil, nil
	}
	requestID, seenID := "", false
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" {
			return nil, nil
		}
		for _, c := range name {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
				return nil, nil
			}
		}
		if strings.EqualFold(name, "X-GitHub-Request-Id") {
			if seenID {
				return nil, nil
			}
			seenID = true
			value = strings.Trim(value, " \t")
			if localGitHubRequestID(value) {
				requestID = value
			}
		}
	}
	return raw[end+separator:], &LocalProviderAttempt{Classification: "http-response", HTTPStatus: code, RequestID: requestID, Diagnostic: "http-response"}
}

// HTTP field values may contain obs-text; it is ignored, never projected.
func localHTTPFieldValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '\t' && (s[i] < 0x20 || s[i] == 0x7f) {
			return false
		}
	}
	return true
}

func localHTTPPrintable(s string) bool {
	for _, c := range s {
		if c != '\t' && (c < 0x20 || c > 0x7e) {
			return false
		}
	}
	return true
}

// GitHub's colon-separated hexadecimal request IDs are the sole admitted
// free-text diagnostic. Unsupported forms are omitted, never sanitized or fixed.
func localGitHubRequestID(s string) bool {
	if len(s) > 128 {
		return false
	}
	parts := strings.Split(s, ":")
	if len(parts) != 4 && len(parts) != 5 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 16 {
			return false
		}
		for _, c := range part {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}
