//go:build !darwin || !cgo

package codesignpolicy

// Native artifact qualification is available only on macOS with Security.framework.
func CertificateFile(string, Role) error { return ErrPolicy }
