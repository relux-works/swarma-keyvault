//go:build !darwin

package kekclient

// processIdentity is unavailable here; the tests that need it skip.
func processIdentity(int) (string, bool) { return "", false }
