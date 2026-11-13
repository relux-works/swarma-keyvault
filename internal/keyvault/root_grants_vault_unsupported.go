//go:build !darwin || !cgo

package keyvault

// The root vault adapter needs the macOS Security framework through cgo. Without
// it there is no native seam, so the production vault cannot be constructed.
func newRootGrantsNative() rootGrantsNative { return nil }

func rootGrantsNativeNamespace() string { return "" }
