//go:build !darwin || !cgo

package testguard

// realBackend matches the build of the real Security.framework store, which
// does not exist without darwin and cgo.
const realBackend = false
