//go:build darwin && cgo

package testguard

// realBackend matches the build of the real Security.framework store.
const realBackend = true
