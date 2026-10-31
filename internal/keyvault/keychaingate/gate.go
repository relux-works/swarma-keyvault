// Package keychaingate confines gated macOS test binaries before keyvault's
// initialization. Real binaries never apply the sandbox. Descendants inherit
// its kernel restrictions, even if they remove SkipEnv from their environment.
package keychaingate

const SkipEnv = "MAC_KEYVAULT_SKIP_KEYCHAIN"

var applied bool
var confined bool

// Applied reports successful installation in this process, not an inherited
// sandbox. It lets regression controls distinguish this layer from a wrapper.
func Applied() bool { return applied }

// Confined reports that installation failed but a read-only canary confirmed
// Keychain denial by existing confinement. It is false when Applied is true,
// and is only recorded in gated test binaries.
func Confined() bool { return confined }
