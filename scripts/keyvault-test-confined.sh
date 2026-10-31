#!/bin/sh
# Confine go test and its descendants before native startup on macOS.
# Usage from any directory: /path/to/keyvault-test-confined.sh <go test args...>
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
# Resolve HOME just as the in-process profile does, including symlinked homes.
keyvault_home=$(CDPATH= cd -- "${HOME:?HOME must be set}" && pwd -P)
export MAC_KEYVAULT_SKIP_KEYCHAIN=${MAC_KEYVAULT_SKIP_KEYCHAIN-1}
exec /usr/bin/sandbox-exec -D "KEYVAULT_HOME=$keyvault_home" \
  -f "$here/keyvault-no-keychain.sb" go test "$@"
