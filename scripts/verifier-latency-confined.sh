#!/usr/bin/env bash
# Hosted Linux verifier gate: qualify the sandbox before the single measurement.
set -euo pipefail

if ! command -v bwrap >/dev/null 2>&1; then
  echo 'verifier prerequisite missing: bwrap; install the workflow-pinned bubblewrap package before testing. No timing samples collected.' >&2
  exit 127
fi
: "${RUNNER_TEMP:?RUNNER_TEMP must be an absolute private scratch parent}"
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE must be the absolute candidate checkout}"
case "$RUNNER_TEMP:$GITHUB_WORKSPACE" in /*:/*) ;; *) echo 'verifier prerequisite: absolute scratch and source paths required' >&2; exit 2 ;; esac
umask 077
cleanup_program=$(realpath -e "$(dirname "$0")/verifier-private-cleanup.py")
# Keep directory descriptors open across execution: cleanup never resolves an
# untrusted replacement path. Python is isolated from ambient import settings.
test -x /usr/bin/python3
test -x /usr/bin/timeout
exec {parent_fd}<"$RUNNER_TEMP"
state=$(mktemp -d "$RUNNER_TEMP/verifier-private.XXXXXX")
exec {state_fd}<"$state"
finish() {
  primary=$?
  set +e
  trap - EXIT
  trap '' HUP INT TERM PIPE
  cleanup_status=0
  /usr/bin/timeout --signal=TERM --kill-after=2s 12s \
    /usr/bin/python3 -I "$cleanup_program" "$parent_fd" "$state_fd" "${state##*/}" \
    || cleanup_status=$?
  if [ "$cleanup_status" -ne 0 ]; then
    echo "verifier cleanup failed (exit $cleanup_status; primary exit $primary); invocation scratch may remain" >&2
    if [ "$primary" -eq 0 ]; then primary=74; fi
  fi
  exit "$primary"
}
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 141' PIPE
for directory in home tmp cache build dependencies; do
  mkdir -m 700 "$state/$directory"
done
# Provision public go.sum-pinned dependencies in this job's own empty cache.
# Clear ambient Go/auth configuration; no shared HOME, cache or credentials.
toolchain=$(env -i PATH="$PATH" HOME="$state/home" TMPDIR="$state/tmp" \
  GOENV=off GOTOOLCHAIN=local GOTELEMETRY=off go env GOROOT)
toolchain=$(realpath -e "$toolchain")
source=$(realpath -e "$GITHUB_WORKSPACE")
cd -- "$source"
# One mount/namespace definition is used for qualification and measurement.
sandbox=(bwrap --die-with-parent --unshare-all --clearenv
  --ro-bind /usr /usr --symlink usr/bin /bin
  --symlink usr/lib /lib --symlink usr/lib64 /lib64
  --proc /proc --dev /dev --dir /etc
  --ro-bind "$source" /source --ro-bind "$toolchain" /opt/go
  --bind "$state" /private --ro-bind "$state/dependencies" /private/dependencies
  --setenv PATH /opt/go/bin:/usr/bin:/bin
  --setenv GOROOT /opt/go --setenv GOTOOLCHAIN local
  --setenv GOENV off --setenv GOTELEMETRY off
  --setenv HOME /private/home --setenv TMPDIR /private/tmp
  --setenv XDG_CACHE_HOME /private/cache --setenv GOCACHE /private/build
  --setenv GOPATH /private/gopath --setenv GOMODCACHE /private/dependencies
  --setenv GOPROXY off --setenv GOSUMDB off
  --setenv GOMAXPROCS 2 --setenv GOFLAGS '-mod=readonly -p=2'
  --chdir /source)
# No timing or product code here. Failure retains bwrap's stderr and exit status.
# In particular, installing bwrap does not prove the runner permits user/net/etc.
# namespaces. Never replace --unshare-all, share networking or disable AppArmor.
if "${sandbox[@]}" /bin/bash -euc '
  readonly_mount() {
    while read -r id parent device root mount options rest; do
      if [ "$mount" = "$1" ]; then
        case ",$options," in *,ro,*) return 0 ;; *) return 1 ;; esac
      fi
    done < /proc/self/mountinfo
    return 1
  }
  for mount in /usr /source /opt/go /private/dependencies; do
    readonly_mount "$mount"
  done
  for directory in "$HOME" "$TMPDIR" "$XDG_CACHE_HOME" "$GOCACHE"; do
    test "$(stat -c %a "$directory")" = 700
    test -w "$directory"
  done
  test -z "${SSH_AUTH_SOCK+x}${GH_TOKEN+x}${GITHUB_TOKEN+x}${GH_CONFIG_DIR+x}"
  test ! -e /home/runner
  test "$(go env GOROOT)" = /opt/go
  test "$(go env GOMODCACHE)" = /private/dependencies
  # A stdlib-only preflight utility uses the authoritative Go module parser.
  # It performs no product operation or dependency provisioning.
  go run /source/tools/verifiertoolchain/main.go
  go version
  for namespace in user mnt net pid ipc uts cgroup; do
    printf "sandbox namespace %s: " "$namespace"
    readlink "/proc/self/ns/$namespace"
  done
'; then
  echo 'verifier sandbox preflight passed; no timing samples collected yet'
else
  status=$?
  echo "verifier sandbox preflight failed (exit $status): job FAIL; sandbox qualification refused; see preceding diagnostic. No timing samples collected; no isolation fallback." >&2
  exit "$status"
fi
# Download/verify is provisioning only, after namespace qualification and before
# offline execution. Go verifies canonical h1 checksums against committed go.sum.
env -i PATH="$toolchain/bin:/usr/bin:/bin" HOME="$state/home" TMPDIR="$state/tmp" \
  GOCACHE="$state/build" GOMODCACHE="$state/dependencies" GOPATH="$state/gopath" \
  GOENV=off GOTOOLCHAIN=local GOTELEMETRY=off GOFLAGS='-mod=readonly -p=2' \
  GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
  go mod download
env -i PATH="$toolchain/bin:/usr/bin:/bin" HOME="$state/home" TMPDIR="$state/tmp" \
  GOCACHE="$state/build" GOMODCACHE="$state/dependencies" GOPATH="$state/gopath" \
  GOENV=off GOTOOLCHAIN=local GOTELEMETRY=off GOFLAGS='-mod=readonly -p=2' \
  GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
  go mod verify
# Fixture signing is outside timing. Exactly 40/path; one run, zero retries.
# Nearest-rank p95 is rank 38 of 40; require p95 <=80ms AND max <100ms.
"${sandbox[@]}" go test -count=1 -v ./internal/grants \
  -run '^(TestLinuxRealVerifierP95|TestLinuxVerifierTimingCriterion|TestLinuxVerifierAttemptControls|TestLinuxVerifierRefusalAndQualificationControls|TestLinuxAdmissionDeadlineCompatibility|TestLinuxAdmissionDeadlineCauseControls|TestLinuxAdmissionPhaseEvidence|TestLinuxAdmissionLateStateIsNotDeadline|TestLinuxAdmissionLockCauseControls)$'
