#!/usr/bin/env bash
# Authority is the reviewed disposable-hosted Actions workflow, not caller env.
set -euo pipefail
fail() { echo "verifier userns setup FAIL: $*; no timing samples collected" >&2; exit 2; }
[ "${VS_RUNNER_ENVIRONMENT-}:${VS_RUNNER_OS-}:${VS_RUNNER_ARCH-}" = github-hosted:Linux:X64 ] || fail 'GitHub-hosted Linux X64 required'
[ "${GITHUB_ACTIONS-}" = true ] || fail 'Actions execution required'
[ "${ImageOS-}" = ubuntu24 ] && [ -n "${ImageVersion-}" ] || fail 'Ubuntu runner image identity required'
[ "${VS_WORKFLOW_PATH-}" = .github/workflows/hosted-ci.yml ] || fail 'unexpected workflow path'
[[ ${VS_WORKFLOW_SHA-} =~ ^[0-9a-f]{40}$ ]] || fail 'missing immutable workflow SHA'
[[ ${GITHUB_REPOSITORY-} =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail 'missing repository identity'
[ "${VS_WORKFLOW_REPOSITORY-}" = "${GITHUB_REPOSITORY-}" ] || fail 'foreign workflow repository'
setup_head=$(git -C "$(dirname "$0")/.." rev-parse HEAD)
[ "$setup_head" = "$VS_WORKFLOW_SHA" ] || fail 'setup source differs from workflow SHA'
actual_os=$(uname -s)
actual_arch=$(uname -m)
[ "$actual_os:$actual_arch" = Linux:x86_64 ] || fail 'actual Linux x86_64 required'
. /etc/os-release
actual_package_arch=$(dpkg --print-architecture)
[ "$ID:$VERSION_ID:$actual_package_arch" = ubuntu:24.04:amd64 ] || fail 'actual Ubuntu 24.04 amd64 required'
printf 'userns runner environment=%s os=%s arch=%s image=%s version=%s workflow_sha=%s\n' "$VS_RUNNER_ENVIRONMENT" "$actual_os" "$actual_arch" "$ImageOS" "$ImageVersion" "$VS_WORKFLOW_SHA"

# Read both knobs even if one fails. A failed read is never a synthetic zero.
apparmor_value=
read_policy() {
  local phase=$1 knob value status first=0
  for knob in kernel.unprivileged_userns_clone kernel.apparmor_restrict_unprivileged_userns; do
    if value=$(sysctl -n "$knob" 2>&1); then
      printf '%s %s value=%s read_exit=0\n' "$phase" "$knob" "$value"
      if [ "$knob" = kernel.apparmor_restrict_unprivileged_userns ]; then apparmor_value=$value; fi
    else
      status=$?
      printf '%s %s unavailable read_exit=%s diagnostic=%s\n' "$phase" "$knob" "$status" "$value" >&2
      if [ "$first" -eq 0 ]; then first=$status; fi
    fi
  done
  return "$first"
}
finish() {
  primary=$?
  trap - EXIT
  trap '' HUP INT TERM PIPE
  set +e
  after_status=0
  apparmor_value=
  read_policy AFTER || after_status=$?
  if [ "$primary" -eq 0 ]; then
    primary=$after_status
    if [ "$primary" -eq 0 ] && [ "$apparmor_value" != 0 ]; then
      echo 'verifier userns setup FAIL: resulting AppArmor userns knob is not 0' >&2
      primary=2
    fi
  fi
  if [ "$primary" -eq 0 ]; then
    echo 'verifier userns setup passed; namespace preflight still required; no timing samples collected'
  else
    echo "verifier userns setup FAIL (exit $primary); no timing samples collected" >&2
  fi
  exit "$primary"
}
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 141' PIPE
read_policy BEFORE
# This is the sole additional policy write, only for the guarded disposable VM.
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
