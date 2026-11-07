#!/usr/bin/env bash
# Privileged setup is permitted only by the reviewed GitHub-hosted workflow.
set -euo pipefail
fail() { echo "verifier package setup FAIL: $*; no timing samples collected" >&2; exit 2; }
# These values are supplied by Actions contexts in the immutable workflow, not
# workflow_dispatch inputs or a caller-selected runner label. This shell check
# is not a portable authorization credential for running setup on other hosts.
[ "${VS_RUNNER_ENVIRONMENT-}:${VS_RUNNER_OS-}:${VS_RUNNER_ARCH-}" = github-hosted:Linux:X64 ] || fail 'GitHub-hosted Linux X64 required'
[ "${GITHUB_ACTIONS-}" = true ] || fail 'Actions execution required'
[ "${VS_WORKFLOW_PATH-}" = .github/workflows/hosted-ci.yml ] || fail 'unexpected workflow path'
[[ ${VS_WORKFLOW_SHA-} =~ ^[0-9a-f]{40}$ ]] || fail 'missing immutable workflow SHA'
[[ ${GITHUB_REPOSITORY-} =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail 'missing repository identity'
[ "${VS_WORKFLOW_REPOSITORY-}" = "${GITHUB_REPOSITORY-}" ] || fail 'foreign workflow repository'
[ "$(git -C "$(dirname "$0")/.." rev-parse HEAD)" = "$VS_WORKFLOW_SHA" ] || fail 'setup source differs from workflow SHA'
. /etc/os-release
[ "$ID:$VERSION_ID:$(dpkg --print-architecture)" = ubuntu:24.04:amd64 ] || fail 'Ubuntu 24.04 amd64 required'
[ "${ImageOS-}" = ubuntu24 ] && [ -n "${ImageVersion-}" ] || fail 'missing Ubuntu runner image identity'
printf 'runner environment=%s os=%s arch=%s image=%s version=%s workflow_sha=%s\n' "$VS_RUNNER_ENVIRONMENT" "$VS_RUNNER_OS" "$VS_RUNNER_ARCH" "$ImageOS" "$ImageVersion" "$VS_WORKFLOW_SHA"
: "${RUNNER_TEMP:?absolute private runner temp required}"
[[ $RUNNER_TEMP = /* ]] || fail 'absolute runner temp required'
umask 077
state=
read_policy() {
  local phase=$1 knob value status
  for knob in kernel.unprivileged_userns_clone kernel.apparmor_restrict_unprivileged_userns; do
    if value=$(sysctl -n "$knob" 2>&1); then
      printf '%s %s value=%s read_exit=0\n' "$phase" "$knob" "$value"
    else
      status=$?
      printf '%s %s unavailable read_exit=%s diagnostic=%s\n' "$phase" "$knob" "$status" "$value"
    fi
  done
}
finish() {
  primary=$?
  trap - EXIT
  set +e
  read_policy AFTER
  installed=$(dpkg-query -W -f='${Version} ${Architecture}' bubblewrap 2>&1); query_exit=$?
  printf 'AFTER installed_package=%s query_exit=%s\n' "$installed" "$query_exit"
  if [ -n "$state" ]; then rm -f -- "$state/bubblewrap.deb"; rmdir -- "$state"; fi
  if [ "$primary" -ne 0 ]; then
    echo "verifier package setup FAIL (exit $primary); no timing samples collected" >&2
  fi
  exit "$primary"
}
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
read_policy BEFORE
version=0.9.0-1ubuntu0.3
sha=2461f1beee9cb04c8942739fe1a2b37e7b7c2a3d518f0779dc75f9245baa3094
url=https://security.ubuntu.com/ubuntu/pool/main/b/bubblewrap/bubblewrap_0.9.0-1ubuntu0.3_amd64.deb
printf 'package=bubblewrap version=%s architecture=amd64 official_source=%s expected_deb_sha256=%s\n' "$version" "$url" "$sha"
state=$(mktemp -d "$RUNNER_TEMP/verifier-package.XXXXXX")
# Fixed official archive route, no redirects, no alternative version or source.
curl --fail --silent --show-error --proto '=https' --tlsv1.2 --output "$state/bubblewrap.deb" "$url"
actual_sha=$(sha256sum "$state/bubblewrap.deb"); actual_sha=${actual_sha%% *}
printf 'downloaded_deb_sha256=%s\n' "$actual_sha"
[ "$actual_sha" = "$sha" ] || fail 'deb SHA256 mismatch'
[ "$(dpkg-deb -f "$state/bubblewrap.deb" Package Version Architecture)" = "$(printf 'Package: bubblewrap\nVersion: %s\nArchitecture: amd64' "$version")" ] || fail 'deb package/version/architecture mismatch'
# Only this exact package's official postinst may adjust policy. No manual
# sysctl writes, AppArmor overrides, apt dependency changes or test sudo.
sudo dpkg --install "$state/bubblewrap.deb"
[ "$(dpkg-query -W -f='${Version} ${Architecture}' bubblewrap)" = "$version amd64" ] || fail 'installed package mismatch'
echo 'verifier package setup passed; namespace preflight still required; no timing samples collected'
