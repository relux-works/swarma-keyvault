#!/usr/bin/env bash
# Offline shell fixtures only. Never run a verifier or collect timing samples.
set -euo pipefail
: "${TMPDIR:?private absolute TMPDIR required}"
case "$TMPDIR" in /*) ;; *) exit 2 ;; esac
root=$(mktemp -d "$TMPDIR/verifier-shell-test.XXXXXX")
trap 'rm -rf -- "$root"' EXIT
helper=$(realpath "$(dirname "$0")/../verifier-latency-confined.sh")
mkdir -m 700 "$root/bin" "$root/runner" "$root/tools"
# Missing bwrap: no provisioning, source access or test startup may occur.
if PATH="$root/bin" RUNNER_TEMP="$root/runner" GITHUB_WORKSPACE=/source \
  /bin/bash "$helper" >"$root/missing.log" 2>&1; then
  echo 'missing bwrap unexpectedly passed' >&2; exit 1
else
  status=$?
fi
test "$status" = 127
grep -q 'verifier prerequisite missing: bwrap' "$root/missing.log"
test -z "$(ls -A "$root/runner")"
echo 'missing-bwrap fixture: exit 127, explicit diagnostic, no state/provisioning/timing'

# A namespace refusal retains original stderr and exit, with no download/retry.
for utility in mktemp mkdir rm realpath env; do
  ln -s "/usr/bin/$utility" "$root/bin/$utility"
done
cat > "$root/bin/go" <<'STUB'
#!/bin/bash
case "$*" in
  'env GOROOT') printf '%s\n' /opt/go ;;
  *) echo 'unexpected go invocation in refusal fixture' >&2; exit 98 ;;
esac
STUB
cat > "$root/bin/bwrap" <<'STUB'
#!/bin/bash
echo 'fixture: namespace denied' >&2
exit 42
STUB
chmod 700 "$root/bin/go" "$root/bin/bwrap"
if PATH="$root/bin" RUNNER_TEMP="$root/runner" GITHUB_WORKSPACE=/source \
  /bin/bash "$helper" >"$root/refused.log" 2>&1; then
  echo 'namespace refusal unexpectedly passed' >&2; exit 1
else
  status=$?
fi
test "$status" = 42
grep -q 'fixture: namespace denied' "$root/refused.log"
grep -q 'preflight failed (exit 42)' "$root/refused.log"
! grep -q 'unexpected go invocation' "$root/refused.log"
test -z "$(ls -A "$root/runner")"
echo 'namespace-refusal fixture: exit 42 retained, stderr retained, no download/retry/timing, scratch removed'

# Relative source/scratch paths must refuse before creating any state.
if PATH="$root/bin" RUNNER_TEMP=relative GITHUB_WORKSPACE=/source \
  /bin/bash "$helper" >"$root/relative.log" 2>&1; then
  echo 'relative scratch unexpectedly passed' >&2; exit 1
else
  status=$?
fi
test "$status" = 2
grep -q 'absolute scratch and source paths required' "$root/relative.log"
test -z "$(ls -A "$root/runner")"
echo 'relative-path fixture: exit 2, no state or execution'

# Real nested bwrap runs the mount/environment/tool preflight. A Go shim stands
# for the provisioned toolchain, then refuses provisioning. This is shell and
# mount-closure evidence only, never a real Go/verifier or latency qualification.
mkdir -m 700 "$root/tools/bin"
cat > "$root/tools/bin/go" <<'STUB'
#!/bin/bash
case "$*" in
  'env GOROOT') printf '%s\n' /opt/go ;;
  'env GOMODCACHE') printf '%s\n' /private/dependencies ;;
  'env GOVERSION') printf '%s\n' go1.26.10 ;;
  version) echo 'fixture toolchain, not real Go qualification' ;;
  'mod download') echo 'fixture: provisioning refused before product execution' >&2; exit 73 ;;
  *) echo 'unexpected product/timing invocation' >&2; exit 99 ;;
esac
STUB
chmod 700 "$root/tools/bin/go"
# Host-side discovery resolves to the fixture tool root; inside the sandbox the
# same fixture is mounted at /opt/go, like the workflow-provisioned toolchain.
cat > "$root/bin/go" <<STUB
#!/bin/bash
if [ "\$*" = 'env GOROOT' ]; then
  printf '%s\\n' '$root/tools'
else
  exit 98
fi
STUB
rm "$root/bin/bwrap"
ln -s /usr/bin/bwrap "$root/bin/bwrap"
if PATH="$root/bin:/usr/bin:/bin" RUNNER_TEMP="$root/runner" GITHUB_WORKSPACE=/source \
  /bin/bash "$helper" >"$root/closure.log" 2>&1; then
  echo 'provisioning refusal unexpectedly passed' >&2; exit 1
else
  status=$?
fi
cat "$root/closure.log"
if [ "$status" = 73 ]; then
  grep -q 'sandbox preflight passed; no timing samples collected yet' "$root/closure.log"
  grep -q 'fixture: provisioning refused before product execution' "$root/closure.log"
  echo 'real nested bwrap closure fixture: preflight passed; provisioning exit 73 retained; fixture Go only'
else
  # Ubuntu may permit the outer sandbox but deny nested user namespaces.
  # This checks error propagation, and does NOT qualify that runtime.
  test "$status" = 1
  grep -q 'bwrap: No permissions to create a new namespace' "$root/closure.log"
  grep -q 'sandbox preflight failed (exit 1)' "$root/closure.log"
  ! grep -q 'sandbox preflight passed' "$root/closure.log"
  echo 'real nested bwrap REFUSED: exit 1 retained; runtime qualification BLOCKED; error handling passed'
fi
! grep -q 'unexpected product/timing invocation' "$root/closure.log"
test -z "$(ls -A "$root/runner")"
echo 'shell fixtures complete: no verifier/timing executed; scratch removed'
