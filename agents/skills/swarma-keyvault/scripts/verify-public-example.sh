#!/bin/sh
# Run only inside the confinement command in references/grants.md.
# Public fixture verification only: no signing, initialization or effects.
set -eu
if [ "$#" -ne 2 ]; then
    echo 'usage: verify-public-example.sh /absolute/portable-cli /absolute/fixtures' >&2
    exit 2
fi
binary=$1
fixtures=$2
case "$binary:$fixtures" in
    /*:/*) ;;
    *) echo 'explicit absolute CLI and fixture paths are required' >&2; exit 2 ;;
esac
umask 077
scratch=$(mktemp -d "$TMPDIR/local-verify.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT HUP INT TERM
cp "$fixtures/enrollment.json" "$scratch/enrollment.json"
chmod 600 "$scratch/enrollment.json"
"$binary" grants verify --config "$scratch/enrollment.json" \
    --certificate "$fixtures/certificate.json" --request "$fixtures/request.json" \
    --at 2026-11-02T11:00:00Z
printf '\naccepted observation: exit 0\n'
if "$binary" grants verify --config "$scratch/enrollment.json" \
    --certificate "$fixtures/certificate.json" --request "$fixtures/request.json" \
    --at 2026-11-02T11:30:00Z > "$scratch/expired.stdout" 2> "$scratch/expired.stderr"; then
    echo 'exclusive expiry unexpectedly accepted' >&2
    exit 1
else
    code=$?
fi
test "$code" -eq 1
test ! -s "$scratch/expired.stdout"
cat "$scratch/expired.stderr"
printf 'expired observation: exit %s; empty stdout\n' "$code"
