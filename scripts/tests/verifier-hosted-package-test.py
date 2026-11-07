#!/usr/bin/env python3
"""Offline command-shim fixtures; no installation, policy writes or timing."""
import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

root = Path(tempfile.mkdtemp(prefix='hosted-package.', dir=os.environ['TMPDIR']))
root.chmod(0o700)
records = []
try:
    tools = root / 'tools'
    tools.mkdir(mode=0o700)
    stub = tools / 'stub'
    stub.write_text('''#!/bin/bash
name=${0##*/}
printf '%s %s\\n' "$name" "$*" >> "$FIXTURE_CALLS"
case "$name" in
 git) echo "${FIXTURE_HEAD:-1111111111111111111111111111111111111111}" ;;
 dpkg) echo "${FIXTURE_ARCH:-amd64}" ;;
 sysctl)
   if [ "${FIXTURE_KNOBS:-}" = unavailable ]; then echo 'fixture: unsupported knob' >&2; exit 3; fi
   case "$2" in kernel.unprivileged_userns_clone) echo 1 ;; *) echo 0 ;; esac ;;
 curl) if [ "${FIXTURE_DOWNLOAD_FAIL:-}" = yes ]; then echo 'fixture: download failed' >&2; exit 23; fi
       while [ "$1" != --output ]; do shift; done; printf 'fixture deb, never executable' > "$2" ;;
 sha256sum) echo "${FIXTURE_SHA:-2461f1beee9cb04c8942739fe1a2b37e7b7c2a3d518f0779dc75f9245baa3094}  fixture.deb" ;;
 dpkg-deb) printf 'Package: bubblewrap\\nVersion: %s\\nArchitecture: amd64\\n' "${FIXTURE_VERSION:-0.9.0-1ubuntu0.3}" ;;
 sudo) [ "$1:$2" = dpkg:--install ] || exit 99
       if [ "${FIXTURE_INSTALL_FAIL:-}" = yes ]; then echo 'fixture: install/postinst failed' >&2; exit 17; fi ;;
 dpkg-query) echo '0.9.0-1ubuntu0.3 amd64' ;;
 *) exit 99 ;;
esac
''')
    stub.chmod(0o700)
    for name in ['git', 'dpkg', 'sysctl', 'curl', 'sha256sum', 'dpkg-deb', 'sudo', 'dpkg-query']:
        (tools / name).symlink_to(stub)
    base = dict(PATH=str(tools)+':/usr/bin:/bin', HOME=os.environ['HOME'], TMPDIR=os.environ['TMPDIR'],
                XDG_CACHE_HOME=os.environ['XDG_CACHE_HOME'], RUNNER_TEMP=str(root), GITHUB_ACTIONS='true',
                VS_RUNNER_ENVIRONMENT='github-hosted', VS_RUNNER_OS='Linux', VS_RUNNER_ARCH='X64',
                VS_WORKFLOW_SHA='1'*40, VS_WORKFLOW_REPOSITORY='example/project', GITHUB_REPOSITORY='example/project',
                VS_WORKFLOW_PATH='.github/workflows/hosted-ci.yml', ImageOS='ubuntu24', ImageVersion='fixture-image')
    cases = [
        ('valid-neighbor', {}, 0, True),
        ('self-hosted', {'VS_RUNNER_ENVIRONMENT':'self-hosted'}, 2, False),
        ('missing-environment', {'VS_RUNNER_ENVIRONMENT':''}, 2, False),
        ('mac', {'VS_RUNNER_OS':'macOS'}, 2, False),
        ('wrong-arch', {'FIXTURE_ARCH':'arm64'}, 2, False),
        ('source-mismatch', {'FIXTURE_HEAD':'2'*40}, 2, False),
        ('wrong-workflow', {'VS_WORKFLOW_PATH':'other.yml'}, 2, False),
        ('missing-repository', {'GITHUB_REPOSITORY':'','VS_WORKFLOW_REPOSITORY':''}, 2, False),
        ('missing-image', {'ImageVersion':''}, 2, False),
        ('missing-knobs', {'FIXTURE_KNOBS':'unavailable'}, 0, True),
        ('download-failure', {'FIXTURE_DOWNLOAD_FAIL':'yes'}, 23, False),
        ('wrong-deb-hash', {'FIXTURE_SHA':'0'*64}, 2, False),
        ('wrong-package-version', {'FIXTURE_VERSION':'0.9.0-other'}, 2, False),
        ('installation-failure', {'FIXTURE_INSTALL_FAIL':'yes'}, 17, True),
    ]
    for name, changes, expected, install in cases:
        calls = root / (name+'.calls')
        env = base | changes | {'FIXTURE_CALLS':str(calls)}
        tick=time.monotonic(); start=datetime.datetime.now(datetime.timezone.utc).isoformat()
        p=subprocess.run(['/bin/bash','-c','set -euo pipefail; bash scripts/verifier-hosted-package.sh 2>&1 | tee "$1"','fixture',str(root/(name+'.log'))],env=env,capture_output=True,text=True,timeout=5)
        commands=calls.read_text() if calls.exists() else ''
        r=dict(name=name,start=start,end=datetime.datetime.now(datetime.timezone.utc).isoformat(),elapsed_seconds=time.monotonic()-tick,
               exit=p.returncode,stdout=p.stdout,stderr=p.stderr,shim_calls=commands,fixture_only=True)
        records.append(r)
        Path('/private/evidence/package-cases.json').write_text(json.dumps(records,indent=2)+'\n')
        assert p.returncode==expected,r
        assert ('sudo dpkg --install' in commands)==install,r
        if name in ['valid-neighbor','missing-knobs','download-failure','wrong-deb-hash','wrong-package-version','installation-failure']:
            for phase in ['BEFORE','AFTER']:
                for knob in ['kernel.unprivileged_userns_clone','kernel.apparmor_restrict_unprivileged_userns']:
                    assert f'{phase} {knob} ' in p.stdout,r
            assert 'version=0.9.0-1ubuntu0.3' in p.stdout,r
            if name != 'download-failure': assert 'downloaded_deb_sha256=' in p.stdout,r
        if name=='missing-knobs':
            assert p.stdout.count('unavailable read_exit=3')==4,r
            assert 'value=0' not in p.stdout,r
        if expected:
            assert 'FAIL' in p.stdout and 'no timing samples collected' in p.stdout,r
        assert not list(root.glob('verifier-package.*')),r
    print(f'{len(records)} offline package/runner/logging/failure fixtures passed; no real package, policy or verifier execution')
finally:
    shutil.rmtree(root)
