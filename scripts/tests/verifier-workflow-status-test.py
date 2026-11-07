#!/usr/bin/python3
"""Offline production run-block controls: inert package commands, exact cleanup."""
import argparse
import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from verifier_workflow_fixture import workflow_run

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--receipt', type=Path, required=True)
parser.add_argument('--baseline', action='store_true', help='reproduce the old rightmost-failure behavior')
args = parser.parse_args()
assert args.receipt.is_absolute()
source = Path(__file__).resolve().parents[2]
fixtures = source/'scripts/tests/verifier-fixtures'
root = Path(tempfile.mkdtemp(prefix='workflow-status.', dir=os.environ['TMPDIR']))
records = []
try:
    tools = root/'tools'; tools.mkdir(mode=0o700)
    stub = tools/'package-command'
    stub.write_text('''#!/bin/bash
name=${0##*/}
printf '%s %s\\n' "$name" "$*" >> "$FIXTURE_CALLS"
case "$name" in
 dpkg) echo amd64 ;;
 sysctl) echo 'fixture: knob unavailable' >&2; exit 3 ;;
 curl) while [ "$1" != --output ]; do shift; done; printf 'inert package bytes' > "$2" ;;
 sha256sum) echo '2461f1beee9cb04c8942739fe1a2b37e7b7c2a3d518f0779dc75f9245baa3094  fixture.deb' ;;
 dpkg-deb) printf 'Package: bubblewrap\\nVersion: 0.9.0-1ubuntu0.3\\nArchitecture: amd64\\n' ;;
 sudo) [ "$1:$2" = dpkg:--install ] || exit 99
       echo 'fixture original install diagnostic' >&2
       if [ -n "${FIXTURE_SIGNAL-}" ]; then kill -s "$FIXTURE_SIGNAL" "$PPID"; exit 0; fi
       exit "$FIXTURE_PRIMARY" ;;
 dpkg-query) echo '0.9.0-1ubuntu0.3 amd64' ;;
 *) exit 99 ;;
esac
''')
    stub.chmod(0o700)
    for name in ['dpkg','sysctl','curl','sha256sum','dpkg-deb','sudo','dpkg-query']:
        (tools/name).symlink_to(stub)
    workflow_source = source
    if args.baseline:
        workflow_source = root/'baseline'
        (workflow_source/'.github/workflows').mkdir(parents=True)
        original = subprocess.check_output(['git','-C',str(source),'show',
                    '1ba3a622123471da63191b92706b8721875908e2:.github/workflows/hosted-ci.yml'],text=True)
        (workflow_source/'.github/workflows/hosted-ci.yml').write_text(original)
    head = subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
    signals = {129:'HUP',130:'INT',143:'TERM',141:'PIPE'}
    statuses = [17] if args.baseline else [0,17,129,130,143,141]
    for route, helper in [('install','verifier-hosted-package.sh'),('timing','verifier-latency-confined.sh')]:
        block = workflow_run(workflow_source, helper)
        for primary in statuses:
            for tee_fail in ([True] if args.baseline else [False,True]):
                name = f'{route}-primary-{primary}-tee-{int(tee_fail)}'
                case = root/name; case.mkdir(mode=0o700)
                (case/'runner').mkdir(mode=0o700)
                (case/'scripts').symlink_to(source/'scripts',target_is_directory=True)
                (case/'.ci-verifier-route').symlink_to(source,target_is_directory=True)
                config = dict(mode='0555',primary=primary,tee_fail=tee_fail)
                if route=='timing' and primary in signals:
                    config.update(primary=0,signal=signals[primary])
                (case/'config.json').write_text(json.dumps(config))
                env = dict(PATH=(str(tools)+':' if route=='install' else '')+str(fixtures)+':/usr/bin:/bin',
                           HOME=os.environ['HOME'],TMPDIR=os.environ['TMPDIR'],XDG_CACHE_HOME=os.environ['XDG_CACHE_HOME'],
                           RUNNER_TEMP=str(case/'runner'),GITHUB_WORKSPACE=str(source),LC_ALL='C',
                           FIXTURE_CALLS=str(case/'calls.log'),FIXTURE_PRIMARY=str(primary),
                           FIXTURE_SIGNAL=signals.get(primary,'') if route=='install' else '',
                           GITHUB_ACTIONS='true',VS_RUNNER_ENVIRONMENT='github-hosted',VS_RUNNER_OS='Linux',VS_RUNNER_ARCH='X64',
                           VS_WORKFLOW_SHA=head,VS_WORKFLOW_REPOSITORY='example/project',GITHUB_REPOSITORY='example/project',
                           VS_WORKFLOW_PATH='.github/workflows/hosted-ci.yml',ImageOS='ubuntu24',ImageVersion='offline-inert-fixture')
                expected = 1 if args.baseline else primary if primary else int(tee_fail)
                tick = time.monotonic(); start = datetime.datetime.now(datetime.timezone.utc).isoformat()
                p = subprocess.run(['/bin/bash','-c',block],cwd=case,env=env,capture_output=True,text=True,timeout=20)
                remaining = sorted(x.name for x in (case/'runner').iterdir())
                calls = (case/'calls.log').read_text()
                r = dict(name=name,route=route,primary=primary,tee_fail=tee_fail,expected=expected,
                         start=start,end=datetime.datetime.now(datetime.timezone.utc).isoformat(),elapsed_seconds=time.monotonic()-tick,
                         command=['/bin/bash','-c',block],exit=p.returncode,stdout=p.stdout,stderr=p.stderr,
                         scratch_remaining=remaining,calls=calls,fixture_only=True,baseline=args.baseline,
                         actual_signal=signals.get(primary),
                         observed_mode=(case/'observed-mode').read_text() if (case/'observed-mode').exists() else None)
                records.append(r)
                args.receipt.write_text(json.dumps(records,indent=2)+'\n')
                assert p.returncode == expected, r
                assert not remaining, r
                if tee_fail: assert '/dev/full:' in p.stderr and 'space' in p.stderr, r
                if route=='timing':
                    assert r['observed_mode']=='0o555', r
                    assert 'fixture original primary stderr' in p.stdout, r
                else:
                    assert 'fixture original install diagnostic' in p.stdout, r
                    for phase in ['BEFORE','AFTER']:
                        for knob in ['kernel.unprivileged_userns_clone','kernel.apparmor_restrict_unprivileged_userns']:
                            assert f'{phase} {knob} unavailable read_exit=3' in p.stdout, r
                    assert not list((case/'runner').glob('verifier-package.*')), r
                print(name,'PASS',p.returncode,flush=True)
                shutil.rmtree(case)
finally:
    args.receipt.write_text(json.dumps(records,indent=2)+'\n')
    shutil.rmtree(root)
print('Offline status selection only; no package/policy/product/timing execution or hosted qualification.')
