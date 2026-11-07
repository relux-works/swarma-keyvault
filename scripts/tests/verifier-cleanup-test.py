#!/usr/bin/python3
"""Offline shell fixtures. Run with read-only source/tools and private scratch."""
import datetime
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import time
from verifier_workflow_fixture import workflow_run

source = pathlib.Path(__file__).resolve().parents[2]
fixtures = source/'scripts/tests/verifier-fixtures'
root = pathlib.Path(os.environ['TMPDIR'])/'cleanup-fixtures'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--receipt', type=pathlib.Path,
                    default=pathlib.Path(os.environ['TMPDIR'])/'cleanup-cases.json')
parser.add_argument('--case', action='append', dest='cases',
                    help='run only a named fixture (repeatable)')
args = parser.parse_args()
receipt = args.receipt
assert receipt.is_absolute(), 'receipt must be in absolute private scratch'
root.mkdir(mode=0o700)
records=[]
configs=[]
for mode in ['0700','0555']:
    for primary in [0,17]:
        configs.append(dict(name=f'cache-{mode}-primary-{primary}',mode=mode,primary=primary,expected=primary))
for primary in [0,17]:
    configs.append(dict(name=f'cleanup-failure-primary-{primary}',mode='0555',primary=primary,cleanup_fail=True,expected=74 if primary==0 else primary))
    configs.append(dict(name=f'tee-failure-primary-{primary}',mode='0555',primary=primary,tee_fail=True,expected=primary if primary else 1))
configs += [dict(name='symlink-target',mode='0555',primary=0,symlink=True,expected=0),
            dict(name='partial-setup',mode='0555',primary=0,partial=True,expected=23),
            dict(name='toolchain-discovery-failure',mode='0555',primary=0,discovery_exit=31,expected=31),
            dict(name='provisioning-failure',mode='0555',primary=0,download_exit=29,expected=29)]
for sig, status in [('HUP',129),('INT',130),('TERM',143),('PIPE',141)]:
    configs.append(dict(name='signal-'+sig,mode='0555',primary=0,signal=sig,expected=status))
if args.cases:
    assert set(args.cases) <= {c['name'] for c in configs}, 'unknown fixture'
    configs = [c for c in configs if c['name'] in args.cases]
try:
    for c in configs:
        case=root/c['name']; case.mkdir(mode=0o700)
        (case/'runner').mkdir(mode=0o700)
        (case/'outside').mkdir(mode=0o700)
        (case/'outside/sentinel').write_text('external sentinel\n')
        (case/'outside').chmod(0o555)
        (case/'config.json').write_text(json.dumps(c))
        env=dict(PATH=f'{fixtures}:/usr/bin:/bin', HOME=os.environ['HOME'],
                 TMPDIR=os.environ['TMPDIR'], XDG_CACHE_HOME=os.environ['XDG_CACHE_HOME'],
                 RUNNER_TEMP=str(case/'runner'),GITHUB_WORKSPACE=str(source),LC_ALL='C')
        # Execute the production run block verbatim; tee is an inert I/O shim.
        (case/'scripts').symlink_to(source/'scripts', target_is_directory=True)
        command=['/bin/bash','-c', workflow_run(source, 'verifier-latency-confined.sh')]
        start=datetime.datetime.now(datetime.timezone.utc).isoformat(); tick=time.monotonic()
        result=subprocess.run(command,cwd=case,env=env,text=True,capture_output=True,timeout=20)
        remaining=sorted(p.name for p in (case/'runner').iterdir())
        record=dict(config=c,command=command,start=start,end=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    elapsed_seconds=time.monotonic()-tick,exit=result.returncode,
                    stdout=result.stdout,stderr=result.stderr,scratch_remaining=remaining,
                    calls=(case/'calls.log').read_text() if (case/'calls.log').exists() else '',
                    observed_mode=(case/'observed-mode').read_text() if (case/'observed-mode').exists() else None)
        records.append(record)
        assert result.returncode==c['expected'], record
        assert bool(remaining)==bool(c.get('cleanup_fail')), record
        if not c.get('partial') and not c.get('discovery_exit'):
            assert record['observed_mode']==oct(int(c['mode'],8)), record
        if c.get('cleanup_fail'):
            assert f'primary exit {c["primary"]}' in result.stdout, record
            assert 'verifier cleanup failed' in result.stdout, record
        if c.get('tee_fail'):
            assert '/dev/full:' in result.stderr and 'space' in result.stderr, record
        if c.get('partial'):
            assert 'fixture original partial setup error' in result.stdout, record
        if c.get('download_exit'):
            assert 'fixture original provisioning error' in result.stdout, record
        if c.get('discovery_exit'):
            assert 'fixture original toolchain discovery error' in result.stdout, record
        if c.get('symlink'):
            assert (case/'outside/sentinel').read_text()=='external sentinel\n'
            assert (case/'outside').stat().st_mode & 0o777 == 0o555
        print(c['name'], 'PASS', 'pipeline exit', result.returncode, flush=True)
        (case/'runner').chmod(0o700)
        for state in (case/'runner').iterdir():
            # Only cleanup-failure fixtures leave an already empty owned root.
            state.rmdir()
        (case/'outside').chmod(0o700)
        shutil.rmtree(case)
finally:
    receipt.write_text(json.dumps(records,indent=2)+'\n')
if root.exists(): root.rmdir()
print('All fixtures offline; no real Go, product, performance or runner qualification.')
