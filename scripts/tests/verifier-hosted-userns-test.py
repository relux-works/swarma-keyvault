#!/usr/bin/python3
"""Inert offline controls of the production userns workflow step; no host writes."""
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
parser.add_argument('--other-release', action='store_true')
args = parser.parse_args()
assert args.receipt.is_absolute()
source = Path(__file__).resolve().parents[2]
fixtures = source/'scripts/tests/verifier-fixtures'
workflow = (source/'.github/workflows/hosted-ci.yml').read_text()
block = workflow_run(source, 'verifier-hosted-userns.sh')
timing = workflow_run(source, 'verifier-latency-confined.sh')
# Bind the tested shell to the real step, context and immutable checkout, and
# require package -> userns -> timing order with no conditional silent skip.
assert workflow.index('bash .ci-verifier-route/scripts/verifier-hosted-package.sh') < workflow.index(block.strip().splitlines()[0], workflow.index('Permit user namespaces'))
assert workflow.index('bash .ci-verifier-route/scripts/verifier-hosted-userns.sh') < workflow.index('bash scripts/verifier-latency-confined.sh')
step = workflow.split('      - name: Permit user namespaces', 1)[1].split('      - name:', 1)[0]
for key, value in [('VS_RUNNER_ENVIRONMENT','runner.environment'), ('VS_RUNNER_OS','runner.os'), ('VS_RUNNER_ARCH','runner.arch'), ('VS_WORKFLOW_SHA','github.workflow_sha')]:
    assert f'{key}: ${{{{ {value} }}}}' in step
assert '        env:\n' in step and '        if:' not in step
assert 'bash .ci-verifier-route/scripts/verifier-hosted-userns.sh' in block
assert 'ref: ${{ github.workflow_sha }}' in workflow
assert 'for log in verifier-setup.log verifier-userns.log verifier-p95.log' in workflow
head = subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'], text=True).strip()
root = Path(tempfile.mkdtemp(prefix='userns-controls.', dir=os.environ['TMPDIR']))
records = []
try:
    tools = root/'tools'; tools.mkdir(mode=0o700)
    stub = tools/'inert-command'
    stub.write_text('''#!/usr/bin/python3 -I
import json, os, pathlib, signal, sys
case=pathlib.Path(os.environ['FIXTURE_CASE'])
c=json.loads((case/'config.json').read_text())
name=pathlib.Path(sys.argv[0]).name
with (case/'calls.log').open('a') as f: f.write(name+' '+json.dumps(sys.argv[1:])+'\\n')
if name=='uname':
    print(c.get('actual_os','Linux') if sys.argv[1:] == ['-s'] else c.get('actual_arch','x86_64'))
elif name=='dpkg':
    assert sys.argv[1:]==['--print-architecture']; print(c.get('package_arch','amd64'))
elif name=='sudo':
    assert sys.argv[1:]==['sysctl','-w','kernel.apparmor_restrict_unprivileged_userns=0']
    if c.get('signal'):
        print('fixture raw write signal diagnostic',file=sys.stderr,flush=True)
        os.kill(os.getppid(),getattr(signal,'SIG'+c['signal'])); sys.exit(0)
    if c.get('write_exit'):
        print('fixture raw sysctl write failure',file=sys.stderr); sys.exit(c['write_exit'])
    os.execv(str(pathlib.Path(sys.argv[0]).parent/'sysctl'), ['sysctl']+sys.argv[2:])
elif name=='sysctl':
    if sys.argv[1:]==['-w','kernel.apparmor_restrict_unprivileged_userns=0']:
        (case/'written').write_text('0'); print('kernel.apparmor_restrict_unprivileged_userns = 0')
    else:
        assert sys.argv[1]=='-n' and sys.argv[2] in ['kernel.unprivileged_userns_clone','kernel.apparmor_restrict_unprivileged_userns']
        counter=case/'reads'; n=int(counter.read_text()) if counter.exists() else 0
        counter.write_text(str(n+1))
        phase='before' if n<2 else 'after'
        if c.get(phase+'_read_exit') and n%2==c.get('failed_knob',0):
            print('fixture raw '+phase+' read failure',file=sys.stderr); sys.exit(c[phase+'_read_exit'])
        print('1' if sys.argv[2].endswith('_clone') or not (case/'written').exists() or c.get('ineffective_write') else '0')
elif name=='bwrap':
    # Refuse before the preflight body or any product is executed.
    print('bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted',file=sys.stderr)
    sys.exit(42)
else:
    sys.exit('unexpected inert command')
''')
    stub.chmod(0o700)
    for name in ['uname','dpkg','sudo','sysctl','bwrap']:
        (tools/name).symlink_to(stub)
    configs = [dict(name='allowed', expected=0)]
    if args.other_release:
        configs = [dict(name='actual-other-release', expected=2, denied=True)]
    else:
        for name, update in [
            ('self-hosted', {'VS_RUNNER_ENVIRONMENT':'self-hosted'}),
            ('missing-environment', {'VS_RUNNER_ENVIRONMENT':None}),
            ('wrong-context-os', {'VS_RUNNER_OS':'macOS'}),
            ('wrong-context-arch', {'VS_RUNNER_ARCH':'ARM64'}),
            ('wrong-image', {'ImageOS':'ubuntu22'}),
            ('missing-image', {'ImageOS':None}),
            ('missing-image-version', {'ImageVersion':None}),
            ('not-actions', {'GITHUB_ACTIONS':'false'}),
            ('wrong-workflow', {'VS_WORKFLOW_PATH':'other.yml'}),
            ('missing-sha', {'VS_WORKFLOW_SHA':None}),
            ('wrong-sha', {'VS_WORKFLOW_SHA':'0'*40}),
            ('foreign-repository', {'VS_WORKFLOW_REPOSITORY':'other/project'}),
            ('missing-repository', {'GITHUB_REPOSITORY':None}),
            ('untrusted-text', {'VS_RUNNER_ENVIRONMENT':'github-hosted; sudo invalid'})]:
            configs.append(dict(name=name, env=update, expected=2, denied=True))
        configs += [dict(name='actual-Mac', actual_os='Darwin', expected=2, denied=True),
                    dict(name='actual-arm', actual_arch='aarch64', expected=2, denied=True),
                    dict(name='actual-package-arm', package_arch='arm64', expected=2, denied=True)]
        for knob in [0,1]:
            configs.append(dict(name=f'before-read-{knob}', before_read_exit=31, failed_knob=knob, expected=31, no_write=True))
            configs.append(dict(name=f'after-read-{knob}', after_read_exit=32, failed_knob=knob, expected=32))
        configs += [dict(name='write-failure',write_exit=17,expected=17),
                    dict(name='write-and-after-failure',write_exit=17,after_read_exit=32,expected=17),
                    dict(name='ineffective-write',ineffective_write=True,expected=2),
                    dict(name='tee-failure',tee_fail=True,expected=1),
                    dict(name='write-and-tee-failure',write_exit=17,tee_fail=True,expected=17),
                    dict(name='preflight-raw-failure',expected=0,preflight=True)]
        for sig, status in [('HUP',129),('INT',130),('TERM',143),('PIPE',141)]:
            for tee_fail in [False,True]:
                configs.append(dict(name=f'signal-{sig}-tee-{int(tee_fail)}',signal=sig,tee_fail=tee_fail,expected=status))
    for c in configs:
        case = root/c['name']; case.mkdir(mode=0o700)
        (case/'runner').mkdir(mode=0o700)
        (case/'config.json').write_text(json.dumps(c))
        (case/'.ci-verifier-route').symlink_to(source, target_is_directory=True)
        (case/'scripts').symlink_to(source/'scripts', target_is_directory=True)
        env = dict(PATH=f'{tools}:{fixtures}:/usr/bin:/bin', HOME=os.environ['HOME'],
                   TMPDIR=os.environ['TMPDIR'], XDG_CACHE_HOME=os.environ['XDG_CACHE_HOME'],
                   RUNNER_TEMP=str(case/'runner'),GITHUB_WORKSPACE=str(source), LC_ALL='C',FIXTURE_CASE=str(case),
                   GITHUB_ACTIONS='true',VS_RUNNER_ENVIRONMENT='github-hosted',VS_RUNNER_OS='Linux',VS_RUNNER_ARCH='X64',
                   VS_WORKFLOW_SHA=head,VS_WORKFLOW_PATH='.github/workflows/hosted-ci.yml',
                   VS_WORKFLOW_REPOSITORY='example/project',GITHUB_REPOSITORY='example/project',
                   ImageOS='ubuntu24',ImageVersion='offline-inert-fixture')
        for key,value in c.get('env',{}).items():
            if value is None: env.pop(key,None)
            else: env[key]=value
        tick=time.monotonic(); start=datetime.datetime.now(datetime.timezone.utc).isoformat()
        p=subprocess.run(['/bin/bash','-c',block],cwd=case,env=env,capture_output=True,text=True,timeout=15)
        calls=(case/'calls.log').read_text() if (case/'calls.log').exists() else ''
        r=dict(config=c,start=start,end=datetime.datetime.now(datetime.timezone.utc).isoformat(),elapsed_seconds=time.monotonic()-tick,
               exit=p.returncode,stdout=p.stdout,stderr=p.stderr,calls=calls,fixture_only=True,mutation=(case/'written').exists())
        records.append(r); args.receipt.write_text(json.dumps(records,indent=2)+'\n')
        assert p.returncode==c['expected'], r
        if c.get('denied'):
            assert 'sudo ' not in calls and 'sysctl ' not in calls and not r['mutation'], r
            assert 'FAIL' in p.stdout and 'setup passed' not in p.stdout, r
        else:
            for phase in ['BEFORE','AFTER']:
                for knob in ['kernel.unprivileged_userns_clone','kernel.apparmor_restrict_unprivileged_userns']:
                    assert f'{phase} {knob}' in p.stdout, r
            if c.get('no_write'): assert 'sudo ' not in calls and not r['mutation'], r
            else:
                lines=calls.splitlines()
                writes=[i for i,line in enumerate(lines) if line.startswith('sudo ')]
                reads=[i for i,line in enumerate(lines) if line.startswith('sysctl ["-n"')]
                assert len(writes)==1 and len(reads)==4 and reads[1]<writes[0]<reads[2], r
            if c.get('write_exit'): assert 'fixture raw sysctl write failure' in p.stdout, r
            if c.get('before_read_exit'): assert 'fixture raw before read failure' in p.stdout, r
            if c.get('after_read_exit'): assert 'fixture raw after read failure' in p.stdout, r
            if c.get('signal'): assert 'fixture raw write signal diagnostic' in p.stdout, r
            if c.get('tee_fail'): assert '/dev/full:' in p.stderr, r
            if p.returncode==0:
                assert 'AFTER kernel.apparmor_restrict_unprivileged_userns value=0 read_exit=0' in p.stdout, r
            if c.get('preflight'):
                q=subprocess.run(['/bin/bash','-c',timing],cwd=case,env=env,capture_output=True,text=True,timeout=15)
                r['preflight']=dict(exit=q.returncode,stdout=q.stdout,stderr=q.stderr,
                                    scratch_remaining=[x.name for x in (case/'runner').iterdir()])
                assert q.returncode==42 and 'Failed RTM_NEWADDR: Operation not permitted' in q.stdout, r
                assert 'No timing samples collected' in q.stdout and 'preflight passed' not in q.stdout, r
                after_calls=(case/'calls.log').read_text()
                assert after_calls.count('bwrap [')==1 and "['mod', 'download']" not in after_calls, r
                assert not r['preflight']['scratch_remaining'], r
        print(c['name'],'PASS',p.returncode,flush=True)
        shutil.rmtree(case)
finally:
    args.receipt.write_text(json.dumps(records,indent=2)+'\n')
    shutil.rmtree(root)
print('Offline inert context/policy controls only; no runtime permission or timing qualification.')
