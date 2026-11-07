#!/usr/bin/python3
"""Descriptor identity and traversal refusals; offline, no product execution."""
import datetime
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

program=pathlib.Path(__file__).resolve().parents[2]/'scripts/verifier-private-cleanup.py'
root=pathlib.Path(os.environ['TMPDIR'])/'cleanup-boundaries'
root.mkdir(mode=0o700)
records=[]
def invoke(parent,state,name,label):
    pf=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
    sf=os.open(state,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        cmd=['/usr/bin/timeout','--signal=TERM','--kill-after=2s','12s',
             '/usr/bin/python3','-I',str(program),str(pf),str(sf),name]
        start=datetime.datetime.now(datetime.timezone.utc).isoformat(); tick=time.monotonic()
        p=subprocess.run(cmd,pass_fds=(pf,sf),capture_output=True,text=True,timeout=16)
        records.append(dict(name=label,command=cmd,start=start,end=datetime.datetime.now(datetime.timezone.utc).isoformat(),elapsed_seconds=time.monotonic()-tick,exit=p.returncode,stdout=p.stdout,stderr=p.stderr))
        assert p.returncode==1, records[-1]
    finally:
        os.close(pf);os.close(sf)

state=root/'verifier-private.original';state.mkdir(mode=0o700)
(state/'sentinel').write_text('owned original')
replacement=root/'verifier-private.replacement';replacement.mkdir(mode=0o700)
(replacement/'sentinel').write_text('other state')
invoke(root,state,replacement.name,'different-inode')
assert (state/'sentinel').read_text()=='owned original'
assert (replacement/'sentinel').read_text()=='other state'
invoke(root,state,'../verifier-private.original','traversal-name')
invoke(root,state,'..','parent-name')
invoke(root,state,'unrelated','non-invocation-name')
# Root symlink replacement is rejected before touching the original state.
link=root/'verifier-private.link';link.symlink_to(state,target_is_directory=True)
invoke(root,state,link.name,'symlink-root-entry')
assert (state/'sentinel').read_text()=='owned original'
link.unlink()
# Directories beyond the depth budget cause a bounded failure, not broad rm.
deep=root/'verifier-private.deep';deep.mkdir(mode=0o700)
p=deep
for n in range(130):
    p=p/'d';p.mkdir(mode=0o700)
(p/'sentinel').write_text('depth bound')
invoke(root,deep,deep.name,'depth-limit')
assert (p/'sentinel').read_text()=='depth bound'
# A separate outer-bwrap mount fixture supplies a real read-only child mount.
if len(sys.argv)>1:
    mounted=pathlib.Path(sys.argv[1])
    original_mode=(mounted/'blocked').stat().st_mode & 0o777
    invoke(mounted.parent,mounted,mounted.name,'mount-boundary')
    assert (mounted/'blocked/README').is_file()
    assert (mounted/'blocked').stat().st_mode & 0o777 == original_mode
pathlib.Path(os.environ['TMPDIR'],'boundary-cases.json').write_text(json.dumps(records,indent=2)+'\n')
shutil.rmtree(root)
for r in records: print(r['name'],'PASS refusal exit',r['exit'])
