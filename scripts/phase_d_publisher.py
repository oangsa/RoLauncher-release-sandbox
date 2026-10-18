"""Held Phase D integration entry; no activation or implicit signing authority."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import zipfile

import owner_evidence as evidence
import release_promotion as promotion
from phase_d import AuditedTransport, PhaseDEvidence, validated_fault


class FrozenArtifacts:
    """One bounded artifact observation per stage, shared by admission/source gate."""
    def __init__(self,call):self.call,self.cache=call,{}
    def __call__(self,path,*args,**kwargs):
        cacheable=not args and (re.fullmatch(r'/actions/runs/[1-9][0-9]*/artifacts\?per_page=100',path)
            or re.fullmatch(r'/actions/artifacts/[1-9][0-9]*/zip',path))
        if not cacheable:return self.call(path,*args,**kwargs)
        if path not in self.cache:
            evidence.require(len(self.cache)<4,'Artifact observation cache limit')
            self.cache[path]=self.call(path,**kwargs)
        return self.cache[path]


def verify_source_artifact(call,binding):
    """All channels: exact source ZIP/Git blobs before either challenge/mutation."""
    import hotfix_policy
    run=binding['source']
    result=call(f'/actions/runs/{run["id"]}/artifacts?per_page=100')
    evidence.require(result['total_count']==len(result['artifacts'])<100,'Source artifact inventory incomplete')
    name=('beta-windows' if binding['intent']['channel']=='beta' else 'release-files')+'-attempt-'+str(run['run_attempt'])
    matches=[a for a in result['artifacts'] if a['name']==name]
    evidence.require(len(matches)==1,'Source artifact ambiguous')
    artifact=matches[0]
    evidence.require(artifact['workflow_run']['id']==run['id'] and artifact['workflow_run']['head_sha']==run['head_sha']
        and 0<artifact['size_in_bytes']<=promotion.MAX_ARCHIVE_BYTES,'Source artifact provenance')
    raw=call('/actions/artifacts/'+str(artifact['id'])+'/zip',raw=True)
    evidence.require(len(raw)==artifact['size_in_bytes'] and artifact['digest']=='sha256:'+hashlib.sha256(raw).hexdigest(),
                     'Source artifact digest')
    prefix='rolauncher-v'+binding['intent']['version']
    end=raw.rfind(b'PK\x05\x06',max(0,len(raw)-65557))
    evidence.require(end>=0 and end+22<=len(raw),'Invalid source artifact footer')
    disk,directory_disk,local_count,count,size,offset,comment=struct.unpack_from('<4H2IH',raw,end+4)
    evidence.require(disk==directory_disk==0 and local_count==count==4 and size<=65536
        and offset+size==end and end+22+comment==len(raw),'Source outer directory budget')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        # The original promotion parser validates the complete ZIP before calling
        # this gate. Recheck exact inventory here before reading only source bytes.
        expected={prefix+s for s in ('-setup-x64.exe','-windows-x64.zip','-source.zip','-SHA256SUMS.txt')}
        evidence.require(len(archive.infolist())==4 and set(archive.namelist())==expected,'Source outer inventory')
        info=archive.getinfo(prefix+'-source.zip')
        evidence.require(info.file_size<=promotion.MAX_ENTRY_BYTES and not info.flag_bits&1,'Source entry budget')
        data=archive.read(info)
    hotfix_policy.verify_source(call,run['head_sha'],data)


class LifecycleEvidence(PhaseDEvidence):
    def gate(self,phase,call,binding):
        verify_source_artifact(call,binding)
        return super().gate(phase,call,binding)


def authorize_plan(plan, env, source):
    evidence.require(set(plan)=={'schema','repository_id','owner_id','trusted_sha','source_sha',
        'run_id','attempt','tag','channel','fault','faults_approved'},'Exact Phase D operation plan required')
    evidence.require(type(plan['schema']) is int and plan['schema']==1
        and type(plan['repository_id']) is int and plan['repository_id']==evidence.REPO_ID
        and type(plan['owner_id']) is int and plan['owner_id']==evidence.OWNER,'Phase D plan identity')
    evidence.require(env.get('GITHUB_REPOSITORY')==evidence.REPO
        and env.get('GITHUB_REPOSITORY_ID')==str(evidence.REPO_ID)
        and env.get('GITHUB_EVENT_NAME')=='workflow_run'
        and env.get('GITHUB_WORKFLOW_REF')==evidence.REPO+'/'+evidence.WORKFLOW+'@refs/heads/main',
        'Trusted Phase D publisher environment required')
    evidence.require(all(isinstance(plan[k],str) and re.fullmatch('[a-f0-9]{40}',plan[k])
        for k in ('trusted_sha','source_sha')) and plan['trusted_sha']==env.get('GITHUB_SHA')
        and plan['source_sha']==source,'Phase D trusted/source mismatch')
    evidence.require(all(type(plan[k]) is int and plan[k]>0 and str(plan[k])==env.get(v)
        for k,v in (('run_id','GITHUB_RUN_ID'),('attempt','GITHUB_RUN_ATTEMPT'))),'Phase D run/attempt mismatch')
    evidence.require(plan['channel'] in ('stable','beta') and isinstance(plan['tag'],str)
        and re.fullmatch(('beta-v' if plan['channel']=='beta' else 'v')+r'0\.0\.(900|901)',plan['tag']),
        'Only reviewed synthetic fixture names permitted')
    evidence.require(type(plan['faults_approved']) is bool and
        (plan['fault'] is None or plan['faults_approved'] is True),'Separate live fault approval required')
    if plan['fault'] is not None:
        evidence.require(isinstance(plan['fault'],dict) and plan['fault'].get('stage') in ('stage','finish'),
                         'Fault must bind one publisher stage')
        validated_fault({k:v for k,v in plan['fault'].items() if k!='stage'})


def scoped_call(call,plan):
    release_ids=set()
    def scoped(path,method='GET',body=None,**kwargs):
        if method!='GET':
            evidence.require(method in ('POST','PATCH'),'Phase D publication never deletes')
            if path=='/git/refs':
                evidence.require(method=='POST' and body=={'ref':'refs/tags/'+plan['tag'],'sha':plan['source_sha']},'Plan tag mismatch')
            elif path=='/releases':
                evidence.require(method=='POST' and body['tag_name']==plan['tag']
                    and body['target_commitish']==plan['source_sha'] and body['draft'] is True
                    and body['prerelease']==(plan['channel']=='beta'),'Plan draft mismatch')
            elif path.startswith('https://uploads.github.com/'):
                version=plan['tag'].removeprefix('beta-v').removeprefix('v')
                name=path.split('?name=',1)[-1]
                evidence.require(method=='POST' and (name=='release-promotion.json'
                    or name.startswith('rolauncher-v'+version+'-')),'Plan asset mismatch')
                match=re.fullmatch('https://uploads.github.com/repos/'+re.escape(evidence.REPO)+r'/releases/([1-9][0-9]*)/assets\?name=[A-Za-z0-9._-]+',path)
                evidence.require(match and int(match[1]) in release_ids,'Plan upload Release ID mismatch')
            else:
                evidence.require(method=='PATCH' and re.fullmatch('/releases/[1-9][0-9]*',path)
                    and int(path.rsplit('/',1)[1]) in release_ids
                    and body=={'draft':False,'prerelease':plan['channel']=='beta',
                               'make_latest':'false' if plan['channel']=='beta' else 'true'},'Plan publication mismatch')
        result=call(path,method,body,**kwargs)
        if result is not None and ((path=='/releases' and method=='POST')
            or (path=='/releases/tags/'+plan['tag'] and method=='GET')):
            evidence.require(type(result['id']) is int and result['id']>0
                and result['tag_name']==plan['tag'] and result['target_commitish']==plan['source_sha']
                and result['prerelease']==(plan['channel']=='beta'),'Plan Release readback mismatch')
            release_ids.add(result['id'])
        return result
    return scoped


def main(argv=None,policy_path=evidence.POLICY):
    # Both flags require separate owner activation. Shipped workflow remains false &&.
    if os.environ.get('RELEASE_PROMOTION_ENABLED')!='true' or os.environ.get('PHASE_D_LIVE_AUTHORIZED')!='true':
        print('Phase D live operations disabled; explicit separate owner authorization required.')
        return 'disabled'
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage',choices=('prepare','stage','finish'),required=True)
    parser.add_argument('--plan',type=Path)
    args=parser.parse_args(argv)
    plan=evidence.parse(args.plan.read_bytes() if args.plan else os.environ.get('PHASE_D_OPERATION_PLAN','').encode())
    # Reviewed scope may bind a future run at runtime; owner signatures still bind
    # its exact challenge/run/attempt independently. This config grants no signature.
    if 'run_id' not in plan and 'attempt' not in plan:
        plan=dict(plan,run_id=int(os.environ['GITHUB_RUN_ID']),attempt=int(os.environ['GITHUB_RUN_ATTEMPT']))
    event=evidence.parse(Path(os.environ['GITHUB_EVENT_PATH']).read_bytes(),evidence.MAX_API)
    authorize_plan(plan,os.environ,event['workflow_run']['head_sha'])
    evidence.load_policy(policy_path)  # Existing enrolled contract; never self-enroll.
    transport=LifecycleEvidence(args.stage,policy_path)
    ledger=Path('owner-evidence')/f'phase-d-{plan["run_id"]}-{plan["attempt"]}-{args.stage}.jsonl'
    fault=dict(plan['fault']) if plan['fault'] else None
    if fault:
        stage=fault.pop('stage')
        if stage!=args.stage:fault=None
    audit=AuditedTransport(None,ledger,fault,fresh=transport.fresh)
    audit.call=scoped_call(promotion.github_api(os.environ['GITHUB_TOKEN'],observer=audit.observe_status),plan)
    try:
        try:result=promotion.promote_event(FrozenArtifacts(audit),event,evidence=transport)
        except evidence.ChallengeReady:result='challenge-ready'
        if args.stage=='prepare':
            with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
                output.write('admitted='+('true' if result=='challenge-ready' else 'false')+'\n')
        print(result)
        return result
    finally:
        audit.close()


if __name__=='__main__':main()
