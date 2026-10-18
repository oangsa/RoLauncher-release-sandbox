"""Held Phase D integration entry; no activation or implicit signing authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import zipfile

import owner_evidence as evidence
from phase_d_capacity import ArtifactFile, ArtifactWorkspace
import release_promotion as promotion
from phase_d import AuditedTransport, PhaseDEvidence, validated_fault


class FrozenArtifacts:
    """One bounded artifact observation per stage, shared by admission/source gate."""
    def __init__(self, call):
        self.call, self.cache, self.workspace = call, {}, None

    def bind_workspace(self, workspace):
        evidence.require(self.workspace is None or self.workspace is workspace, 'Artifact workspace changed')
        self.workspace=workspace

    def observe_immutable_visibility(self, visibility):
        observer = getattr(self.call, 'observe_immutable_visibility', None)
        evidence.require(callable(observer), 'Audit transport cannot record immutable-settings visibility')
        observer(visibility)

    def authorize_release(self, release):
        authorizer = getattr(self.call, 'authorize_release', None)
        if callable(authorizer):
            authorizer(release)

    def close(self):
        if self.workspace is not None:
            self.workspace.close()

    def __call__(self, path, *args, **kwargs):
        cacheable = not args and (re.fullmatch(r'/actions/runs/[1-9][0-9]*/artifacts\?per_page=100', path)
            or re.fullmatch(r'/actions/artifacts/[1-9][0-9]*/zip', path))
        if not cacheable:
            return self.call(path, *args, **kwargs)
        if path not in self.cache:
            evidence.require(len(self.cache) < 4, 'Artifact observation cache limit')
            if path.endswith('/zip'):
                if self.workspace is None:
                    self.workspace = ArtifactWorkspace(promotion.capacity_policy())
                artifact_id = int(path.split('/')[3])
                sink = kwargs.get('sink') or self.workspace.sink(
                    f'artifact-{artifact_id}.zip', self.workspace.policy.max_archive_bytes, 'archive')
                try:
                    result = self.call(path, raw=True, sink=sink)
                    if isinstance(result, bytes):
                        for offset in range(0, len(result), self.workspace.policy.max_buffer_bytes):
                            sink.write(result[offset:offset + self.workspace.policy.max_buffer_bytes])
                    self.cache[path] = sink.finish()
                except BaseException:
                    sink.abort()
                    raise
            else:
                self.cache[path] = self.call(path, **kwargs)
        return self.cache[path]


def _verify_source_artifact(call,binding,workspace):
    """All channels: exact source ZIP/Git blobs before either challenge/mutation."""
    import hotfix_policy
    run=binding['source']
    prefix='rolauncher-v'+binding['intent']['version']
    source_name=prefix+'-source.zip'
    if workspace is not None and source_name in workspace.release_files:
        source_file=workspace.release_files[source_name]
        evidence.require(isinstance(source_file,ArtifactFile),'Source artifact was not staged as a bounded file')
        hotfix_policy.verify_source_file(call,run['head_sha'],source_file)
        return
    result=call(f'/actions/runs/{run["id"]}/artifacts?per_page=100')
    evidence.require(result['total_count']==len(result['artifacts'])<100,'Source artifact inventory incomplete')
    name=('beta-windows' if binding['intent']['channel']=='beta' else 'release-files')+'-attempt-'+str(run['run_attempt'])
    matches=[a for a in result['artifacts'] if a['name']==name]
    evidence.require(len(matches)==1,'Source artifact ambiguous')
    artifact=matches[0]
    evidence.require(artifact['workflow_run']['id']==run['id'] and artifact['workflow_run']['head_sha']==run['head_sha']
        and 0<artifact['size_in_bytes']<=promotion.capacity_policy().max_archive_bytes,'Source artifact provenance')
    raw=call('/actions/artifacts/'+str(artifact['id'])+'/zip',raw=True)
    if workspace is None:workspace=ArtifactWorkspace(promotion.capacity_policy())
    if isinstance(raw,ArtifactFile):
        raw_size,raw_digest=raw.verify()
        raw_path=raw.path
    else:
        raw_size=len(raw)
        raw_digest=hashlib.sha256(raw).hexdigest()
        raw_file=workspace.write_bytes(f'artifact-{artifact["id"]}.zip',raw,workspace.policy.max_archive_bytes,'archive')
        raw_path=raw_file.path
    evidence.require(raw_size==artifact['size_in_bytes'] and artifact['digest']=='sha256:'+raw_digest,
                     'Source artifact digest')
    promotion._archive_footer(raw_path,4,workspace.policy)
    workspace.open_archive()
    try:
      with zipfile.ZipFile(raw_path) as archive:
        expected={prefix+s for s in ('-setup-x64.exe','-windows-x64.zip','-source.zip','-SHA256SUMS.txt')}
        evidence.require(len(archive.infolist())==4 and set(archive.namelist())==expected,'Source outer inventory')
        info=archive.getinfo(prefix+'-source.zip')
        evidence.require(info.file_size<=workspace.policy.max_entry_bytes and not info.flag_bits&1,'Source entry budget')
        source_file=workspace.source_files.get(source_name)
        if source_file is None:
            sink=workspace.sink(f'source-{artifact["id"]}.zip',workspace.policy.max_entry_bytes,'expanded')
            try:
                written=0
                with archive.open(info) as source:
                    while chunk:=source.read(workspace.policy.max_buffer_bytes):written+=sink.write(chunk)
                evidence.require(written==info.file_size,'Source entry size mismatch')
                source_file=sink.finish()
                workspace.source_files[source_name]=source_file
            except BaseException:
                sink.abort()
                raise
      hotfix_policy.verify_source_file(call,run['head_sha'],source_file)
    finally:
      workspace.close_archive()


def verify_source_artifact(call,binding,workspace=None):
    workspace=workspace or getattr(call,'workspace',None)
    owns_workspace=workspace is None
    if owns_workspace:
        workspace=ArtifactWorkspace(promotion.capacity_policy())
        binder=getattr(call,'bind_workspace',None)
        if callable(binder):
            binder(workspace)
            owns_workspace=False
    try:
        return _verify_source_artifact(call,binding,workspace)
    finally:
        if owns_workspace:workspace.close()


class LifecycleEvidence(PhaseDEvidence):
    def __init__(self,stage,policy_path=evidence.POLICY,state=evidence.STATE,plan=None):
        super().__init__(stage,policy_path,state)
        self.plan=plan

    def gate(self,phase,call,binding):
        intent=binding.get('intent') if isinstance(binding,dict) else None
        source=binding.get('source') if isinstance(binding,dict) else None
        channel=self.plan.get('channel') if isinstance(self.plan,dict) else None
        version=intent.get('version') if isinstance(intent,dict) else None
        expected_channel={'stable':'stable','beta':'beta'}.get(channel)
        expected_tag=('beta-v' if channel=='beta' else 'v')+version if isinstance(version,str) else None
        evidence.require(expected_channel is not None and isinstance(intent,dict)
            and intent.get('channel')==expected_channel
            and self.plan.get('tag')==expected_tag and isinstance(source,dict)
            and source.get('head_sha')==self.plan.get('source_sha'),
            'Phase D operation plan does not match admitted intent/source')
        verify_source_artifact(call,binding,workspace=getattr(self,'workspace',None))
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
    mutable_release_ids=set()
    numeric_readbacks={}
    tag_create_attempted=False
    release_create_attempted=False
    version=plan['tag'].removeprefix('beta-v').removeprefix('v')
    allowed_assets={'release-promotion.json'} | {
        'rolauncher-v'+version+suffix for suffix in (
            '-setup-x64.exe','-windows-x64.zip','-source.zip','-linux-x64.tar.gz','-SHA256SUMS.txt')}

    def identity_matches(release,release_id):
        return (isinstance(release,dict) and type(release.get('id')) is int
            and release['id']==release_id and release.get('tag_name')==plan['tag']
            and release.get('target_commitish')==plan['source_sha']
            and release.get('prerelease') is (plan['channel']=='beta'))

    def authorize_release(release):
        evidence.require(isinstance(release,dict) and type(release.get('id')) is int
            and release['id']>0,'Malformed validated Release ID')
        release_id=release['id']
        readback=numeric_readbacks.get(release_id)
        evidence.require(readback is not None and readback is release
            and identity_matches(readback,release_id),'Release ID lacks matching numeric readback')
        body=release.get('body')
        evidence.require(isinstance(body,str)
            and len(re.findall(r'<!-- release-promotion:[a-f0-9]{64} -->',body))==1,
            'Release ID lacks one valid receipt marker')
        assets=release.get('assets')
        evidence.require(isinstance(assets,list),'Release ID assets are malformed')
        names=[]
        for asset in assets:
            evidence.require(isinstance(asset,dict) and isinstance(asset.get('name'),str)
                and asset['name'] in allowed_assets and type(asset.get('id')) is int
                and type(asset.get('size')) is int and asset['size']>=0
                and isinstance(asset.get('digest'),str)
                and re.fullmatch(r'sha256:[a-f0-9]{64}',asset['digest'])
                and asset.get('state')=='uploaded','Release ID has unvalidated asset metadata')
            names.append(asset['name'])
        evidence.require(len(names)==len(set(names)),'Release ID has duplicate asset names')
        if release.get('draft') is True:
            mutable_release_ids.add(release_id)

    def scoped(path,method='GET',body=None,**kwargs):
        nonlocal tag_create_attempted,release_create_attempted
        if method!='GET':
            evidence.require(method in ('POST','PATCH'),'Phase D publication never deletes')
            if path=='/git/refs':
                evidence.require(method=='POST' and not tag_create_attempted
                    and body=={'ref':'refs/tags/'+plan['tag'],'sha':plan['source_sha']},'Plan tag mismatch')
                tag_create_attempted=True
            elif path=='/releases':
                evidence.require(method=='POST' and not release_create_attempted
                    and not mutable_release_ids and isinstance(body,dict)
                    and set(body)=={'tag_name','target_commitish','name','body','draft','prerelease','make_latest'}
                    and body['tag_name']==plan['tag'] and body['target_commitish']==plan['source_sha']
                    and body['name']=='RoLauncher '+version and body['draft'] is True
                    and body['prerelease']==(plan['channel']=='beta') and body['make_latest']=='false'
                    and isinstance(body['body'],str)
                    and len(re.findall(r'<!-- release-promotion:[a-f0-9]{64} -->',body['body']))==1,
                    'Plan draft mismatch')
                release_create_attempted=True
            elif path.startswith('https://uploads.github.com/'):
                match=re.fullmatch('https://uploads.github.com/repos/'+re.escape(evidence.REPO)+r'/releases/([1-9][0-9]*)/assets\?name=[A-Za-z0-9._-]+',path)
                evidence.require(method=='POST' and match and path.rsplit('=',1)[1] in allowed_assets
                    and int(match[1]) in mutable_release_ids
                    and numeric_readbacks.get(int(match[1]),{}).get('draft') is True,
                    'Plan upload Release ID or asset mismatch')
            else:
                match=re.fullmatch('/releases/([1-9][0-9]*)',path)
                evidence.require(method=='PATCH' and match and int(match[1]) in mutable_release_ids
                    and numeric_readbacks.get(int(match[1]),{}).get('draft') is True
                    and identity_matches(numeric_readbacks[int(match[1])],int(match[1]))
                    and body=={'draft':False,'prerelease':plan['channel']=='beta',
                               'make_latest':'false' if plan['channel']=='beta' else 'true'},'Plan publication mismatch')
        result=call(path,method,body,**kwargs)
        numeric=re.fullmatch('/releases/([1-9][0-9]*)',path) if method=='GET' else None
        if numeric:
            release_id=int(numeric[1])
            evidence.require(isinstance(result,dict) and type(result.get('id')) is int
                and result['id']==release_id,'Plan numeric Release readback mismatch')
            numeric_readbacks[release_id]=result
        return result
    scoped.authorize_release=authorize_release
    return scoped


def main(argv=None,policy_path=evidence.POLICY):
    # Both runtime flags require separate owner activation.
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
    transport=LifecycleEvidence(args.stage,policy_path,plan=plan)
    ledger=Path('owner-evidence')/f'phase-d-{plan["run_id"]}-{plan["attempt"]}-{args.stage}.jsonl'
    fault=dict(plan['fault']) if plan['fault'] else None
    if fault:
        stage=fault.pop('stage')
        if stage!=args.stage:fault=None
    audit=AuditedTransport(None,ledger,fault,fresh=transport.fresh)
    scoped=scoped_call(promotion.github_api(os.environ['GITHUB_TOKEN'],observer=audit.observe_status),plan)
    evidence.require(callable(getattr(scoped,'authorize_release',None)),
                     'Live Publisher scope lacks Release-ID admission')
    audit.call=scoped
    try:
        try:result=promotion.promote_event(FrozenArtifacts(audit),event,channel=plan['channel'],evidence=transport)
        except evidence.ChallengeReady:result='challenge-ready'
        if args.stage=='prepare':
            with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
                output.write('admitted='+('true' if result=='challenge-ready' else 'false')+'\n')
        print(result)
        return result
    finally:
        audit.close()


if __name__=='__main__':main()
