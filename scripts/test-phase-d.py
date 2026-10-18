"""Phase D public seams: audited transport, strict evidence and inert fixtures."""
import base64
import copy
import importlib.util
import io
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from urllib.error import HTTPError
import unittest
from unittest.mock import patch

import phase_d
import owner_evidence as evidence
import release_promotion as promotion

spec = importlib.util.spec_from_file_location('phase_d_owner', Path(__file__).with_name('test-owner-evidence.py'))
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)


class AuditTests(unittest.TestCase):
    def test_live_entry_is_closed_without_explicit_authority(self):
        import phase_d_publisher as live
        with patch.dict(os.environ,{},clear=True),patch.object(promotion,'github_api') as network:
            self.assertEqual(live.main([]),'disabled')
            network.assert_not_called()

    def test_each_activation_flag_is_required_and_plan_errors_precede_transport(self):
        import phase_d_publisher as live
        base=dict(GITHUB_REPOSITORY=evidence.REPO,GITHUB_REPOSITORY_ID=str(evidence.REPO_ID),
            GITHUB_WORKFLOW_REF=evidence.REPO+'/'+evidence.WORKFLOW+'@refs/heads/main',
            GITHUB_EVENT_NAME='workflow_run',GITHUB_SHA='d'*40,GITHUB_RUN_ID='99',GITHUB_RUN_ATTEMPT='1')
        for enabled in ({},{'RELEASE_PROMOTION_ENABLED':'true'},
                        {'PHASE_D_LIVE_AUTHORIZED':'true'}):
            with self.subTest(enabled=enabled),patch.dict(os.environ,{**base,**enabled},clear=True),\
                    patch.object(promotion,'github_api') as network:
                self.assertEqual(live.main(['--stage','prepare']),'disabled')
                network.assert_not_called()
        for plan in ('','{'):
            with self.subTest(plan=plan),patch.dict(os.environ,{**base,
                    'RELEASE_PROMOTION_ENABLED':'true','PHASE_D_LIVE_AUTHORIZED':'true',
                    'PHASE_D_OPERATION_PLAN':plan},clear=True),patch.object(promotion,'github_api') as network:
                with self.assertRaises(ValueError):live.main(['--stage','prepare'])
                network.assert_not_called()

    def test_beta_event_cannot_enter_stable_operation_scope(self):
        event=dict(repository=dict(default_branch='main',id=evidence.REPO_ID,full_name=evidence.REPO),
            workflow_run=dict(id=12,run_attempt=1,head_sha='a'*40))
        writes=[]
        def simulated_github(path,method='GET',body=None,**kwargs):
            if method!='GET':writes.append((path,method))
            return dict(run_attempt=1,head_sha='a'*40,status='completed',conclusion='success',
                path='.github/workflows/beta-release.yml')
        with self.assertRaisesRegex(ValueError,'Wrong publication channel'):
            promotion.promote_event(simulated_github,event,channel='stable',evidence=object())
        self.assertEqual(writes,[])

    def test_live_entry_passes_plan_channel_into_event_reconciliation(self):
        import phase_d_publisher as live
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]) as folder:
            event_path=Path(folder)/'event.json'
            event_path.write_text(json.dumps(dict(
                repository=dict(default_branch='main',id=evidence.REPO_ID,full_name=evidence.REPO),
                workflow_run=dict(id=12,run_attempt=1,head_sha='a'*40))),encoding='utf-8')
            plan=dict(schema=1,repository_id=evidence.REPO_ID,owner_id=evidence.OWNER,
                trusted_sha='d'*40,source_sha='a'*40,run_id=99,attempt=1,tag='v0.0.900',
                channel='stable',fault=None,faults_approved=False)
            writes=[]
            def simulated_github(path,method='GET',body=None,**kwargs):
                if method!='GET':writes.append((path,method))
                return dict(run_attempt=1,head_sha='a'*40,status='completed',conclusion='success',
                    path='.github/workflows/beta-release.yml')
            cwd=Path.cwd()
            try:
                os.chdir(folder)
                with patch.dict(os.environ,dict(GITHUB_REPOSITORY=evidence.REPO,
                        GITHUB_REPOSITORY_ID=str(evidence.REPO_ID),
                        GITHUB_WORKFLOW_REF=evidence.REPO+'/'+evidence.WORKFLOW+'@refs/heads/main',
                        GITHUB_EVENT_NAME='workflow_run',GITHUB_SHA='d'*40,GITHUB_RUN_ID='99',
                        GITHUB_RUN_ATTEMPT='1',GITHUB_EVENT_PATH=str(event_path),
                        RELEASE_PROMOTION_ENABLED='true',PHASE_D_LIVE_AUTHORIZED='true',
                        PHASE_D_OPERATION_PLAN=json.dumps(plan),GITHUB_TOKEN='synthetic-token'),clear=True),\
                        patch.object(promotion,'github_api',return_value=simulated_github):
                    with self.assertRaisesRegex(ValueError,'Wrong publication channel'):
                        live.main(['--stage','prepare'])
            finally:
                os.chdir(cwd)
            self.assertEqual(writes,[])

    def test_activation_workflow_contract_is_guarded_and_uses_phase_d_for_every_stage(self):
        root=Path(__file__).resolve().parents[1]
        publisher=(root/'.github/workflows/release-promotion.yml').read_text(encoding='utf-8')
        beta=(root/'.github/workflows/beta-release.yml').read_text(encoding='utf-8')
        poc=(root/'.github/workflows/owner-evidence-dry-run.yml').read_text(encoding='utf-8')
        job=publisher.split('  promote:\n',1)[1]
        guard=job.split('    runs-on:',1)[0]
        self.assertNotIn('false &&',guard)
        for condition in ("vars.RELEASE_PROMOTION_ENABLED == 'true'",
                          "vars.PHASE_D_LIVE_AUTHORIZED == 'true'",
                          "github.repository == 'oangsa/RoLauncher-release-sandbox'",
                          "github.repository_id == '1423257712'",
                          "github.event.workflow_run.event == 'push'",
                          "github.event.workflow_run.conclusion == 'success'",
                          "github.event.workflow_run.head_repository.full_name == github.repository",
                          "github.event.workflow_run.head_branch == 'main'",
                          "github.event.workflow_run.name == 'Beta release'"):
            self.assertIn(condition,guard)
        for stage in ('prepare','stage','finish'):
            self.assertIn(f'python3 scripts/phase_d_publisher.py --stage {stage}',job)
        self.assertEqual(job.count('PHASE_D_LIVE_AUTHORIZED: ${{ vars.PHASE_D_LIVE_AUTHORIZED }}'),3)
        self.assertEqual(job.count('PHASE_D_OPERATION_PLAN: ${{ vars.PHASE_D_OPERATION_PLAN }}'),3)
        self.assertEqual(job.count('RELEASE_PROMOTION_ENABLED: ${{ vars.RELEASE_PROMOTION_ENABLED }}'),3)
        self.assertEqual(job.count('GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}'),3)
        self.assertIn('ref: ${{ github.sha }}',job)
        self.assertIn('persist-credentials: false',job)
        self.assertIn('actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683',job)
        self.assertIn('actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',job)
        self.assertIn('cancel-in-progress: false',publisher)
        self.assertIn('group: protected-release-promotion',publisher)
        self.assertIn('contents: write',job)
        self.assertIn('actions: read',job)
        self.assertIn('pull-requests: read',job)
        self.assertIn('issues: read',job)
        self.assertNotIn('administration:',job)
        self.assertNotIn('id-token:',job)
        self.assertIn('timeout-minutes: 60',job)
        self.assertEqual(beta.count('false &&'),2)
        self.assertIn('false &&',poc)
        self.assertNotIn('workflow_dispatch:',publisher)

    def test_operation_plan_binds_exact_trusted_source_run_and_fixture(self):
        import phase_d_publisher as live
        env=dict(GITHUB_REPOSITORY=evidence.REPO,GITHUB_REPOSITORY_ID=str(evidence.REPO_ID),
                 GITHUB_WORKFLOW_REF=evidence.REPO+'/'+evidence.WORKFLOW+'@refs/heads/main',
                 GITHUB_EVENT_NAME='workflow_run',GITHUB_SHA='d'*40,GITHUB_RUN_ID='99',GITHUB_RUN_ATTEMPT='1')
        plan=dict(schema=1,repository_id=evidence.REPO_ID,owner_id=evidence.OWNER,
                  trusted_sha='d'*40,source_sha='a'*40,run_id=99,attempt=1,tag='v0.0.900',
                  channel='stable',fault=None,faults_approved=False)
        live.authorize_plan(plan,env,'a'*40)
        for field,bad in (('repository_id',1406138209),('owner_id',1),('source_sha','b'*40),
                          ('trusted_sha','f'*40),('run_id',100),('attempt',2),('tag','v1.7.1'),
                          ('fault',{'mutation':1,'when':'after'})):
            with self.subTest(field=field),self.assertRaises(ValueError):
                live.authorize_plan(dict(plan,**{field:bad}),env,'a'*40)
        with self.assertRaises(ValueError):
            live.authorize_plan(dict(plan,faults_approved=True,
                fault=dict(stage='finish',mutation=1,when='delay-after',seconds=131)),env,'a'*40)

    def test_publication_scope_pins_release_id_before_upload_or_patch(self):
        import phase_d_publisher as live
        writes=[]
        release=dict(id=50,tag_name='v0.0.900',target_commitish='a'*40,prerelease=False,
            draft=True,body='<!-- release-promotion:'+'f'*64+' -->',assets=[])
        def backend(path,method='GET',body=None,**kwargs):
            if method!='GET':writes.append(path)
            if path=='/releases/50':return dict(release)
            if path=='/releases?per_page=100&page=1':return [dict(release)]
            if path=='/releases?per_page=100&page=2':return []
            if path=='/releases/tags/v0.0.900':return dict(release)
            return dict(release)
        api=live.scoped_call(backend,dict(tag='v0.0.900',source_sha='a'*40,channel='stable'))
        body=dict(draft=False,prerelease=False,make_latest='true')
        with self.assertRaises(ValueError):api('/releases/999','PATCH',body)
        self.assertEqual(writes,[])
        with self.assertRaisesRegex(ValueError,'numeric readback'):
            api.authorize_release(release)
        listed=api('/releases?per_page=100&page=1')[0]
        with self.assertRaisesRegex(ValueError,'numeric readback'):
            api.authorize_release(listed)
        numeric=api('/releases/50')
        with self.assertRaises(ValueError):
            api('https://uploads.github.com/repos/'+evidence.REPO+'/releases/999/assets?name=release-promotion.json',
                'POST',binary=b'inert')
        self.assertEqual(writes,[])
        api.authorize_release(numeric)
        with self.assertRaisesRegex(ValueError,'asset mismatch'):
            api('https://uploads.github.com/repos/'+evidence.REPO+'/releases/50/assets?name=rolauncher-v0.0.900-extra.bin',
                'POST',binary=b'inert')
        with self.assertRaises(ValueError):api('/releases/50','DELETE')
        self.assertEqual(writes,[])
        api('/releases/50','PATCH',body)
        self.assertEqual(writes,['/releases/50'])
    def test_large_fixture_capacity_and_streamed_bytes(self):
        import phase_d_fixtures as large
        from phase_d_capacity import DEFAULT_CAPACITY, TWO_X_STRESS_TEST_CAPACITY
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder)/'inert.bin'
            large.write_inert(target,4096)
            self.assertEqual(target.stat().st_size,4096)
            self.assertFalse(target.read_bytes().startswith(b'MZ'))
            self.assertEqual(target.read_bytes()[100:],bytes(3996))
            with self.assertRaises(ValueError):large.capacity(512*1024**2,256*1024**2)
            self.assertEqual(large.capacity(256*1024**2,128*1024**2)['windows_bytes'],256*1024**2)
            stress=large.capacity(512*1024**2,256*1024**2,profile='2x-test')
            self.assertEqual(stress['entry_limit'],TWO_X_STRESS_TEST_CAPACITY.max_entry_bytes)
            self.assertEqual(DEFAULT_CAPACITY.max_archive_bytes,256*1024**2)
            self.assertEqual(DEFAULT_CAPACITY.max_entry_bytes,256*1024**2)
            self.assertEqual(DEFAULT_CAPACITY.max_expanded_bytes,512*1024**2)

    def test_capacity_workspace_enforces_file_aggregate_disk_and_time_limits(self):
        from phase_d_capacity import ArtifactWorkspace, CapacityPolicy

        policy = CapacityPolicy(max_archive_bytes=8, max_entry_bytes=4, max_expanded_bytes=6,
            max_temp_disk_bytes=9, max_buffer_bytes=4, max_processing_seconds=1)
        with tempfile.TemporaryDirectory() as folder:
            with ArtifactWorkspace(policy, parent=folder) as workspace:
                archive = workspace.sink('archive.zip', 9, 'archive')
                with self.assertRaisesRegex(ValueError, 'size limit'):
                    archive.write(b'123456789')
                archive.abort()

                expanded = workspace.sink('expanded.bin', 4, 'expanded')
                expanded.write(b'1234')
                staged = workspace.sink('staged.bin', 6, 'staging')
                staged.write(b'1234')
                with self.assertRaisesRegex(ValueError, 'disk budget'):
                    staged.write(b'56')
                staged.abort()
                expanded.finish()

                remainder = workspace.sink('remainder.bin', 4, 'expanded')
                remainder.write(b'12')
                remainder.finish()
                over_expanded = workspace.sink('over-expanded.bin', 1, 'expanded')
                with self.assertRaisesRegex(ValueError, 'decompression size'):
                    over_expanded.write(b'x')
                over_expanded.abort()
                abandoned = workspace.sink('abandoned.bin', 4, 'staging')
                abandoned.write(b'x')
                workspace.started -= 2
                with self.assertRaisesRegex(TimeoutError, 'time limit'):
                    workspace.check_deadline()
            self.assertFalse(workspace.root.exists())

    def test_scaled_large_archives_repeat_deterministically_and_cleanup_is_plan_only(self):
        import phase_d_fixtures as large
        import phase_d_audit as audit
        import sandbox_fixtures as fixtures
        with tempfile.TemporaryDirectory() as folder:
            # Offline tests discard inherited Git trust configuration. Own the test
            # repository instead of depending on the hosted container checkout.
            root=Path(folder)/'source';root.mkdir()
            inputs={'Cargo.toml':'[package]\nname="rolauncher"\nversion="0.0.900"\n',
                'Cargo.lock':'[[package]]\nname="rolauncher"\nversion="0.0.900"\n',
                'README.md':'# RoLauncher 0.0.900\nSandbox only\n',
                'AGENTS.md':'Synthetic instructions\n','LICENSE':'Synthetic license\n',
                'THIRD_PARTY_NOTICES.md':'No binary dependencies\n'}
            for name,text in inputs.items():(root/name).write_bytes(text.encode('utf-8'))
            fixtures.git(root,'init','-q');fixtures.git(root,'add','--all')
            fixtures.git(root,'-c','user.name=Offline Fixture','-c','user.email=fixture@example.invalid',
                '-c','commit.gpgsign=false','commit','-qm','synthetic offline fixture')
            first=large.package(Path(folder)/'one',4096,2048,root=root)
            second=large.package(Path(folder)/'two',4096,2048,root=root)
            self.assertEqual(first['archives'],second['archives'])
            self.assertEqual(first['files'],second['files'])
        self.assertEqual(audit.cleanup_plan([])['status'],'PROPOSAL ONLY')

    def test_source_artifact_gate_uses_exact_cached_download_and_git_blobs(self):
        import zipfile
        import phase_d_publisher as live
        content=b'Inert source\n'
        source=io.BytesIO()
        with zipfile.ZipFile(source,'w') as z:z.writestr('AGENTS.md',content)
        outer=io.BytesIO()
        prefix='rolauncher-v0.0.900'
        with zipfile.ZipFile(outer,'w') as z:
            for suffix in ('-setup-x64.exe','-windows-x64.zip','-SHA256SUMS.txt'):z.writestr(prefix+suffix,b'inert')
            z.writestr(prefix+'-source.zip',source.getvalue())
        raw=outer.getvalue()
        artifact=dict(id=30,name='release-files-attempt-1',size_in_bytes=len(raw),
            digest='sha256:'+hashlib.sha256(raw).hexdigest(),workflow_run=dict(id=12,head_sha='a'*40))
        calls=[]
        def backend(path,**kwargs):
            calls.append(path)
            if path.startswith('/actions/runs/'):return dict(total_count=1,artifacts=[artifact])
            if path.startswith('/actions/artifacts/'):return raw
            return dict(truncated=False,tree=[dict(path='AGENTS.md',mode='100644',type='blob',
                sha=hashlib.sha1(b'blob 13\0'+content).hexdigest())])
        cached=live.FrozenArtifacts(backend)
        self.addCleanup(cached.close)
        binding=dict(source=dict(id=12,run_attempt=1,head_sha='a'*40),intent=dict(version='0.0.900',channel='stable'))
        live.verify_source_artifact(cached,binding)
        live.verify_source_artifact(cached,binding)
        self.assertEqual(calls.count('/actions/artifacts/30/zip'),1)

    def test_file_backed_source_gate_rejects_wrong_sha_blob_and_tree_inventory(self):
        import warnings
        import zipfile
        import phase_d_publisher as live
        from phase_d_capacity import ArtifactWorkspace, DEFAULT_CAPACITY

        source_sha='a'*40
        good=b'Inert source\n'
        changed=b'Different source\n'

        def blob(path, content, mode='100644'):
            digest=hashlib.sha1(b'blob '+str(len(content)).encode()+b'\0'+content).hexdigest()
            return dict(path=path,mode=mode,type='blob',sha=digest)

        def zip_bytes(entries):
            output=io.BytesIO()
            with zipfile.ZipFile(output,'w') as archive:
                for name,content in entries:
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore',UserWarning)
                        archive.writestr(name,content)
            return output.getvalue()

        cases=(
            ('wrong-source-sha','b'*40,[('AGENTS.md',good)],[blob('AGENTS.md',changed)]),
            ('wrong-git-blob',source_sha,[('AGENTS.md',changed)],[blob('AGENTS.md',good)]),
            ('missing-source-file',source_sha,[('AGENTS.md',good)],[blob('AGENTS.md',good),blob('README.md',b'Readme\n')]),
            ('unexpected-source-file',source_sha,[('AGENTS.md',good),('extra.txt',b'Extra\n')],[blob('AGENTS.md',good)]),
            ('duplicate-source-entry',source_sha,[('AGENTS.md',good),('AGENTS.md',good)],[blob('AGENTS.md',good)]),
            ('unsupported-git-symlink',source_sha,[('AGENTS.md',good)],[blob('AGENTS.md',good,'120000')]),
        )
        for fault,sha,source_entries,tree in cases:
            with self.subTest(fault=fault):
                prefix='rolauncher-v0.0.900'
                source=zip_bytes(source_entries)
                outer=io.BytesIO()
                with zipfile.ZipFile(outer,'w') as archive:
                    for suffix in ('-setup-x64.exe','-windows-x64.zip','-SHA256SUMS.txt'):
                        archive.writestr(prefix+suffix,b'inert')
                    archive.writestr(prefix+'-source.zip',source)
                raw=outer.getvalue()
                artifact=dict(id=30,name='release-files-attempt-1',size_in_bytes=len(raw),
                    digest='sha256:'+hashlib.sha256(raw).hexdigest(),
                    workflow_run=dict(id=12,head_sha=sha))

                def backend(path,**kwargs):
                    if path=='/actions/runs/12/artifacts?per_page=100':
                        return dict(total_count=1,artifacts=[artifact])
                    if path=='/actions/artifacts/30/zip':return raw
                    if path==f'/git/trees/{sha}?recursive=1':
                        return dict(truncated=False,tree=tree)
                    raise AssertionError(path)

                workspace=ArtifactWorkspace(DEFAULT_CAPACITY,parent=Path(__file__).resolve().parents[1])
                cached=live.FrozenArtifacts(backend)
                cached.bind_workspace(workspace)
                binding=dict(source=dict(id=12,run_attempt=1,head_sha=sha),
                             intent=dict(version='0.0.900',channel='stable'))
                try:
                    with self.assertRaises(ValueError):live.verify_source_artifact(cached,binding)
                finally:
                    cached.close()
    def test_http_outcome_observer_receives_status_only(self):
        class Response(io.BytesIO):
            headers={}
            status=201
            def geturl(self):return self.url
        class Connection:
            def open(self,request,*args,**kwargs):
                response=Response(b'{"id":50}')
                response.url=request.full_url
                return response
        statuses=[]
        with patch.object(promotion,'build_opener',return_value=Connection()):
            api=promotion.github_api('disposable-not-a-credential',observer=statuses.append)
            self.assertEqual(api('/releases','POST',{'draft':True}),{'id':50})
        self.assertEqual(statuses,[201])

    def test_raw_download_streams_bounded_chunks_into_private_file(self):
        from phase_d_capacity import ArtifactWorkspace, DEFAULT_CAPACITY
        payload=b'bounded-download-fixture'
        class Response(io.BytesIO):
            headers={'Content-Length':str(len(payload))}
            status=200
            reads=[]
            def geturl(self):return self.url
            def read(self,size=-1):
                self.reads.append(size)
                return super().read(size)
        responses=[]
        class Connection:
            def open(self,request,timeout):
                response=Response(payload)
                response.url=request.full_url
                responses.append(response)
                return response
        workspace=ArtifactWorkspace(DEFAULT_CAPACITY,parent=Path(__file__).resolve().parents[1])
        self.addCleanup(workspace.close)
        sink=workspace.sink('download.zip',64,'archive')
        with patch.object(promotion,'build_opener',return_value=Connection()):
            self.assertIsNone(promotion.github_api('disposable-download-token')(
                '/actions/artifacts/30/zip',raw=True,sink=sink))
        downloaded=sink.finish()
        self.assertEqual((downloaded.size,downloaded.sha256),
            (len(payload),hashlib.sha256(payload).hexdigest()))
        self.assertEqual(responses[0].reads,[DEFAULT_CAPACITY.max_buffer_bytes,DEFAULT_CAPACITY.max_buffer_bytes])

    def test_release_upload_streams_file_chunks_without_request_body_buffer(self):
        from phase_d_capacity import ArtifactWorkspace, DEFAULT_CAPACITY, MiB
        payload=(b'bounded-upload-fixture'*(2*MiB//22+1))[:2*MiB+17]
        workspace=ArtifactWorkspace(DEFAULT_CAPACITY,parent=Path(__file__).resolve().parents[1])
        self.addCleanup(workspace.close)
        artifact=workspace.write_bytes('payload.bin',payload,len(payload),'staging')
        sent=[]
        class Response(io.BytesIO):
            status=201
            headers={'Content-Length':'9'}
        connections=[]
        class Connection:
            def __init__(self,host,port,timeout,context):
                self.headers={};self.target=None;connections.append(self)
            def putrequest(self,method,target):self.method,self.target=method,target
            def putheader(self,key,value):self.headers[key]=value
            def endheaders(self):pass
            def send(self,chunk):sent.append(bytes(chunk))
            def getresponse(self):return Response(b'{"id":50}')
            def close(self):pass
        api=promotion.github_api('disposable-upload-token')
        with patch.object(promotion.http.client,'HTTPSConnection',Connection):
            result=api(
                'https://uploads.github.com/repos/'+evidence.REPO+
                '/releases/50/assets?name=fixture.bin','POST',binary=artifact)
        self.assertEqual(result,{'id':50})
        self.assertGreater(len(sent),1)
        self.assertTrue(all(0<len(chunk)<=promotion.COPY_BYTES for chunk in sent))
        self.assertEqual(b''.join(sent),payload)
        self.assertEqual(connections[0].headers['Content-Length'],str(len(payload)))
        self.assertEqual(connections[0].target,'/repos/'+evidence.REPO+'/releases/50/assets?name=fixture.bin')

    def test_http_failure_matrix_is_sanitized_and_never_permission_classified(self):
        cases=(
            ('primary rate limit',403,{'X-RateLimit-Remaining':'0'},b'primary-limit-secret'),
            ('secondary rate limit',403,{'Retry-After':'60'},
             b'{"message":"You have exceeded a secondary rate limit."}'),
            ('throttle header',403,{'Retry-After':'60','X-RateLimit-Remaining':'5'},b'throttle-secret'),
            ('ambiguous body',403,{},b'ambiguous-body-secret'),
            ('no classification',403,{},b''),
            ('unauthorized',401,{},b'unauthorized-secret'),
            ('not found',404,{},b'not-found-secret'),
            ('too many requests',429,{},b'rate-limit-secret'),
            ('server error',500,{},b'server-secret'),
            ('bad gateway',502,{},b'gateway-secret'),
            ('unavailable',503,{},b'unavailable-secret'))
        for name,status,headers,body in cases:
            with self.subTest(name=name):
                class Connection:
                    def open(self,request,timeout):
                        raise HTTPError(request.full_url,status,'synthetic failure',headers,io.BytesIO(body))
                observed=[]
                with patch.object(promotion,'build_opener',return_value=Connection()):
                    api=promotion.github_api('disposable-test-token',observer=observed.append)
                    with self.assertRaisesRegex(RuntimeError,'no automatic mutation retry') as raised:
                        api('/immutable-releases')
                self.assertIn(f'HTTP {status}',str(raised.exception))
                self.assertEqual(observed,[status])
                self.assertNotIn('disposable-test-token',str(raised.exception))
                if body:
                    self.assertNotIn(body.decode('ascii'),str(raised.exception))

    def test_immutable_permission_classification_requires_documented_response_contract(self):
        permission_body=b'{"message":"Resource not accessible by integration"}'
        endpoint='/repos/'+evidence.REPO+'/immutable-releases'
        def failure(status=403,headers=None,body=permission_body,path='/immutable-releases',method='GET'):
            class Connection:
                def open(self,request,timeout):
                    raise HTTPError(request.full_url,status,'synthetic failure',headers or {},io.BytesIO(body))
            with patch.object(promotion,'build_opener',return_value=Connection()):
                api=promotion.github_api('disposable-classification-token')
                with self.assertRaises(promotion.GitHubAPIError) as raised:
                    api(path,method)
            return raised.exception
        # GitHub documents this error as insufficient App/PAT permissions and the
        # header as the endpoint's required permission; rate-limit evidence is separate.
        headers={'X-Accepted-GitHub-Permissions':'administration=read','X-RateLimit-Remaining':'17'}
        allowed=failure(headers=headers)
        self.assertTrue(allowed.is_explicit_permission_restriction('GET',endpoint,'administration=read'))
        self.assertNotIn('Resource not accessible',str(allowed))
        self.assertNotIn('disposable-classification-token',str(allowed))
        rejected=(
            failure(headers={'X-Accepted-GitHub-Permissions':'administration=read'}),
            failure(headers={**headers,'X-RateLimit-Remaining':'0'}),
            failure(headers={**headers,'Retry-After':'60'}),
            failure(headers={**headers,'X-Accepted-GitHub-Permissions':'contents=read'}),
            failure(headers=headers,body=b'{"message":"ambiguous 403"}'),
            failure(headers=headers,body=b'{malformed'),
            failure(status=429,headers=headers),
            failure(headers=headers,path='/rulesets'),
            failure(headers=headers,method='POST'))
        for error in rejected:
            with self.subTest(error=error.status,error_path=error.path,error_method=error.method):
                self.assertFalse(error.is_explicit_permission_restriction(
                    'GET',endpoint,'administration=read'))
        wrong_origin=promotion.GitHubAPIError('GET',
            'https://attacker.invalid'+endpoint,403,headers,permission_body)
        self.assertFalse(wrong_origin.is_explicit_permission_restriction(
            'GET',endpoint,'administration=read'))

    def test_github_api_timeout_and_malformed_json_fail_closed(self):
        class TimeoutConnection:
            def open(self,*args,**kwargs):raise TimeoutError('synthetic timeout')
        with patch.object(promotion,'build_opener',return_value=TimeoutConnection()):
            with self.assertRaises(TimeoutError):promotion.github_api('disposable-token')('/immutable-releases')
        class ResetConnection:
            def open(self,*args,**kwargs):raise ConnectionResetError('synthetic connection reset')
        with patch.object(promotion,'build_opener',return_value=ResetConnection()):
            with self.assertRaises(ConnectionResetError):promotion.github_api('disposable-token')('/immutable-releases')
        class MalformedResponse(io.BytesIO):
            headers={}
            status=200
            def geturl(self):return self.url
        class MalformedConnection:
            def open(self,request,*args,**kwargs):
                response=MalformedResponse(b'{malformed-json')
                response.url=request.full_url
                return response
        with patch.object(promotion,'build_opener',return_value=MalformedConnection()):
            with self.assertRaises(json.JSONDecodeError):promotion.github_api('disposable-token')('/immutable-releases')
        class RedirectedResponse(io.BytesIO):
            headers={}
            status=200
            def geturl(self):return 'https://attacker.invalid/immutable-releases'
        class RedirectedConnection:
            def open(self,*args,**kwargs):return RedirectedResponse(b'{"enabled":true,"enforced_by_owner":false}')
        with patch.object(promotion,'build_opener',return_value=RedirectedConnection()):
            with self.assertRaisesRegex(ValueError,'redirect'):
                promotion.github_api('disposable-token')('/immutable-releases')
    def test_lost_response_records_commit_and_never_retries(self):
        writes = []
        def server(path, method='GET', body=None, **kwargs):
            writes.append((path, method))
            return {'id': 50}
        with tempfile.TemporaryDirectory() as folder:
            ledger = Path(folder) / 'ledger.jsonl'
            api = phase_d.AuditedTransport(server, ledger, fault={'mutation': 1, 'when': 'after'})
            with self.assertRaises(TimeoutError):
                api('/releases', 'POST', {'draft': True})
            self.assertEqual(writes, [('/releases', 'POST')])
            events = [json.loads(line) for line in ledger.read_text().splitlines()]
            self.assertEqual(events[-1]['outcome'], 'response-lost-after-return')
            self.assertEqual(events[-1]['mutation'], 1)
            api.close()

    def test_foreign_routes_redacted_and_fault_bounds_fail_before_forwarding(self):
        with tempfile.TemporaryDirectory() as folder:
            forwarded = []
            api = phase_d.AuditedTransport(lambda *a, **k: forwarded.append(a), Path(folder)/'audit')
            for path in ('https://api.github.com/repos/oangsa/RoLauncher/releases',
                         '/../../RoLauncher/releases', 'https://attacker.invalid/?token=private'):
                with self.assertRaises(ValueError): api(path, 'POST', {'draft': True})
            api.close()
            self.assertEqual(forwarded, [])
            self.assertNotIn('private', (Path(folder)/'audit').read_text())
            with self.assertRaises(ValueError):
                phase_d.AuditedTransport(None, Path(folder)/'bad', {'mutation':1,'when':'delay-after','seconds':131})

    def test_nested_freshness_reads_cannot_exhaust_mutation_completion_ledger_slot(self):
        with tempfile.TemporaryDirectory() as folder:
            writes=[]
            def backend(path,method='GET',body=None,**kwargs):
                if method!='GET':writes.append(path)
                return {}
            api=phase_d.AuditedTransport(backend,Path(folder)/'bounded',max_events=5)
            api.fresh=lambda:(api('/issues/5'),api('/issues/5'))
            try:
                with self.assertRaisesRegex(ValueError,'ledger limit'):api('/releases','POST',{'draft':True})
                self.assertEqual(writes,[])
                self.assertLessEqual(len(api.ledger.read_text().splitlines()),5)
            finally:api.close()


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): owner.OwnerEvidenceTests.setUpClass()

    @classmethod
    def tearDownClass(cls): owner.OwnerEvidenceTests.tearDownClass()

    def setUp(self):
        self.fixture = owner.OwnerEvidenceTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.transport = lambda stage: phase_d.PhaseDEvidence(stage, self.fixture.policy_path, self.fixture.state)

    def audit(self, name, fault=None):
        f = self.fixture
        api = phase_d.AuditedTransport(f.api, f.root / (name + '.jsonl'), fault)
        self.addCleanup(api.close)
        destination=os.environ.get('PHASE_D_TEST_AUDIT_DIR')
        if destination:
            backend=f.api
            def retain():
                target=Path(destination);target.mkdir(parents=True,exist_ok=True)
                (target/(name+'.jsonl')).write_text(api.ledger.read_text())
                state=dict(tag=backend.tag,release=None if backend.release is None else
                    {k:backend.release.get(k) for k in ('id','tag_name','draft','prerelease','immutable')},
                    assets={n:dict(id=a['id'],size=a['size'],sha256=hashlib.sha256(a['data']).hexdigest())
                            for n,a in backend.assets.items()})
                (target/(name+'-state.json')).write_text(json.dumps(state,indent=2)+'\n')
            self.addCleanup(retain)
        return api

    def run_stage(self, stage, api):
        f = self.fixture
        transport = f.transport(stage)
        api.fresh = transport.fresh
        return promotion.promote(api, f.api.run, transport)

    def finish(self, api):
        f = self.fixture
        f.post(f.prepare())
        with self.assertRaises(evidence.ChallengeReady): self.run_stage('stage', api)
        f.post(f.challenge('final'))
        return self.run_stage('finish', api)

    def test_correctly_signed_noncanonical_payload_rejected_without_consuming_nonce(self):
        f = self.fixture
        challenge = f.prepare()
        with patch.object(evidence, 'canonical', side_effect=lambda x: json.dumps(x, indent=2).encode()):
            response = f.response(challenge)
        used = set()
        with self.assertRaisesRegex(ValueError, 'canonical'):
            phase_d.verify_canonical(response, challenge, used, f.policy_path)
        self.assertEqual(used, set())
        phase_d.verify_canonical(f.response(challenge), challenge, used, f.policy_path)
        self.assertEqual(used, {challenge['nonce']})

    def test_privileged_readiness_never_treats_missing_bypass_as_empty(self):
        import phase_d_readiness as readiness
        f=self.fixture
        self.assertEqual(readiness.inspect(f.api.full,f.policy)['privileged_controls'],'PASS')
        result=readiness.inspect(f.api,f.policy)
        self.assertEqual(result['privileged_controls'],'BLOCKED')
        self.assertTrue(result['missing_bypass_arrays'])

    def test_readiness_entry_is_get_only_and_rejects_untrusted_context_before_transport(self):
        import contextlib
        import phase_d_readiness as readiness
        f=self.fixture
        calls=[]
        visible=False
        def backend(path,method='GET'):
            self.assertEqual(method,'GET')
            calls.append(path)
            if path=='/branches/main':return {'commit':{'sha':'a'*40}}
            return f.api.full(path) if visible else f.api(path)
        env=dict(PHASE_D_READ_ONLY_AUTHORIZED='true',GITHUB_REPOSITORY=evidence.REPO,
            GITHUB_REPOSITORY_ID=str(evidence.REPO_ID),GITHUB_EVENT_NAME='workflow_dispatch',
            GITHUB_REF='refs/heads/main',GITHUB_WORKFLOW_REF=evidence.REPO+
                '/.github/workflows/phase-d-readiness.yml@refs/heads/main',GITHUB_SHA='a'*40,
            GITHUB_TOKEN='offline-token',GITHUB_RUN_ID='99',GITHUB_RUN_ATTEMPT='1')
        with patch.dict(os.environ,env,clear=True),contextlib.chdir(f.root), \
                patch.object(promotion,'github_api',return_value=backend) as factory, \
                patch.object(evidence,'load_policy',return_value=(f.policy,f.policy['keys'])), \
                patch.object(evidence,'sign') as sign:
            with self.assertRaises(SystemExit) as blocked:
                readiness.main()
            self.assertEqual(blocked.exception.code,1)
            result=json.loads(Path('phase-d-readiness.json').read_text())
            self.assertEqual(result['privileged_controls'],'BLOCKED')
            self.assertEqual(result['trusted_sha'],'a'*40)
            self.assertEqual((result['run_id'],result['attempt']),(99,1))
            self.assertEqual(json.loads(Path('phase-d-readiness.json').read_text()),result)
            visible=True
            self.assertEqual(readiness.main()['privileged_controls'],'PASS')
            accepted_calls=list(calls)
            for key,value in [('GITHUB_EVENT_NAME','push'),('GITHUB_EVENT_NAME','pull_request'),
                    ('GITHUB_REF','refs/heads/codex/test'),('GITHUB_REPOSITORY','oangsa/RoLauncher'),
                    ('GITHUB_REPOSITORY_ID','1'),('GITHUB_WORKFLOW_REF','untrusted'),
                    ('PHASE_D_READ_ONLY_AUTHORIZED','false')]:
                with self.subTest(key=key,value=value),patch.dict(os.environ,{key:value}),self.assertRaises(ValueError):
                    readiness.main()
            self.assertEqual(calls,accepted_calls)
            self.assertEqual(factory.call_count,2)
            factory.assert_called_with('offline-token')
            sign.assert_not_called()
        self.assertEqual(f.api.writes,[])

    def test_full_lifecycle_ledger_and_consumed_retry_have_no_duplicate_mutations(self):
        f = self.fixture
        api = self.audit('positive')
        self.assertEqual(self.finish(api), 'published')
        self.assertTrue(f.api.release['immutable'])
        original = copy.deepcopy(f.api.assets)
        receipt = f.api.assets['release-promotion.json']['data']
        writes = len(f.api.writes)
        f.state = f.root / 'retry'
        os.environ['GITHUB_RUN_ATTEMPT'] = '2'
        self.assertEqual(self.finish(api), 'consumed')
        self.assertEqual(f.api.assets, original)
        self.assertEqual(f.api.assets['release-promotion.json']['data'], receipt)
        self.assertEqual(len(f.api.writes), writes)

    def test_independent_download_audit_rejects_changed_published_bytes(self):
        import phase_d_audit as audit
        f=self.fixture
        self.assertEqual(self.finish(self.audit('downloads')),'published')
        receipt=f.api.assets['release-promotion.json']['data']
        self.assertEqual(audit.verify_release(f.api,'v2.3.4','a'*40,receipt)['status'],'PASS')
        asset=next(a for n,a in f.api.assets.items() if n!='release-promotion.json')
        asset['data']=b'tampered'
        with self.assertRaisesRegex(ValueError,'download'):audit.verify_release(f.api,'v2.3.4','a'*40,receipt)

    def test_denied_probe_driver_requires_exact_approval_and_unchanged_state(self):
        import phase_d_audit as audit
        import phase_d_probes as probes
        f=self.fixture
        self.finish(self.audit('probe-baseline'))
        receipt=f.api.assets['release-promotion.json']['data']
        baseline=audit.verify_release(f.api,'v2.3.4','a'*40,receipt)
        plan=audit.denied_probe_plan(baseline,'b'*40)
        requests=[]
        def denied(path,method='GET',body=None,**kwargs):
            requests.append((path,method))
            raise HTTPError('https://api.github.com/',403,'immutable',{},None)
        api=phase_d.AuditedTransport(denied,f.root/'denials.jsonl',approved_probe_name='PHASE-D-DENIED.txt')
        self.addCleanup(api.close)
        readback=lambda:audit.verify_release(f.api,'v2.3.4','a'*40,receipt)
        with self.assertRaises(ValueError):probes.run(api,plan,baseline,readback)
        self.assertEqual(requests,[])
        result=probes.run(api,plan,baseline,readback,approved_sha256=evidence.digest(plan))
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(len(requests),5)
        self.assertEqual(readback(),baseline)

    def test_beta_uses_both_real_crypto_gates_and_keeps_channel_contract(self):
        f=self.fixture
        f.api.with_beta()
        self.assertEqual(self.finish(self.audit('beta')),'published')
        self.assertTrue(f.api.release['prerelease'])
        self.assertEqual(f.api.release['make_latest'],'false')

    def test_visible_immutable_contradiction_denies_both_gates(self):
        f=self.fixture
        observations=(
            ('disabled',dict(enabled=False,enforced_by_owner=False)),
            ('owner changed',dict(enabled=True,enforced_by_owner=True)),
            ('missing owner field',dict(enabled=True)),
            ('null owner field',dict(enabled=True,enforced_by_owner=None)),
            ('malformed enabled field',dict(enabled='true',enforced_by_owner=False)))
        for phase in ('preflight','final'):
            for name,immutable in observations:
              with self.subTest(phase=phase,observation=name):
                f.api=owner.LiveFixture()
                f.state=f.root/('immutable-contradiction-'+phase+'-'+name.replace(' ','-'))
                f.post(f.prepare())
                if phase=='final':
                    f.stage()
                    f.post(f.challenge('final'))
                before=list(f.api.writes)
                def changed(path,*args,**kwargs):
                    if path=='/immutable-releases':return immutable
                    return f.api(path,*args,**kwargs)
                with self.assertRaises(ValueError):
                    promotion.promote(changed,f.api.run,f.transport('stage' if phase=='preflight' else 'finish'))
                self.assertEqual(f.api.writes,before)

    def test_native_immutable_change_immediately_before_stage_or_publication_is_rejected(self):
        f=self.fixture
        for phase in ('preflight','final'):
            with self.subTest(phase=phase):
                f.api=owner.LiveFixture()
                f.state=f.root/('immutable-toctou-'+phase)
                f.post(f.prepare())
                if phase=='final':
                    staged=self.audit('immutable-toctou-final-stage')
                    with self.assertRaises(evidence.ChallengeReady):self.run_stage('stage',staged)
                    f.post(f.challenge('final'))
                    api=self.audit('immutable-toctou-final-publication',
                        dict(mutation=1,when='delay-before',seconds=1))
                    stage='finish'
                else:
                    api=self.audit('immutable-toctou-preflight-stage',
                        dict(mutation=1,when='delay-before',seconds=1))
                    stage='stage'
                api.sleep=lambda seconds:f.api.immutable.__setitem__('enabled',False)
                before=list(f.api.writes)
                with self.assertRaises(ValueError):self.run_stage(stage,api)
                self.assertEqual(f.api.writes,before)

    def test_ambiguous_immutable_403_denies_both_gates_without_crossing_mutation_boundary(self):
        f=self.fixture
        for phase in ('preflight','final'):
            with self.subTest(phase=phase):
                f.api=owner.LiveFixture()
                f.state=f.root/('ambiguous-403-'+phase)
                f.post(f.prepare())
                api=self.audit('ambiguous-403-'+phase)
                if phase=='final':
                    with self.assertRaises(evidence.ChallengeReady):self.run_stage('stage',api)
                    f.post(f.challenge('final'))
                before=list(f.api.writes)
                def restricted(path,*args,**kwargs):
                    if path=='/immutable-releases':
                        raise RuntimeError('GitHub GET failed (HTTP 403); no automatic mutation retry')
                    return f.api(path,*args,**kwargs)
                api.call=restricted
                with self.assertRaises(RuntimeError):
                    self.run_stage('stage' if phase=='preflight' else 'finish',api)
                self.assertEqual(f.api.writes,before)

    def test_documented_permission_limit_uses_fresh_owner_attestation_at_both_gates(self):
        f=self.fixture
        api=self.audit('owner-attested-immutable')
        body=b'{"message":"Resource not accessible by integration"}'
        def restricted(path,method='GET',body_value=None,**kwargs):
            if path=='/immutable-releases':
                raise promotion.GitHubAPIError('GET',
                    'https://api.github.com/repos/'+evidence.REPO+path,403,
                    {'X-Accepted-GitHub-Permissions':'administration=read',
                     'X-RateLimit-Remaining':'17'},body)
            return f.api(path,method,body_value,**kwargs)
        api.call=restricted
        self.assertEqual(self.finish(api),'published')
        self.assertTrue(f.api.release['immutable'])
        observations=[json.loads(row) for row in api.ledger.read_text().splitlines()]
        owner_attestations=[row for row in observations if row.get('event')=='security-observation'
            and row.get('observation')=='native-immutable-settings' and row.get('value')=='OWNER_ATTESTED']
        self.assertGreaterEqual(len(owner_attestations),2)

    def test_frozen_artifacts_forwards_security_observations_to_audit_ledger(self):
        import phase_d_publisher as live
        with self.assertRaisesRegex(ValueError,'(?i)audit transport cannot record'):
            live.FrozenArtifacts(lambda *args,**kwargs:None).observe_immutable_visibility('RUNNER_VISIBLE')
        f=self.fixture
        for visibility in ('RUNNER_VISIBLE','OWNER_ATTESTED'):
            with self.subTest(visibility=visibility):
                f.api=owner.LiveFixture()
                f.state=f.root/('forwarded-observation-'+visibility.lower())
                secret='synthetic-token-must-not-enter-ledger'
                permission_body=json.dumps({'message':'Resource not accessible by integration',
                    'access_token':secret}).encode()
                ledger=f.root/(visibility.lower()+'.jsonl')
                backend=f.api
                def call(path,method='GET',body=None,**kwargs):
                    if visibility=='OWNER_ATTESTED' and path=='/immutable-releases':
                        raise promotion.GitHubAPIError('GET',
                            'https://api.github.com/repos/'+evidence.REPO+path,403,
                            {'Authorization':'Bearer '+secret,
                             'X-Accepted-GitHub-Permissions':'administration=read',
                             'X-RateLimit-Remaining':'17'},
                            permission_body)
                    return backend(path,method,body,**kwargs)
                api=phase_d.AuditedTransport(call,ledger)
                self.addCleanup(api.close)
                def run(stage):
                    transport=f.transport(stage)
                    api.fresh=transport.fresh
                    return promotion.promote(live.FrozenArtifacts(api),f.api.run,transport)
                f.post(f.prepare())
                with self.assertRaises(evidence.ChallengeReady):run('stage')
                f.post(f.challenge('final'))
                self.assertEqual(run('finish'),'published')
                rows=[json.loads(row) for row in ledger.read_text().splitlines()]
                observations=[row for row in rows if row.get('event')=='security-observation'
                    and row.get('observation')=='native-immutable-settings']
                self.assertGreaterEqual(len(observations),2)
                self.assertEqual({row['value'] for row in observations},{visibility})
                self.assertNotIn(secret,ledger.read_text())
                self.assertTrue(all(not {'token','headers','body'} & set(row) for row in rows))

    def test_permission_limit_does_not_bypass_invalid_owner_signature(self):
        f=self.fixture
        challenge=f.prepare()
        response=f.response(challenge)
        response['signature']='invalid-signature'
        f.post(challenge,response)
        api=self.audit('invalid-signature-permission-limit')
        body=b'{"message":"Resource not accessible by integration"}'
        def restricted(path,*args,**kwargs):
            if path=='/immutable-releases':
                raise promotion.GitHubAPIError('GET',
                    'https://api.github.com/repos/'+evidence.REPO+path,403,
                    {'X-Accepted-GitHub-Permissions':'administration=read',
                     'X-RateLimit-Remaining':'17'},body)
            return f.api(path,*args,**kwargs)
        api.call=restricted
        before=list(f.api.writes)
        with self.assertRaises(ValueError):self.run_stage('stage',api)
        self.assertEqual(f.api.writes,before)
        self.assertFalse(any(json.loads(row).get('event')=='security-observation'
            for row in api.ledger.read_text().splitlines()))

    def test_visible_bypass_contradiction_denies_both_gates(self):
        f=self.fixture
        for phase in ('preflight','final'):
            with self.subTest(phase=phase):
                f.api=owner.LiveFixture()
                f.state=f.root/('bypass-contradiction-'+phase)
                f.post(f.prepare())
                if phase=='final':
                    f.stage()
                    f.post(f.challenge('final'))
                before=list(f.api.writes)
                def changed(path,*args,**kwargs):
                    result=f.api(path,*args,**kwargs)
                    if path=='/rulesets/2':
                        result['bypass_actors']=[dict(actor_type='RepositoryRole',actor_id=5,bypass_mode='always')]
                    return result
                with self.assertRaisesRegex(ValueError,'bypass'):
                    promotion.promote(changed,f.api.run,f.transport('stage' if phase=='preflight' else 'finish'))
                self.assertEqual(f.api.writes,before)

    def test_live_metadata_change_immediately_before_mutation_denies_both_gates(self):
        f=self.fixture
        for phase in ('preflight','final'):
            with self.subTest(phase=phase):
                f.api=owner.LiveFixture()
                f.state=f.root/('metadata-race-'+phase)
                f.post(f.prepare())
                if phase=='final':
                    f.stage()
                    f.post(f.challenge('final'))
                before=list(f.api.writes)
                api=self.audit('metadata-race-'+phase,dict(mutation=1,when='delay-before',seconds=1))
                api.sleep=lambda seconds:f.api.branch_ruleset['conditions']['ref_name']['exclude'].append('refs/heads/main')
                with self.assertRaisesRegex(ValueError,'metadata'):
                    self.run_stage('stage' if phase=='preflight' else 'finish',api)
                self.assertEqual(f.api.writes,before)

    def test_signed_evidence_denial_matrix_preserves_both_mutation_boundaries(self):
        f=self.fixture
        faults=('key','revoked','namespace','payload','base64','base64-padding',
            'digest','bypass','immutable','repository','owner','trusted','source','workflow','run',
            'attempt','phase','expired','replay','edited','duplicate','cancel','main','artifacts','receipt','asset')
        for phase in ('preflight','final'):
            for fault in faults:
                with self.subTest(phase=phase,fault=fault):
                    f.api=owner.LiveFixture()
                    f.state=f.root/('denial-'+phase+'-'+fault)
                    c=f.prepare()
                    if phase=='final':
                        f.post(c)
                        f.stage()
                        c=f.challenge('final')
                    payload=f.payload(copy.deepcopy(c))
                    if fault in ('repository','owner','trusted','workflow','run','attempt','phase'):
                        field={'owner':'owner_id','trusted':'trusted_sha','run':'run_id'}.get(fault,fault)
                        payload['challenge'][field]='wrong'
                    if fault=='source':payload['challenge']['binding']['source']['head_sha']='f'*40
                    if fault=='digest':payload['controls']['rulesets'][0]['rules'].append(dict(type='changed'))
                    if fault=='bypass':payload['controls']['rulesets'][0].pop('bypass_actors')
                    if fault=='immutable':payload['controls'].pop('immutable')
                    if fault=='expired':payload['expires']-=121
                    if fault=='namespace':
                        with patch.object(evidence,'NAMESPACE','wrong-namespace'):
                            response=evidence.sign(payload,f.key)
                    else:response=evidence.sign(payload,f.other_key if fault=='key' else f.key)
                    if fault=='payload':
                        payload['expires']+=1
                        response['payload_base64']=base64.b64encode(evidence.canonical(payload)).decode()
                    if fault=='base64':response['payload_base64']='!'
                    if fault=='base64-padding':response['payload_base64']+='===='
                    comment=f.post(c,response)
                    if fault=='edited':comment['updated_at']='edited'
                    if fault=='duplicate':f.post(c,response)
                    if fault=='cancel':f.api.comments.clear()
                    if fault=='main':f.api.branch['commit']['sha']='f'*40
                    if fault=='artifacts':f.api.artifacts.clear()
                    if fault=='receipt':f.api.intent['id']='00000000-0000-4000-8000-000000000000'
                    if fault=='asset':
                        if phase=='final':next(iter(f.api.assets.values()))['digest']='sha256:'+'0'*64
                        else:f.api.tag=dict(object=dict(type='commit',sha='f'*40))
                    if fault=='replay':
                        (f.state/'preflight-accepted.json').write_bytes(evidence.canonical(dict(challenge=c)))
                    before=list(f.api.writes)
                    with patch.object(evidence.time,'monotonic',side_effect=[0,1,2000]),patch.object(evidence.time,'sleep'):
                        if fault=='revoked':
                            f.policy['revoked']=['SHA256:'+base64.b64encode(hashlib.sha256(
                                base64.b64decode(f.public.split()[1])).digest()).decode().rstrip('=')]
                            f.write_policy()
                        try:
                            with self.assertRaises((ValueError,RuntimeError)):
                                promotion.promote(f.api,f.api.run,f.transport('stage' if phase=='preflight' else 'finish'))
                            self.assertEqual(f.api.writes,before)
                        finally:
                            f.policy['revoked']=[]
                            f.write_policy()

    def test_ambiguous_or_incomplete_immutable_read_never_falls_back(self):
        f=self.fixture
        for phase in ('preflight','final'):
            for fault in ('missing','null','owner-changed','404','401','500','timeout'):
                with self.subTest(phase=phase,fault=fault):
                    f.api=owner.LiveFixture()
                    f.state=f.root/('immutable-errors-'+phase+'-'+fault)
                    f.post(f.prepare())
                    if phase=='final':
                        f.stage()
                        f.post(f.challenge('final'))
                    def unavailable(path,*args,**kwargs):
                        if path!='/immutable-releases':return f.api(path,*args,**kwargs)
                        if fault=='missing':return {}
                        if fault=='null':return None
                        if fault=='owner-changed':return dict(enabled=True,enforced_by_owner=True)
                        if fault=='timeout':raise TimeoutError('offline timeout')
                        raise RuntimeError('GitHub GET failed (HTTP '+fault+'); no automatic mutation retry')
                    before=list(f.api.writes)
                    with self.assertRaises((ValueError,RuntimeError,TimeoutError)):
                        promotion.promote(unavailable,f.api.run,f.transport('stage' if phase=='preflight' else 'finish'))
                    self.assertEqual(f.api.writes,before)

    def test_interruption_matrix_preserves_existing_assets_and_recovers(self):
        f = self.fixture
        for index, when in ((1,'before'), (1,'after'), (2,'after'), (3,'before'), (3,'after'), (4,'before')):
            with self.subTest(mutation=index, when=when):
                f.api = owner.LiveFixture()
                f.state = f.root / f'case-{index}-{when}'
                os.environ['GITHUB_RUN_ATTEMPT'] = '1'
                api = self.audit(f'case-{index}-{when}', {'mutation':index,'when':when})
                f.post(f.prepare())
                with self.assertRaises(TimeoutError): self.run_stage('stage',api)
                original = copy.deepcopy(f.api.assets)
                self.assertTrue(f.api.release is None or f.api.release['draft'])
                f.state = f.root / f'recovery-{index}-{when}'
                os.environ['GITHUB_RUN_ATTEMPT'] = '2'
                api.fault = {}
                self.assertEqual(self.finish(api),'published')
                for name,value in original.items(): self.assertEqual(f.api.assets[name],value)
                rows = [json.loads(x) for x in api.ledger.read_text().splitlines()]
                attempts = [r for r in rows if r.get('method') not in (None,'GET') and r.get('outcome')=='returned']
                committed = [(r['method'],r['route'],r.get('asset')) for r in attempts]
                self.assertEqual(len(committed),len(set(committed)))
                # Before-acceptance retries repeat an attempt, never a committed write.
                if when=='before': self.assertTrue(any(r['duplicate_attempt'] for r in attempts))

    def test_before_publish_and_lost_committed_publish_reconcile_without_replacement(self):
        f = self.fixture
        for when in ('before','after'):
            f.api=owner.LiveFixture()
            f.state=f.root/('publish-'+when)
            os.environ['GITHUB_RUN_ATTEMPT']='1'
            api=self.audit('publish-'+when)
            f.post(f.prepare())
            with self.assertRaises(evidence.ChallengeReady): self.run_stage('stage',api)
            original=copy.deepcopy(f.api.assets)
            f.post(f.challenge('final'))
            api.fault={'mutation':api.mutations+1,'when':when}
            with self.assertRaises(TimeoutError): self.run_stage('finish',api)
            self.assertEqual(f.api.release['draft'],when=='before')
            f.state=f.root/('publish-retry-'+when)
            os.environ['GITHUB_RUN_ATTEMPT']='2'
            api.fault={}
            self.assertEqual(self.finish(api),'published' if when=='before' else 'consumed')
            self.assertEqual(f.api.assets,original)

    def test_denied_final_and_cancelled_wait_preserve_draft_without_publish(self):
        f=self.fixture
        api=self.audit('cancel')
        f.post(f.prepare())
        with self.assertRaises(evidence.ChallengeReady): self.run_stage('stage',api)
        writes=len(f.api.writes)
        with patch.object(evidence.time,'monotonic',side_effect=[0,1,2000]), patch.object(evidence.time,'sleep'):
            with self.assertRaisesRegex(ValueError,'timeout'): self.run_stage('finish',api)
        self.assertTrue(f.api.release['draft'])
        self.assertEqual(len(f.api.writes),writes)
        final=f.challenge('final')
        response=f.response(final)
        response['signature']='invalid'
        f.post(final,response)
        with self.assertRaises(ValueError): self.run_stage('finish',api)
        self.assertEqual(len(f.api.writes),writes)

    def test_runtime_gate_rejects_signed_noncanonical_evidence_zero_writes(self):
        f=self.fixture
        api=self.audit('noncanonical')
        c=f.prepare()
        with patch.object(evidence,'canonical',side_effect=lambda x:json.dumps(x,indent=2).encode()):
            response=f.response(c)
        f.post(c,response)
        with self.assertRaisesRegex(ValueError,'canonical'): self.run_stage('stage',api)
        self.assertEqual(f.api.writes,[])

    def test_noncanonical_comment_wrapper_rejected_before_mutation(self):
        f=self.fixture
        c=f.prepare()
        comment=f.post(c)
        comment['body']=json.dumps(json.loads(comment['body']),indent=2)
        with self.assertRaisesRegex(ValueError,'canonical'):
            self.run_stage('stage',self.audit('wrapper'))
        self.assertEqual(f.api.writes,[])

    def test_principal_lookup_and_native_control_exclusion(self):
        import phase_d_probes as probes
        f=self.fixture
        c=f.prepare()
        response=f.response(c)
        allowed=f.root/'allowed'
        allowed.write_text(evidence.PRINCIPAL+' namespaces="'+evidence.NAMESPACE+'" '+f.public+'\n')
        signature=f.root/'signature'
        signature.write_text(response['signature'])
        result=evidence.subprocess.run([evidence.ssh(),'-Y','verify','-f',str(allowed),'-I',
            'github-user-1','-n',evidence.NAMESPACE,'-s',str(signature)],
            input=base64.b64decode(response['payload_base64']),capture_output=True)
        self.assertNotEqual(result.returncode,0)
        snapshot=evidence.collect(f.api.full)
        self.assertTrue(probes.outside_tag_rulesets('sandbox-native-immutable-0.0.900',snapshot,f.policy))
        self.assertFalse(probes.outside_tag_rulesets('v0.0.900',snapshot,f.policy))
        snapshot['rulesets'][0].pop('bypass_actors')
        with self.assertRaises(ValueError):probes.outside_tag_rulesets('sandbox-native-immutable-0.0.900',snapshot,f.policy)

    def test_independent_native_fixture_audit_uses_no_version_tag_rule(self):
        import phase_d_probes as probes
        f=self.fixture
        snapshot=evidence.collect(f.api.full)
        proposal=probes.native_control_proposal('a'*40,snapshot,f.policy)
        payload=b'SANDBOX NATIVE IMMUTABILITY CONTROL\n'
        digest=hashlib.sha256(payload).hexdigest()
        release=dict(id=70,tag_name=proposal['tag'],target_commitish='a'*40,draft=False,
                     prerelease=False,immutable=True)
        asset=dict(id=71,name='PHASE-D-NATIVE-CONTROL.txt',size=len(payload),digest='sha256:'+digest)
        def backend(path,**kwargs):
            if path=='':return f.api.full('')
            if path.startswith('/git/ref/tags/'):return dict(object=dict(type='commit',sha='a'*40))
            if path.endswith('/assets'):return [asset]
            if path=='/releases/assets/71':return payload
            return release
        result=probes.verify_native_control(backend,'a'*40,snapshot,f.policy)
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(result['tag'],proposal['tag'])
        self.assertTrue(result['outside_version_rulesets'])

    def test_hotfix_uses_existing_independent_authority_and_both_crypto_gates(self):
        spec=importlib.util.spec_from_file_location('phase_d_hotfix',Path(__file__).with_name('test-hotfix-policy.py'))
        hotfix=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hotfix)
        class FullHotfix(hotfix.HotfixFixture,owner.LiveFixture):
            def __init__(self):
                hotfix.HotfixFixture.__init__(self)
                live=owner.LiveFixture()
                self.comments=[]
                self.branch_ruleset=live.branch_ruleset
                self.tag_rules=live.tag_rules
            def __call__(self,path,method='GET',body=None,**kwargs):
                if method=='GET' and (path=='' or path.startswith(('/rulesets','/issues/'))):
                    return owner.LiveFixture.__call__(self,path,method,body,**kwargs)
                return hotfix.HotfixFixture.__call__(self,path,method,body,**kwargs)
        f=self.fixture
        f.api=FullHotfix()
        self.assertEqual(self.finish(self.audit('hotfix')),'published')
        self.assertTrue(f.api.release['immutable'])
        self.assertFalse(f.api.release['prerelease'])

    def test_upload_expiry_before_between_and_inflight_recovers_fresh(self):
        f=self.fixture
        now=[int(time.time())]
        for index,when in ((3,'delay-before'),(4,'delay-before'),(3,'delay-after')):
            with self.subTest(index=index,when=when), patch.object(evidence.time,'time',side_effect=lambda:now[0]):
                f.api=owner.LiveFixture()
                f.state=f.root/f'expiry-{index}-{when}'
                os.environ['GITHUB_RUN_ATTEMPT']='1'
                api=self.audit(f'expiry-{index}-{when}',{'mutation':index,'when':when,'seconds':121})
                api.sleep=lambda seconds:now.__setitem__(0,now[0]+seconds)
                f.post(f.prepare())
                with self.assertRaisesRegex(ValueError,'expired'):self.run_stage('stage',api)
                self.assertTrue(f.api.release['draft'])
                self.assertEqual(len(f.api.assets),0 if index==3 and when=='delay-before' else 1)
                original=copy.deepcopy(f.api.assets)
                f.state=f.root/f'fresh-{index}-{when}'
                os.environ['GITHUB_RUN_ATTEMPT']='2'
                api.fault={}
                self.assertEqual(self.finish(api),'published')
                for name,value in original.items():self.assertEqual(f.api.assets[name],value)

    def test_interrupted_artifact_download_has_zero_writes_and_fresh_retry_verifies(self):
        f=self.fixture
        api=self.audit('download-recovery')
        pending=[True]
        def interrupted(path,*args,**kwargs):
            if pending[0] and path=='/actions/artifacts/30/zip':
                pending[0]=False
                raise TimeoutError('Simulated interrupted download; no partial payload accepted')
            return f.api(path,*args,**kwargs)
        api.call=interrupted
        with self.assertRaises(TimeoutError):self.run_stage('prepare',api)
        self.assertEqual(f.api.writes,[])
        with self.assertRaises(evidence.ChallengeReady):self.run_stage('prepare',api)
        f.post(f.challenge('preflight'))
        with self.assertRaises(evidence.ChallengeReady):self.run_stage('stage',api)
        f.post(f.challenge('final'))
        self.assertEqual(self.run_stage('finish',api),'published')

    def test_held_entry_composes_coherent_git_source_scope_and_two_crypto_gates(self):
        import zipfile
        import sandbox_fixtures as fixtures
        import phase_d_publisher as live
        f=self.fixture
        root=f.root/'source';root.mkdir()
        files={'Cargo.toml':'[package]\nname="rolauncher"\nversion="0.0.900"\n',
            'Cargo.lock':'[[package]]\nname="rolauncher"\nversion="0.0.900"\n',
            'README.md':'# RoLauncher 0.0.900\nSandbox only\n','AGENTS.md':'Fixture instructions\n',
            'LICENSE':'Synthetic\n','THIRD_PARTY_NOTICES.md':'Synthetic\n',
            'docs/RELEASE-0.0.900.md':'# RoLauncher 0.0.900\n\n'+'Inert fixture only. '*10,
            owner.reference.PATH:json.dumps(dict(owner.reference.GitHubFixture().intent,version='0.0.900'))}
        for name,text in files.items():
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(text.encode('utf-8'))
        fixtures.git(root,'init','-q');fixtures.git(root,'add','--all')
        fixtures.git(root,'-c','user.name=Offline Fixture','-c','user.email=fixture@example.invalid',
            '-c','commit.gpgsign=false','commit','-qm','synthetic source')
        sha=fixtures.git(root,'rev-parse','HEAD').decode().strip()
        tree=[]
        for record in fixtures.git(root,'ls-tree','-rz',sha).split(b'\0'):
            if record:
                header,name=record.split(b'\t',1);mode,kind,blob=header.decode().split()
                tree.append(dict(path=name.decode(),mode=mode,type=kind,sha=blob))
        class Candidate(owner.LiveFixture):
            def __init__(self):
                super().__init__();self.intent['version']='0.0.900'
                self.run['head_sha']=self.linux_run['head_sha']=self.branch['commit']['sha']=sha
                self.pr['merge_commit_sha']=sha
                for job in self.jobs+self.linux_jobs:job['head_sha']=sha
                self.artifacts=[]
                for i,platform,group in ((30,'windows','release-files'),(31,'linux','release-linux-files')):
                    payload=fixtures.package(platform,f.root/'payload',root,sha)
                    buffer=io.BytesIO()
                    with zipfile.ZipFile(buffer,'w') as z:
                        for name,data in payload.items():z.writestr(name,data)
                    self.archives[i]=buffer.getvalue()
                    self.artifacts.append(dict(id=i,name=group+'-attempt-1',expired=False,
                        size_in_bytes=len(self.archives[i]),digest='sha256:'+hashlib.sha256(self.archives[i]).hexdigest(),
                        workflow_run=dict(id=12,head_sha=sha)))
            def __call__(self,path,method='GET',body=None,**kwargs):
                if method=='GET':
                    if path.startswith('/git/trees/'):return dict(truncated=False,tree=tree)
                    if path.startswith('/contents/'):
                        name=path.split('/contents/',1)[1].split('?ref=',1)[0]
                        raw=fixtures.git(root,'cat-file','blob',sha+':'+name)
                        return dict(encoding='base64',content=base64.b64encode(raw).decode())
                    if path=='/releases/latest':return None
                    path=path.replace(sha,owner.reference.SHA).replace('v0.0.900','v2.3.4')
                result=super().__call__(path,method,body,**kwargs)
                if method=='POST' and path=='/releases':self.tag['object']['sha']=sha
                return result
        f.api=Candidate()
        f.state=f.root/'owner-evidence'
        event=f.root/'event.json'
        event.write_text(json.dumps(dict(repository=dict(default_branch='main',id=evidence.REPO_ID,
            full_name=evidence.REPO),workflow_run=f.api.run)))
        scope=dict(schema=1,repository_id=evidence.REPO_ID,owner_id=evidence.OWNER,trusted_sha='d'*40,
            source_sha=sha,tag='v0.0.900',channel='stable',fault=None,faults_approved=False)
        cwd=Path.cwd()
        try:
            os.chdir(f.root)
            with patch.dict(os.environ,RELEASE_PROMOTION_ENABLED='true',PHASE_D_LIVE_AUTHORIZED='true',
                    PHASE_D_OPERATION_PLAN=json.dumps(dict(scope,tag='v0.0.901')),GITHUB_EVENT_PATH=str(event),
                    GITHUB_OUTPUT=str(f.root/'outputs'),GITHUB_TOKEN='disposable-not-a-credential'),\
                    patch.object(promotion,'github_api',return_value=f.api):
                with self.assertRaisesRegex(ValueError,'plan.*intent'):
                    live.main(['--stage','prepare'],policy_path=f.policy_path)
                self.assertEqual(f.api.writes,[])
                # A rejected publisher attempt keeps its append-only stage ledger.
                os.environ['GITHUB_RUN_ATTEMPT']='2'
                os.environ['PHASE_D_OPERATION_PLAN']=json.dumps(scope)
                self.assertEqual(live.main(['--stage','prepare'],policy_path=f.policy_path),'challenge-ready')
                f.post(f.challenge('preflight'))
                self.assertEqual(live.main(['--stage','stage'],policy_path=f.policy_path),'challenge-ready')
                f.post(f.challenge('final'))
                self.assertEqual(live.main(['--stage','finish'],policy_path=f.policy_path),'published')
        finally:os.chdir(cwd)
        self.assertTrue(f.api.release['immutable'])
        ledger=''.join(path.read_text(encoding='utf-8') for path in (f.root/'owner-evidence').glob('phase-d-*.jsonl'))
        self.assertIn('"value":"RUNNER_VISIBLE"',ledger)
        self.assertNotIn('disposable-not-a-credential',ledger)
        self.assertNotIn('GITHUB_TOKEN',ledger)


if __name__ == '__main__':
    unittest.main()
