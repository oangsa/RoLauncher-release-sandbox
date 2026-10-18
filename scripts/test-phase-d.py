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
        def backend(path,method='GET',body=None,**kwargs):
            if method!='GET':writes.append(path)
            return dict(id=50,tag_name='v0.0.900',target_commitish='a'*40,prerelease=False)
        api=live.scoped_call(backend,dict(tag='v0.0.900',source_sha='a'*40,channel='stable'))
        body=dict(draft=False,prerelease=False,make_latest='true')
        with self.assertRaises(ValueError):api('/releases/999','PATCH',body)
        self.assertEqual(writes,[])
        api('/releases/tags/v0.0.900')
        with self.assertRaises(ValueError):
            api('https://uploads.github.com/repos/'+evidence.REPO+'/releases/999/assets?name=release-promotion.json',
                'POST',binary=b'inert')
        self.assertEqual(writes,[])
        api('/releases/50','PATCH',body)
        self.assertEqual(writes,['/releases/50'])
    def test_large_fixture_capacity_and_streamed_bytes(self):
        import phase_d_fixtures as large
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder)/'inert.bin'
            large.write_inert(target,4096)
            self.assertEqual(target.stat().st_size,4096)
            self.assertFalse(target.read_bytes().startswith(b'MZ'))
            self.assertEqual(target.read_bytes()[100:],bytes(3996))
            with self.assertRaises(ValueError):large.capacity(512*1024**2,256*1024**2)
            self.assertEqual(large.capacity(256*1024**2,128*1024**2)['windows_bytes'],256*1024**2)

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
        binding=dict(source=dict(id=12,run_attempt=1,head_sha='a'*40),intent=dict(version='0.0.900',channel='stable'))
        live.verify_source_artifact(cached,binding)
        live.verify_source_artifact(cached,binding)
        self.assertEqual(calls.count('/actions/artifacts/30/zip'),1)
    def test_http_outcome_observer_receives_status_only(self):
        class Response(io.BytesIO):
            headers={}
            status=201
        class Connection:
            def open(self,*args,**kwargs): return Response(b'{"id":50}')
        statuses=[]
        with patch.object(promotion,'build_opener',return_value=Connection()):
            api=promotion.github_api('disposable-not-a-credential',observer=statuses.append)
            self.assertEqual(api('/releases','POST',{'draft':True}),{'id':50})
        self.assertEqual(statuses,[201])
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
                attempts = [r for r in rows if r['method']!='GET' and r['outcome']=='returned']
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
                        raw=fixtures.git(root,'show',sha+':'+name)
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
                    PHASE_D_OPERATION_PLAN=json.dumps(scope),GITHUB_EVENT_PATH=str(event),
                    GITHUB_OUTPUT=str(f.root/'outputs'),GITHUB_TOKEN='disposable-not-a-credential'),\
                    patch.object(promotion,'github_api',return_value=f.api):
                self.assertEqual(live.main(['--stage','prepare'],policy_path=f.policy_path),'challenge-ready')
                f.post(f.challenge('preflight'))
                self.assertEqual(live.main(['--stage','stage'],policy_path=f.policy_path),'challenge-ready')
                f.post(f.challenge('final'))
                self.assertEqual(live.main(['--stage','finish'],policy_path=f.policy_path),'published')
        finally:os.chdir(cwd)
        self.assertTrue(f.api.release['immutable'])


if __name__ == '__main__':
    unittest.main()
