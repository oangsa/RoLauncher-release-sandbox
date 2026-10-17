"""Sandbox identity isolation and source-contract checks; all API calls are fake."""
import ast
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
import socket
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.request import Request
import zipfile

import hotfix_policy
import owner_evidence as evidence
import release_files
import release_promotion as promotion
import sandbox_fixtures as fixtures

ROOT = Path(__file__).resolve().parent.parent
PRODUCTION = 'oangsa/RoLauncher'
SANDBOX = 'oangsa/RoLauncher-release-sandbox'
REPO_ID = 1423257712

spec = importlib.util.spec_from_file_location('sandbox_reference', Path(__file__).with_name('test-release-promotion.py'))
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


class PortTests(unittest.TestCase):
    def test_offline_runner_blocks_sockets_shell_and_remote_subprocesses(self):
        self.assertEqual(socket.create_connection.__name__, 'deny_network')
        self.assertEqual(subprocess.Popen.__name__, 'OfflineProcess')
        with self.assertRaisesRegex(AssertionError, 'Network'):
            socket.create_connection(('github.com', 443))
        for args, options in ((['git', 'push', 'origin', 'main'], {}),
                              (['git', 'fetch', 'origin'], {}),
                              (['gh', 'api', 'user'], {}),
                              ('git status', {'shell': True}),
                              (['git', 'status'], {'executable': 'gh'})):
            with self.subTest(args=args), self.assertRaises(AssertionError):
                subprocess.run(args, **options)

    def test_all_unchanged_security_functions_match_pinned_production_ast(self):
        contract = json.loads((ROOT / 'tests/production-contract.json').read_text())
        self.assertEqual(contract['revision'], '193c465e4d5999506f8c406ac45ff3e88d1a1a94')
        count = 0
        for filename, record in contract['files'].items():
            tree = ast.parse((ROOT / 'scripts' / filename).read_text())
            nodes = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
            for name, expected in record['ast_sha256'].items():
                actual = hashlib.sha256(ast.dump(nodes[name], include_attributes=False).encode()).hexdigest()
                self.assertEqual(actual, expected, filename + ':' + name)
                count += 1
        self.assertGreater(count, 30)

    def test_pinned_identities_unenrolled_policy_and_unchanged_limits(self):
        self.assertEqual((promotion.REPO, promotion.REPO_ID, promotion.OWNER_ID),
                         (SANDBOX, REPO_ID, 71574088))
        self.assertEqual((evidence.REPO, evidence.REPO_ID, evidence.OWNER),
                         (SANDBOX, REPO_ID, 71574088))
        self.assertEqual(evidence.NAMESPACE, 'rolauncher-sandbox-lifecycle-controls-v1')
        self.assertEqual((evidence.TTL, evidence.WAIT), (120, 1200))
        self.assertEqual((promotion.MAX_ARCHIVE_BYTES, promotion.MAX_ENTRY_BYTES,
                          promotion.MAX_EXPANDED_BYTES),
                         (256 * 1024**2, 256 * 1024**2, 512 * 1024**2))
        policy = json.loads((ROOT / '.github/owner-evidence-policy.json').read_text())
        self.assertEqual(policy, dict(schema=1, repository_id=REPO_ID, owner_id=71574088,
                                     inbox=None, public_disclosure_approved=False,
                                     disclosure_sha256=None, keys=[], revoked=[]))
        self.assertFalse((ROOT / '.github/release-intents').exists())

    def test_production_and_foreign_absolute_endpoints_rejected_before_transport(self):
        forbidden = [
            'https://api.github.com/repos/' + PRODUCTION,
            'https://api.github.com/repos/' + PRODUCTION + '/releases',
            'https://uploads.github.com/repos/' + PRODUCTION + '/releases/1/assets?name=test.zip',
            'https://api.github.com/repos/' + SANDBOX + '-foreign/releases',
            'https://api.github.com/repos/' + SANDBOX + '/../RoLauncher/releases',
            'https://api.github.com/repos/' + SANDBOX + '/%2e%2e/RoLauncher/releases',
            'https://api.github.com/repos/' + SANDBOX + '/%252e%252e/RoLauncher/releases',
            'https://api.github.com:443/repos/' + SANDBOX + '/releases',
            'https://api.github.com@attacker.invalid/repos/' + SANDBOX + '/releases',
            'http://api.github.com/repos/' + SANDBOX + '/releases',
            'https://attacker.invalid/releases',
        ]
        with patch.object(promotion, 'build_opener') as factory:
            api = promotion.github_api('synthetic-token-never-sent')
            for endpoint in forbidden:
                with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                    api(endpoint, 'POST', {'draft': False})
            factory.return_value.open.assert_not_called()

    def test_valid_api_and_upload_routes_keep_the_sandbox_scope(self):
        urls = []
        class Response(io.BytesIO):
            headers = {}
        def opened(request, **kwargs):
            urls.append(request.full_url)
            return Response(b'{}')
        with patch.object(promotion, 'build_opener') as factory:
            factory.return_value.open.side_effect = opened
            api = promotion.github_api('synthetic-token-never-sent')
            api('')
            api('/releases/1')
            api('https://uploads.github.com/repos/' + SANDBOX + '/releases/1/assets?name=fixture.zip',
                'POST', binary=b'inert')
        self.assertEqual(urls, ['https://api.github.com/repos/' + SANDBOX,
                               'https://api.github.com/repos/' + SANDBOX + '/releases/1',
                               'https://uploads.github.com/repos/' + SANDBOX + '/releases/1/assets?name=fixture.zip'])

    def test_redirects_cannot_forward_credentials_to_production(self):
        request = Request('https://api.github.com/repos/' + SANDBOX + '/actions/artifacts/1/zip',
                          headers={'Authorization': 'Bearer synthetic-not-a-token'})
        handler = promotion.SafeRedirect()
        for target in ('https://api.github.com/repos/' + PRODUCTION + '/releases',
                       'https://uploads.github.com/repos/' + PRODUCTION + '/releases/1/assets?name=x',
                       'https://github.com/' + PRODUCTION + '/releases',
                       'http://storage.example.invalid/archive.zip'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, '', {}, target)
        redirected = handler.redirect_request(request, None, 302, '', {},
                                              'https://storage.example.invalid/archive.zip?redacted')
        self.assertNotIn('Authorization', redirected.headers)
        self.assertNotIn('Bearer', repr(redirected.headers))

    def test_wrong_source_pr_owner_and_event_numeric_identities_fail_closed(self):
        for fault in ('source-name', 'head-name', 'source-id', 'head-id', 'pr-base-id', 'pr-head-id', 'owner-id'):
            api = reference.GitHubFixture().with_intent()
            if fault == 'source-name': api.run['repository']['full_name'] = PRODUCTION
            if fault == 'head-name': api.run['head_repository']['full_name'] = PRODUCTION
            if fault == 'source-id': api.run['repository']['id'] = 1406138209
            if fault == 'head-id': api.run['head_repository']['id'] = 1406138209
            if fault == 'pr-base-id': api.pr['base']['repo']['id'] = 1406138209
            if fault == 'pr-head-id': api.pr['head']['repo']['id'] = 1406138209
            def call(path, *args, **kwargs):
                value = api(path, *args, **kwargs)
                if path == '' and fault == 'owner-id':
                    value['owner']['id'] = 7
                return value
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                promotion.authorize(call, api.run)
            self.assertEqual(api.writes, [])
        api = reference.GitHubFixture().with_intent()
        event = dict(repository={'default_branch': 'main', 'full_name': PRODUCTION, 'id': 1406138209},
                     workflow_run=api.run)
        with self.assertRaisesRegex(ValueError, 'event repository'):
            promotion.promote_event(api, event)
        self.assertEqual(api.writes, [])

    def test_production_publisher_environment_cannot_create_transport_or_state(self):
        with tempfile.TemporaryDirectory() as folder:
            for fault in ('name', 'id', 'workflow'):
                env = dict(GITHUB_REPOSITORY=SANDBOX, GITHUB_REPOSITORY_ID=str(REPO_ID),
                           GITHUB_EVENT_NAME='workflow_run',
                           GITHUB_WORKFLOW_REF=SANDBOX + '/' + evidence.WORKFLOW + '@refs/heads/main')
                if fault == 'name': env['GITHUB_REPOSITORY'] = PRODUCTION
                if fault == 'id': env['GITHUB_REPOSITORY_ID'] = '1406138209'
                if fault == 'workflow': env['GITHUB_WORKFLOW_REF'] = PRODUCTION + '/' + evidence.WORKFLOW + '@refs/heads/main'
                with self.subTest(fault=fault), patch.dict(os.environ, env), self.assertRaises(ValueError):
                    evidence.StagedEvidence('prepare', state=Path(folder) / 'forbidden-state')
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_owner_helper_cannot_address_foreign_routes_before_cli(self):
        with patch.object(evidence, 'bounded_process') as process:
            for path in ('https://api.github.com/repos/' + PRODUCTION,
                         '/repos/' + PRODUCTION + '/issues/1/comments',
                         '/../RoLauncher/releases', '/releases', '/git/refs'):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    evidence.gh_api(path, {'body': 'forbidden'}, inbox=1)
            process.assert_not_called()

    def test_every_workflow_job_is_literal_false_and_repository_pinned(self):
        for workflow in (ROOT / '.github/workflows').glob('*.yml'):
            text = workflow.read_text()
            jobs = text.split('\njobs:\n', 1)[1].splitlines()
            job_headers = [i for i, line in enumerate(jobs) if line.startswith('  ') and not line.startswith('   ') and line.endswith(':')]
            self.assertTrue(job_headers, workflow.name)
            for position, index in enumerate(job_headers):
                end = job_headers[position + 1] if position + 1 < len(job_headers) else len(jobs)
                job = '\n'.join(jobs[index:end])
                with self.subTest(workflow=workflow.name, job=jobs[index]):
                    self.assertIn('    if: >-\n      false &&', job)
                    self.assertIn("github.repository == '" + SANDBOX + "'", job)
                    self.assertIn("github.repository_id == '1423257712'", job)
            self.assertNotIn('pull_request_target', text)
            self.assertNotIn('administration:', text)
            if workflow.name != 'release-promotion.yml':
                self.assertNotIn('contents: write', text)
                self.assertNotIn('scripts/publish-', text)

    def test_legacy_beta_write_seam_is_absent(self):
        tree = ast.parse((ROOT / 'scripts/publish-beta.py').read_text())
        self.assertFalse(any(isinstance(n, ast.FunctionDef) and n.name == 'publish' for n in tree.body))
        self.assertIn("main('beta')", (ROOT / 'scripts/publish-beta.py').read_text())

    def test_inert_fixtures_are_deterministic_and_exact_source_passes_verifier(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'source'
            root.mkdir()
            self.assertEqual(subprocess.run(['git', 'init', '-q', str(root)], capture_output=True).returncode, 0)
            fixture_inputs = {
                'Cargo.toml': b'[package]\nname="rolauncher"\nversion="0.0.900"\n',
                'Cargo.lock': b'[[package]]\nname="rolauncher"\nversion="0.0.900"\n',
                'README.md': b'# RoLauncher 0.0.900\nSandbox only\n',
                'AGENTS.md': b'Synthetic test source rules\n',
                'LICENSE': b'Synthetic test license notice\n',
                'THIRD_PARTY_NOTICES.md': b'No binary third party dependencies\n',
            }
            for name, data in fixture_inputs.items():
                (root / name).write_bytes(data)
            fixtures.git(root, 'add', '--all')
            fixtures.git(root, '-c', 'user.name=Offline Fixture', '-c', 'user.email=fixture@example.invalid',
                         '-c', 'commit.gpgsign=false', 'commit', '-qm', 'synthetic offline fixture')
            sha = fixtures.git(root, 'rev-parse', 'HEAD').decode().strip()
            first, second = Path(folder) / 'first', Path(folder) / 'second'
            win = fixtures.package('windows', first, root)
            linux = fixtures.package('linux', first, root)
            self.assertEqual(win, fixtures.package('windows', second, root))
            self.assertEqual(linux, fixtures.package('linux', second, root))
            prefix = 'rolauncher-v0.0.900'
            self.assertFalse(win[prefix + '-setup-x64.exe'].startswith(b'MZ'))
            combined = release_files.checked_files(first, '0.0.900')
            self.assertEqual(len(combined), 5)
            tree = {'truncated': False, 'tree': [
                dict(path=name, type='blob', mode='100644',
                     sha=hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest())
                for name, data in fixture_inputs.items()
            ]}
            hotfix_policy.verify_source(lambda _: tree, sha, win[prefix + '-source.zip'])
            with zipfile.ZipFile(io.BytesIO(win[prefix + '-source.zip'])) as archive:
                self.assertEqual(set(archive.namelist()), set(fixture_inputs))
            with self.assertRaises(ValueError):
                fixtures.package('unknown', second, root)
            with self.assertRaises(ValueError):
                fixtures.source_files(root, 'main')
