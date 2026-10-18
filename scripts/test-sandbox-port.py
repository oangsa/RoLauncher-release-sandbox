"""Sandbox identity isolation and source-contract checks; all API calls are fake."""
import ast
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
import re
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

# promote deliberately diverges from the production byte-only implementation to
# require bounded, file-backed staging for the Phase D publisher path. Keep that
# reviewed adaptation pinned independently while every other protected function
# remains pinned to the production contract.
REVIEWED_AST_DIVERGENCES = {
    ('release_promotion.py', 'promote'): '0d7b095b1018eacecdd5270ed86832727d0006fe6ab13d5b5b58c6c8f6e12a46',
}

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

    def test_security_functions_match_pinned_production_or_reviewed_phase_d_ast(self):
        contract = json.loads((ROOT / 'tests/production-contract.json').read_text())
        self.assertEqual(contract['revision'], '193c465e4d5999506f8c406ac45ff3e88d1a1a94')
        count = 0
        for filename, record in contract['files'].items():
            tree = ast.parse((ROOT / 'scripts' / filename).read_text())
            nodes = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
            for name, expected in record['ast_sha256'].items():
                actual = hashlib.sha256(ast.dump(nodes[name], include_attributes=False).encode()).hexdigest()
                reviewed = REVIEWED_AST_DIVERGENCES.get((filename, name))
                self.assertEqual(actual, reviewed or expected, filename + ':' + name)
                count += 1
        self.assertGreater(count, 30)

    def test_pinned_enrollment_identities_and_unchanged_limits(self):
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
                                     inbox=5, public_disclosure_approved=True,
                                     disclosure_sha256='c48b4ebe3972abe2d5fe75b2ef7e5a0f70065c3b7e5c71a7bc9cd8a18d09c368',
                                     keys=['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJPXo+4JhA/+CwDnDNJYnUctFyayOVMwOMZLG1hMGhfX'],
                                     revoked=[]))
        loaded, active = evidence.load_policy()
        self.assertEqual(loaded, policy)
        self.assertEqual(active, policy['keys'])
        raw = base64.b64decode(active[0].split()[1], validate=True)
        self.assertEqual(raw[:19], b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 ')
        self.assertEqual(len(raw), 51)
        self.assertEqual('SHA256:' + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('='),
                         'SHA256:jG13DdI7llxXe3kfcJ2xnu8kftf2xe41QMv8hYkuuiQ')
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
            def geturl(self): return self.url
        def opened(request, **kwargs):
            urls.append(request.full_url)
            response = Response(b'{}')
            response.url = request.full_url
            return response
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

    def test_hosted_ci_and_manual_readiness_are_repository_pinned(self):
        enabled = {('ci-release.yml', 'branch-flow'), ('ci-release.yml', 'windows-checks'),
                   ('ci-release.yml', 'linux-checks'), ('linux.yml', 'linux-checks'),
                   ('phase-d-readiness.yml', 'inspect'), ('release-promotion.yml', 'promote')}
        disabled = {('beta-release.yml', 'windows-checks'), ('beta-release.yml', 'linux-checks'),
                    ('owner-evidence-dry-run.yml', 'verify')}
        seen = set()
        for workflow in (ROOT / '.github/workflows').glob('*.yml'):
            text = workflow.read_text()
            jobs = text.split('\njobs:\n', 1)[1].splitlines()
            job_headers = [i for i, line in enumerate(jobs) if line.startswith('  ') and not line.startswith('   ') and line.endswith(':')]
            self.assertTrue(job_headers, workflow.name)
            for position, index in enumerate(job_headers):
                end = job_headers[position + 1] if position + 1 < len(job_headers) else len(jobs)
                job = '\n'.join(jobs[index:end])
                identity = (workflow.name, jobs[index].strip().removesuffix(':'))
                seen.add(identity)
                with self.subTest(workflow=workflow.name, job=jobs[index]):
                    guard = ('    if: >-\n' + ('' if identity in enabled else '      false &&\n')
                             + "      github.repository == '" + SANDBOX + "' &&\n"
                             + "      github.repository_id == '1423257712'")
                    if identity == ('release-promotion.yml', 'promote'):
                        guard = guard.replace("      github.repository ==",
                            "      vars.RELEASE_PROMOTION_ENABLED == 'true' &&\n"
                            "      vars.PHASE_D_LIVE_AUTHORIZED == 'true' &&\n"
                            "      github.repository ==")
                    self.assertIn(guard, job)
            self.assertNotIn('pull_request_target', text)
            self.assertNotIn('administration:', text)
            for action in re.findall(r'uses: (\S+)', text):
                self.assertRegex(action, r'^[\w./-]+@[a-f0-9]{40}$')
            if workflow.name not in ('release-promotion.yml','phase-d-readiness.yml'):
                self.assertNotIn('contents: write', text)
            if workflow.name != 'release-promotion.yml':
                self.assertNotIn('scripts/publish-', text)
            if workflow.name=='phase-d-readiness.yml':
                self.assertEqual(text.split('on:\n',1)[1].split('\npermissions:',1)[0].strip(),
                                 'workflow_dispatch:')
                self.assertIn("      github.ref == 'refs/heads/main'",text)
                self.assertNotIn('  push:',text)
                self.assertNotIn('workflow_run:',text)
                self.assertIn('run: python scripts/phase_d_readiness.py',text)
                self.assertIn('        if: always()\n        with:\n          name: phase-d-readiness-',text)
            if workflow.name in ('ci-release.yml', 'linux.yml'):
                self.assertIn('permissions:\n  contents: read\n', text)
                self.assertIn('scripts/offline_tests.py', text)
                self.assertNotRegex(text, r'\b(cargo|dotnet|msbuild)\b')
                for step in text.split('      - uses: actions/upload-artifact@')[1:]:
                    self.assertIn("if: github.event_name == 'push' && github.ref == 'refs/heads/main'", step)
        self.assertEqual(seen, enabled | disabled)

    def test_bootstrap_uses_existing_development_and_promotion_admission(self):
        def no_api(*args, **kwargs):
            self.fail('Development bootstrap must not need release evidence')
        for base, head, expected in (('dev', 'codex/sandbox-hosted-ci', 'development'),
                                     ('dev', 'feature/sandbox-hosted-ci', 'development'),
                                     ('main', 'dev', 'feature-promotion')):
            event = dict(pull_request=dict(base=dict(ref=base),
                                          head=dict(ref=head, repo=dict(full_name=SANDBOX))))
            with self.subTest(base=base, head=head):
                self.assertEqual(hotfix_policy.check_branch_flow(event, no_api), expected)
        event = dict(pull_request=dict(base=dict(ref='main'),
                                      head=dict(ref='codex/sandbox-hosted-ci', repo=dict(full_name=SANDBOX))))
        with self.assertRaisesRegex(ValueError, 'Unauthorized main source branch'):
            hotfix_policy.check_branch_flow(event, no_api)
        event['pull_request']['head'] = dict(ref='dev', repo=dict(full_name=PRODUCTION))
        with self.assertRaisesRegex(ValueError, 'Official main PR required'):
            hotfix_policy.check_branch_flow(event, no_api)

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
