"""Sandbox-only evidence protocol. No release, tag, intent, or production write code."""
import argparse
import base64
import copy
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from urllib.request import Request, build_opener, HTTPRedirectHandler
import zipfile

ROOT = Path(__file__).resolve().parent
REPO = 'oangsa/RoLauncher-release-sandbox'
REPO_ID = 1423257712
OWNER = 71574088
WORKFLOW = '.github/workflows/owner-evidence-dry-run.yml'
NAMESPACE = 'rolauncher-sandbox-evidence'
PRINCIPAL = 'github-user-71574088'
CONTEXT = {'schema', 'purpose', 'repository', 'repository_id', 'owner_id', 'workflow',
           'workflow_sha', 'source_sha', 'run_id', 'attempt', 'phase', 'nonce', 'created', 'deadline', 'inbox'}
PAYLOAD = {'schema', 'purpose', 'challenge', 'challenge_sha256', 'collection_start',
           'collection_end', 'expires', 'rulesets'}
FAULTS = {'tampered-signature': 'signature', 'expired': 'expired', 'wrong-nonce': 'binding',
          'wrong-repository': 'binding', 'wrong-attempt': 'binding', 'wrong-source': 'binding',
          'wrong-phase': 'binding', 'unexpected-actors': 'actors', 'missing-bypasses': 'bypasses'}
FIELDS = ('id', 'source', 'target', 'enforcement', 'conditions', 'rules', 'bypass_actors')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')


def unique(pairs):
    value = dict(pairs)
    require(len(value) == len(pairs), 'duplicate fields')
    return value


def parse(data, limit=48 * 1024):
    require(len(data) <= limit, 'message size')
    return json.loads(data, object_pairs_hook=unique)


def policy():
    p = parse((ROOT / 'policy.json').read_bytes())
    require(p['repository'] == REPO and p['repository_id'] == REPO_ID and p['owner_id'] == OWNER,
            'sandbox policy identity')
    require(set(p['fixtures']) == {'25300842', '25300914'}, 'fixture identities')
    return p


def ssh():
    executable = shutil.which('ssh-keygen')
    if not executable and os.name == 'nt':
        executable = 'C:/Windows/System32/OpenSSH/ssh-keygen.exe'
    require(executable is not None, 'OpenSSH unavailable')
    return executable


def gh():
    executable = shutil.which('gh')
    if not executable and os.name == 'nt':
        candidate = Path('C:/Program Files/GitHub CLI/gh.exe')
        if candidate.is_file():
            executable = str(candidate)
    require(executable is not None, 'GitHub CLI unavailable')
    return executable


def read_path(path):
    return bool(re.fullmatch(r'/rulesets/(25300842|25300914)|/actions/runs/[1-9][0-9]*'
                            r'|/actions/runs/[1-9][0-9]*/artifacts\?per_page=100'
                            r'|/actions/artifacts/[1-9][0-9]*/zip'
                            r'|/issues/1/comments\?per_page=100&since=[0-9TZ:%.-]+'
                            r'|/issues/comments/[1-9][0-9]*', path))


def gh_api(path, body=None, raw=False):
    # The only owner-side mutation is posting to this sandbox's fixed inbox.
    allowed_post = path == '/issues/1/comments' and body is not None
    require((read_path(path) and body is None) or allowed_post or (path == 'user' and body is None),
            'owner endpoint denied')
    endpoint = 'user' if path == 'user' else 'repos/' + REPO + path
    args = [gh(), 'api', '--method', 'POST' if body is not None else 'GET', endpoint]
    data = None
    if body is not None:
        require(set(body) == {'body'} and len(body['body'].encode()) <= 48 * 1024, 'comment shape/size')
        args += ['--input', '-']
        data = canonical(body)
    result = subprocess.run(args, input=data, capture_output=True)
    require(result.returncode == 0, 'GitHub CLI request failed; inspect authentication/permissions locally')
    require(len(result.stdout) <= 2 * 1024 * 1024, 'GitHub CLI response size')
    return result.stdout if raw else parse(result.stdout, 2 * 1024 * 1024)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('runner API redirects denied')


def runner_get(path):
    require(read_path(path) and '/zip' not in path, 'runner endpoint denied')
    request = Request('https://api.github.com/repos/' + REPO + path, headers={
        'Authorization': 'Bearer ' + os.environ['GITHUB_TOKEN'],
        'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'RoLauncher-sandbox-evidence'})
    with build_opener(NoRedirect()).open(request, timeout=20) as response:
        return parse(response.read(2 * 1024 * 1024 + 1), 2 * 1024 * 1024)


def fixture_evidence(items):
    p = policy()
    require(isinstance(items, list) and len(items) == 2, 'fixture collection')
    require({str(x.get('id')) for x in items} == set(p['fixtures']), 'fixture identity')
    for item in items:
        require('bypass_actors' in item and isinstance(item['bypass_actors'], list), 'bypasses missing')
        require(set(item) == set(FIELDS), 'fixture fields')
        expected = p['fixtures'][str(item['id'])]
        require(item['bypass_actors'] == expected['bypass_actors'], 'actors unexpected')
        require(item == expected, 'fixture definition changed')


def check_challenge(c, now=None):
    now = int(time.time()) if now is None else now
    p = policy()
    require(isinstance(c, dict) and set(c) == CONTEXT, 'challenge fields')
    require(type(c['schema']) is int and c['schema'] == 1 and c['purpose'] == 'non-publishing-sandbox', 'challenge purpose')
    require(c['repository'] == REPO and type(c['repository_id']) is int and c['repository_id'] == REPO_ID
            and type(c['owner_id']) is int and c['owner_id'] == OWNER, 'challenge sandbox')
    require(c['workflow'] == WORKFLOW and c['inbox'] == p['inbox'], 'challenge workflow/inbox')
    require(all(isinstance(c[k], str) and re.fullmatch('[a-f0-9]{40}', c[k])
                for k in ('source_sha', 'workflow_sha')), 'challenge source')
    require(c['source_sha'] == c['workflow_sha'], 'sandbox source/workflow mismatch')
    require(all(type(c[k]) is int and c[k] > 0 for k in ('run_id', 'attempt')), 'challenge run')
    require(c['phase'] in ('preflight', 'final') and isinstance(c['nonce'], str)
            and re.fullmatch('[a-f0-9]{64}', c['nonce']), 'challenge phase/nonce')
    require(type(c['created']) is int and type(c['deadline']) is int
            and c['deadline'] == c['created'] + 600 and c['created'] <= now + 5 <= c['deadline'] + 5,
            'challenge deadline')


def signed(payload, key):
    data = canonical(payload)
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / 'message.json'
        path.write_bytes(data)
        result = subprocess.run([ssh(), '-Y', 'sign', '-f', str(Path(key).resolve()), '-n', NAMESPACE, str(path)],
                                capture_output=True)
        require(result.returncode == 0, 'local signing failed')
        signature = Path(str(path) + '.sig').read_text(encoding='ascii')
    return {'payload_base64': base64.b64encode(data).decode('ascii'), 'signature': signature}


def verify(item, challenge, consumed, now=None):
    now = int(time.time()) if now is None else now
    require(isinstance(item, dict) and set(item) == {'payload_base64', 'signature'}, 'response fields')
    require(isinstance(item['payload_base64'], str) and isinstance(item['signature'], str)
            and len(item['signature']) < 2048, 'response shape')
    data = base64.b64decode(item['payload_base64'], validate=True)
    require(len(data) <= 32 * 1024, 'payload size')
    with tempfile.TemporaryDirectory() as folder:
        signature = Path(folder) / 'message.sig'
        signature.write_text(item['signature'], encoding='ascii')
        result = subprocess.run([ssh(), '-Y', 'verify', '-f', str(ROOT / 'allowed_signers'),
                                 '-I', PRINCIPAL, '-n', NAMESPACE, '-s', str(signature)],
                                input=data, capture_output=True)
        require(result.returncode == 0, 'signature rejected')
    payload = parse(data, 32 * 1024)
    require(isinstance(payload, dict) and set(payload) == PAYLOAD, 'payload fields')
    require(type(payload['schema']) is int and payload['schema'] == 1
            and payload['purpose'] == 'non-publishing-sandbox-evidence', 'payload purpose')
    require(canonical(payload['challenge']) == canonical(challenge)
            and payload['challenge_sha256'] == hashlib.sha256(canonical(challenge)).hexdigest(), 'binding mismatch')
    check_challenge(challenge, now)
    times = [payload[k] for k in ('collection_start', 'collection_end', 'expires')]
    require(all(type(t) is int for t in times), 'time types')
    start, end, expires = times
    require(challenge['created'] <= start <= end <= now + 5 and end - start <= 30
            and expires == start + 60 and now <= expires, 'expired/future/slow evidence')
    require(challenge['nonce'] not in consumed, 'replay rejected')
    fixture_evidence(payload['rulesets'])
    consumed.add(challenge['nonce'])
    return payload


def bundle(payload, key):
    cases = {'valid': signed(payload, key)}
    for name in FAULTS:
        altered = copy.deepcopy(payload)
        if name == 'tampered-signature':
            item = copy.deepcopy(cases['valid'])
            # Preserve SSHSIG framing; corrupt the actual signature bytes.
            armor = item['signature'].strip().splitlines()
            raw = bytearray(base64.b64decode(''.join(armor[1:-1]), validate=True))
            raw[-1] ^= 1
            encoded = base64.b64encode(raw).decode('ascii')
            item['signature'] = armor[0] + '\n' + '\n'.join(
                encoded[i:i + 70] for i in range(0, len(encoded), 70)) + '\n' + armor[-1] + '\n'
            require(item != cases['valid'], 'tamper vector not changed')
            cases[name] = item
            continue
        if name == 'expired':
            for field in ('collection_start', 'collection_end', 'expires'):
                altered[field] -= 120
        if name == 'wrong-nonce': altered['challenge']['nonce'] = '0' * 64
        if name == 'wrong-repository': altered['challenge']['repository'] = 'oangsa/not-the-sandbox'
        if name == 'wrong-attempt': altered['challenge']['attempt'] += 1
        if name == 'wrong-source': altered['challenge']['source_sha'] = '0' * 40
        if name == 'wrong-phase': altered['challenge']['phase'] = 'final' if payload['challenge']['phase'] == 'preflight' else 'preflight'
        if name == 'unexpected-actors': altered['rulesets'][0]['bypass_actors'].append(
            {'actor_type': 'RepositoryRole', 'actor_id': 4, 'bypass_mode': 'always'})
        if name == 'missing-bypasses': altered['rulesets'][0].pop('bypass_actors')
        cases[name] = signed(altered, key)
    return {'protocol': 'sandbox-test-cases-v1', 'cases': cases}


def exercise(response, challenge, consumed):
    require(set(response) == {'protocol', 'cases'} and response['protocol'] == 'sandbox-test-cases-v1', 'test wrapper')
    cases = response['cases']
    require(set(cases) == set(FAULTS) | {'valid'}, 'test case inventory')
    results = {}
    for name, expected in FAULTS.items():
        try:
            verify(cases[name], challenge, set())
        except ValueError as error:
            require(expected in str(error), name + ': unexpected denial')
            results[name] = 'rejected: ' + str(error)
        else:
            raise ValueError(name + ': unexpectedly accepted')
    verify(cases['valid'], challenge, consumed)
    results['valid'] = 'accepted'
    try:
        verify(cases['valid'], challenge, consumed)
    except ValueError as error:
        require('replay' in str(error), 'wrong replay denial')
        results['same-challenge-replay'] = 'rejected'
    else:
        raise ValueError('same challenge replay accepted')
    return results


def challenge_command(phase):
    require(os.environ['GITHUB_REPOSITORY'] == REPO and os.environ['GITHUB_REPOSITORY_ID'] == str(REPO_ID), 'runner sandbox only')
    require(os.environ['GITHUB_REF'] == 'refs/heads/main' and os.environ['GITHUB_EVENT_NAME'] in ('push', 'workflow_dispatch'), 'runner event/ref')
    now = int(time.time())
    c = dict(schema=1, purpose='non-publishing-sandbox', repository=REPO, repository_id=REPO_ID,
             owner_id=OWNER, workflow=WORKFLOW, workflow_sha=os.environ['GITHUB_WORKFLOW_SHA'],
             source_sha=os.environ['GITHUB_SHA'], run_id=int(os.environ['GITHUB_RUN_ID']),
             attempt=int(os.environ['GITHUB_RUN_ATTEMPT']), phase=phase, nonce=secrets.token_hex(32),
             created=now, deadline=now + 600, inbox=policy()['inbox'])
    check_challenge(c)
    path = Path('challenges') / phase / 'challenge.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(c))
    visibility = {}
    for fixture in policy()['fixtures']:
        raw = runner_get('/rulesets/' + fixture)
        visibility[fixture] = {'bypass_field_present': 'bypass_actors' in raw}
    Path('runtime-visibility.json').write_bytes(canonical(visibility))
    print(json.dumps({'phase': phase, 'run': c['run_id'], 'attempt': c['attempt'], 'runtime_visibility': visibility}))


def wait_command(phase):
    c = parse((Path('challenges') / phase / 'challenge.json').read_bytes())
    check_challenge(c)
    state_path = Path('accepted-state.json')
    state = parse(state_path.read_bytes()) if state_path.exists() else {'nonces': [], 'phases': {}}
    require(phase not in state['phases'], 'phase already consumed')
    require(phase != 'final' or 'preflight' in state['phases'], 'preflight required')
    since = datetime.fromtimestamp(c['created'] - 5, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    while int(time.time()) < c['deadline']:
        comments = runner_get(f'/issues/1/comments?per_page=100&since={since}')
        require(isinstance(comments, list) and len(comments) < 100, 'incomplete inbox collection')
        matches = []
        for comment in comments:
            if comment['user']['id'] != OWNER:
                continue
            try:
                response = parse(comment['body'].encode())
                item = parse(base64.b64decode(response['cases']['valid']['payload_base64'], validate=True))
                if item['challenge'] == c:
                    matches.append((comment, response))
            except (ValueError, KeyError, TypeError):
                continue
        require(len(matches) <= 1, 'conflicting owner responses')
        if matches:
            comment, response = matches[0]
            fresh = runner_get('/issues/comments/' + str(comment['id']))
            require(fresh['body'] == comment['body'] and fresh['user']['id'] == OWNER
                    and fresh['created_at'] == fresh['updated_at'], 'comment changed/edited')
            consumed = set(state['nonces'])
            results = exercise(response, c, consumed)
            if phase == 'final':
                previous = state['phases']['preflight']['response']['cases']['valid']
                try:
                    verify(previous, c, set())
                except ValueError as error:
                    require('binding' in str(error), 'wrong cross-gate replay denial')
                    results['preflight-replayed-at-final'] = 'rejected'
                else:
                    raise ValueError('cross-gate replay accepted')
            state['nonces'] = sorted(consumed)
            state['phases'][phase] = {'comment_id': comment['id'], 'results': results, 'response': response}
            state_path.write_bytes(canonical(state))
            Path('result-' + phase + '.json').write_bytes(canonical({'phase': phase, 'results': results,
                'comment_url': comment['html_url'], 'run_id': c['run_id'], 'attempt': c['attempt'],
                'source_sha': c['source_sha'], 'non_publishing': True}))
            print(json.dumps({'phase': phase, 'results': results, 'non_publishing': True}))
            return
        time.sleep(5)
    raise ValueError('owner response wait expired')


def download_challenge(run_id, attempt, phase):
    result = gh_api(f'/actions/runs/{run_id}/artifacts?per_page=100')
    require(result['total_count'] == len(result['artifacts']) < 100, 'artifact collection')
    name = f'challenge-{run_id}-{attempt}-{phase}'
    matches = [a for a in result['artifacts'] if a['name'] == name]
    require(len(matches) <= 1, 'ambiguous challenge artifact')
    if not matches:
        return None
    artifact = matches[0]
    require(not artifact['expired'] and artifact['workflow_run']['id'] == run_id
            and artifact['workflow_run']['repository_id'] == REPO_ID and artifact['size_in_bytes'] < 65536,
            'artifact provenance/size')
    raw = gh_api('/actions/artifacts/' + str(artifact['id']) + '/zip', raw=True)
    require(artifact['digest'] == 'sha256:' + hashlib.sha256(raw).hexdigest(), 'challenge artifact digest')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        require(len(entries) == 1 and entries[0].filename == 'challenge.json'
                and entries[0].file_size < 16384 and not entries[0].flag_bits & 1
                and entries[0].external_attr >> 16 & 0o170000 != 0o120000, 'challenge archive inventory')
        return parse(archive.read(entries[0]), 16384)


def attend(args):
    require(args.approve_public_evidence, 'explicit public evidence approval required')
    identity = gh_api('user')
    require(identity['id'] == OWNER and identity['login'] == 'oangsa', 'owner CLI identity')
    require(Path(args.key).is_file(), 'local test key missing')
    overall_deadline = time.monotonic() + 1500
    attempt = None
    for phase in ('preflight', 'final'):
        while time.monotonic() < overall_deadline:
            run = gh_api(f'/actions/runs/{args.run_id}')
            require(run['path'] == WORKFLOW and run['head_sha'] == args.expected_sha
                    and run['head_branch'] == 'main' and run['event'] in ('push', 'workflow_dispatch')
                    and run['repository']['id'] == REPO_ID and run['head_repository']['id'] == REPO_ID,
                    'owner run provenance')
            attempt = run['run_attempt'] if attempt is None else attempt
            require(run['run_attempt'] == attempt, 'run attempt changed')
            require(run['status'] != 'completed', 'workflow already completed before evidence delivery')
            c = download_challenge(args.run_id, attempt, phase)
            if c is None:
                time.sleep(5)
                continue
            check_challenge(c)
            require(c['run_id'] == args.run_id and c['attempt'] == attempt
                    and c['source_sha'] == args.expected_sha and c['phase'] == phase, 'artifact challenge binding')
            start = int(time.time())
            rulesets = []
            for fixture in sorted(policy()['fixtures']):
                raw = gh_api('/rulesets/' + fixture)
                require('bypass_actors' in raw, 'owner bypass evidence missing')
                rulesets.append({field: raw[field] for field in FIELDS})
            fixture_evidence(rulesets)
            end = int(time.time())
            require(end - start <= 30, 'owner collection too slow')
            payload = dict(schema=1, purpose='non-publishing-sandbox-evidence', challenge=c,
                challenge_sha256=hashlib.sha256(canonical(c)).hexdigest(), collection_start=start,
                collection_end=end, expires=start + 60, rulesets=rulesets)
            response = bundle(payload, args.key)
            exercise(response, c, set())
            body = canonical(response).decode()
            require(len(body.encode()) <= 48 * 1024, 'comment budget exceeded')
            posted = gh_api('/issues/1/comments', {'body': body})
            print(json.dumps({'phase': phase, 'comment_url': posted['html_url'], 'cases': len(response['cases']),
                              'owner_id': identity['id'], 'collection_seconds': end - start}), flush=True)
            break
        else:
            raise ValueError('owner helper overall wait expired')
    print('Both sandbox response bundles posted; consult Ubuntu run results for acceptance.', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('challenge', 'wait'):
        sub = commands.add_parser(name)
        sub.add_argument('phase', choices=('preflight', 'final'))
    owner = commands.add_parser('attend')
    owner.add_argument('--run-id', type=int, required=True)
    owner.add_argument('--expected-sha', required=True)
    owner.add_argument('--key', required=True)
    owner.add_argument('--approve-public-evidence', action='store_true')
    args = parser.parse_args()
    if args.command == 'attend': attend(args)
    elif args.command == 'challenge': challenge_command(args.phase)
    else: wait_command(args.phase)
