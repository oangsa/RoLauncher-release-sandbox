"""Sandbox lifecycle instrumentation; existing publisher remains the authority."""
import base64
import hashlib
import json
from pathlib import Path
import re
import time
from urllib.parse import urlparse, parse_qs

import release_promotion as promotion
import owner_evidence as evidence


def canonical_payload(response):
    evidence.require(isinstance(response, dict) and isinstance(response.get('payload_base64'), str)
        and len(response['payload_base64']) <= 44 * 1024, 'Malformed canonical evidence')
    raw = base64.b64decode(response['payload_base64'], validate=True)
    value = evidence.parse(raw, 32 * 1024)
    evidence.require(evidence.canonical(value) == raw and base64.b64encode(raw).decode() == response['payload_base64'],
                     'Noncanonical evidence encoding')
    return value


def verify_canonical(response, challenge, consumed, policy_path=evidence.POLICY, now=None):
    canonical_payload(response)
    return evidence.verify(response, challenge, consumed, policy_path, now)


class PhaseDEvidence(evidence.StagedEvidence):
    """Add strict wire canonicalization without changing pinned Architecture C code."""
    def gate(self, phase, call, binding):
        path = self.state / phase / 'challenge.json'
        challenge = evidence.parse(path.read_bytes()) if path.exists() else None
        def canonical_call(endpoint, *args, **kwargs):
            value = call(endpoint, *args, **kwargs)
            if challenge and endpoint.startswith('/issues/'):
                for comment in value if isinstance(value, list) else [value]:
                    if not isinstance(comment, dict) or comment.get('user', {}).get('id') != evidence.OWNER:
                        continue
                    try:
                        wrapper = evidence.parse(comment['body'].encode())
                    except (ValueError, KeyError, AttributeError):
                        continue
                    if isinstance(wrapper, dict) and wrapper.get('challenge_sha256') == evidence.digest(challenge):
                        evidence.require(evidence.canonical(wrapper).decode()==comment['body'],'Noncanonical evidence wrapper')
                        canonical_payload(wrapper.get('response'))
            return value
        return super().gate(phase, canonical_call, binding)


def validated_fault(value):
    promotion.require(value is None or isinstance(value,dict),'Fault must be an object')
    fault=dict(value or {})
    if fault:
        promotion.require(set(fault) <= {'mutation','when','seconds'}
            and type(fault.get('mutation')) is int and fault['mutation']>0
            and fault.get('when') in ('before','after','delay-before','delay-after')
            and type(fault.get('seconds',0)) in (int,float)
            and 0<=fault.get('seconds',0)<=130,'Invalid bounded fault')
    return fault


class AuditedTransport:
    """Bounded append-only attempt ledger; one forward, never an automatic retry.

    Wrap the existing sandbox transport, not a general HTTP client. A live caller
    must separately authorize mutation and supply the evidence freshness guard.
    Successful backend return means response received, not immutable readback proof.
    """
    def __init__(self, call, ledger, fault=None, fresh=None, clock=time.time_ns,
                 sleep=time.sleep, max_events=2000, approved_probe_name=None):
        self.call, self.fresh = call, fresh
        self.ledger, self.fault = Path(ledger), validated_fault(fault)
        self.clock, self.sleep, self.max_events = clock, sleep, max_events
        self.mutations, self.events, self.seen = 0, 0, set()
        self.inflight=0
        self.http_status = None
        promotion.require(approved_probe_name in (None,'PHASE-D-DENIED.txt'),'Unknown probe upload name')
        self.approved_probe_name=approved_probe_name
        self.ledger.parent.mkdir(parents=True, exist_ok=True)
        # One ledger per run/attempt/stage. Never overwrite a prior audit.
        self.stream = self.ledger.open('x', encoding='utf-8')

    def close(self):
        self.stream.close()

    def observe_status(self, status):
        promotion.require(status is None or type(status) is int and 100 <= status <= 599,
                          'Invalid HTTP observation')
        self.http_status = status

    def record(self, row):
        promotion.require(self.events < self.max_events, 'Mutation ledger limit')
        self.stream.write(json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n')
        self.stream.flush()
        self.events += 1

    def __call__(self, path, method='GET', body=None, **kwargs):
        promotion.require(method in ('GET', 'POST', 'PATCH', 'DELETE'), 'Audit method denied')
        mutation = method != 'GET'
        self.http_status=None
        if mutation:
            self.mutations += 1
        row = dict(method=method, mutation=self.mutations if mutation else None,
                   started_ns=self.clock(), route='denied-route')
        promotion.require(self.events + 2 + self.inflight <= self.max_events, 'Mutation ledger limit')
        self.inflight+=1
        try:
            url = path if path.startswith('https://') else 'https://api.github.com/repos/' + promotion.REPO + path
            promotion.checked_url(url)
            parsed = urlparse(url)
            # Never retain query values, signed URLs, headers, bodies or credentials.
            row['route'] = parsed.netloc + parsed.path
            if parsed.netloc == 'uploads.github.com':
                query = parse_qs(parsed.query, strict_parsing=True)
                promotion.require(set(query) == {'name'} and len(query['name']) == 1
                    and (query['name'][0]==self.approved_probe_name or re.fullmatch(r'rolauncher-v[0-9]+\.[0-9]+\.[0-9]+-(setup-x64\.exe|windows-x64\.zip|source\.zip|linux-x64\.tar\.gz|SHA256SUMS\.txt)|release-promotion\.json', query['name'][0])),
                    'Unapproved upload name')
                row['asset'] = query['name'][0]
            digest = hashlib.sha256((method + '\n' + url + '\n').encode())
            digest.update(kwargs.get('binary') or json.dumps(body, sort_keys=True).encode())
            identity = digest.hexdigest()
            row['duplicate_attempt'] = identity in self.seen
            self.seen.add(identity)
            self.record(dict(row, outcome='started'))
            fault = self.fault if mutation and self.mutations == self.fault.get('mutation') else {}
            when = fault.get('when')
            if when == 'before':
                raise TimeoutError('Injected interruption before server acceptance')
            if when == 'delay-before':
                self.sleep(fault.get('seconds', 0))
            if mutation and self.fresh:
                self.fresh()  # After any injected delay, immediately before forwarding.
            self.http_status = None
            result = self.call(path, method, body, **kwargs)
            if when == 'delay-after':
                self.sleep(fault.get('seconds', 0))
            if when == 'after':
                self.record(dict(row, ended_ns=self.clock(), outcome='response-lost-after-return',http_status=self.http_status))
                raise TimeoutError('Injected lost response after backend return')
            self.record(dict(row, ended_ns=self.clock(), outcome='returned', http_status=self.http_status))
            return result
        except BaseException as error:
            if not (isinstance(error, TimeoutError) and str(error) == 'Injected lost response after backend return'):
                self.record(dict(row, ended_ns=self.clock(), outcome=type(error).__name__,
                                 http_status=getattr(error, 'code', self.http_status)))
            raise
        finally:
            self.inflight-=1
