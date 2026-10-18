"""Separately approved immutable-resource probes; no automatic live entry point."""
import fnmatch
import hashlib
import re
from urllib.error import HTTPError

import owner_evidence as evidence
import release_promotion as promotion


def outside_tag_rulesets(tag,snapshot,policy):
    evidence.validate_disclosure(snapshot,policy)
    evidence.require(isinstance(snapshot,dict) and isinstance(snapshot.get('rulesets'),list),
                     'Complete Rulesets required for native-control proof')
    ref='refs/tags/'+tag
    for ruleset in snapshot['rulesets']:
        evidence.require(isinstance(ruleset.get('bypass_actors'),list),'Missing privileged bypass evidence')
        if ruleset['target']!='tag' or ruleset['enforcement']!='active':continue
        names=ruleset['conditions']['ref_name']
        matches=lambda patterns:any(p=='~ALL' or fnmatch.fnmatchcase(ref,p) for p in patterns)
        evidence.require('~DEFAULT_BRANCH' not in names['include'],'Ambiguous tag Ruleset condition')
        if matches(names['include']) and not matches(names['exclude']):return False
    return True


def native_control_proposal(source,snapshot,policy):
    tag='sandbox-native-immutable-0.0.900'
    evidence.require(re.fullmatch('[a-f0-9]{40}',source),'Exact native-control source required')
    evidence.require(outside_tag_rulesets(tag,snapshot,policy),'Native control overlaps active tag Ruleset')
    payload=b'SANDBOX NATIVE IMMUTABILITY CONTROL\n'
    return dict(status='PROPOSAL ONLY',approval_required=True,repository_id=evidence.REPO_ID,
        source=source,tag=tag,asset='PHASE-D-NATIVE-CONTROL.txt',payload_base64=evidence.base64.b64encode(payload).decode(),
        sha256=hashlib.sha256(payload).hexdigest(),outside_version_rulesets=True,
        scope='Separate permanent native-control fixture; not a publisher/source-contract validation result')


def verify_native_control(call,source,snapshot,policy):
    proposed=native_control_proposal(source,snapshot,policy)
    repository=call('')
    evidence.require(repository['id']==evidence.REPO_ID and repository['full_name']==evidence.REPO
        and repository['owner']['id']==evidence.OWNER,'Native-control repository mismatch')
    release=call('/releases/tags/'+proposed['tag'])
    current=call('/releases/'+str(release['id']))
    evidence.require(current==release and current['tag_name']==proposed['tag'] and current['target_commitish']==source
        and current['draft'] is False and current.get('immutable') is True,'Native-control immutable readback')
    evidence.require(promotion.promotion_state(call,proposed['tag'],source),'Native-control tag/source mismatch')
    assets=call('/releases/'+str(release['id'])+'/assets')
    evidence.require(len(assets)==1 and assets[0]['name']==proposed['asset'] and assets[0]['size']<1024,
                     'Native-control asset inventory')
    asset=assets[0]
    raw=call('/releases/assets/'+str(asset['id']),raw=True)
    digest=hashlib.sha256(raw).hexdigest()
    evidence.require(len(raw)==asset['size'] and digest==proposed['sha256']
        and asset['digest']=='sha256:'+digest,'Native-control downloaded bytes')
    evidence.require(call('/releases/'+str(release['id']))==current,'Native control changed during readback')
    return dict(status='PASS',immutable=True,release_id=release['id'],tag=proposed['tag'],source=source,
        assets=[dict(id=asset['id'],name=asset['name'],size=len(raw),sha256=digest)],outside_version_rulesets=True)


def run(call,plan,baseline,readback,approved_sha256=None):
    """No implicit authority. Exact generated plan digest must be owner-approved.

    The caller supplies the SAME audited sandbox credential for every request.
    HTTP failures alone are insufficient: independent readback must remain identical.
    Local rejection/no HTTP status is BLOCKED, never a native immutability PASS.
    """
    evidence.require(approved_sha256==evidence.digest(plan),'Separate exact denied-probe authorization required')
    evidence.require(baseline['status']=='PASS' and baseline['immutable'] is True
        and plan['release_id']==baseline['release_id'] and plan['tag']==baseline['tag'],
        'Denied-probe baseline mismatch')
    evidence.require(readback()==baseline,'Probe resource changed before start')
    outcomes=[]
    for operation in plan['operations']:
        kwargs={}
        if 'binary_sha256' in operation:
            kwargs['binary']=b'SANDBOX DENIED MUTATION PROBE\n'
            evidence.require(hashlib.sha256(kwargs['binary']).hexdigest()==operation['binary_sha256'],
                             'Approved probe payload differs')
        try:
            call(operation['path'],operation['method'],operation.get('body'),**kwargs)
        except (HTTPError,RuntimeError) as error:
            status=getattr(error,'code',getattr(call,'http_status',None))
            if status not in (403,422):
                return dict(status='BLOCKED',outcomes=outcomes,reason='No expected actual GitHub denial status')
            unchanged=readback()==baseline
            outcomes.append(dict(method=operation['method'],http_status=status,unchanged=unchanged))
            if not unchanged:return dict(status='FAIL',outcomes=outcomes,reason='Resource changed after denial; quarantine')
        else:
            return dict(status='FAIL',outcomes=outcomes,reason='Mutation unexpectedly accepted; stop and quarantine')
    return dict(status='PASS',outcomes=outcomes,evidence='HTTP outcomes and independent resource readback')
