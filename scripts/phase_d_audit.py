"""Independent GET-only publication audit and nonexecuting cleanup/probe plans."""
import hashlib
import json
import re
from urllib.parse import quote

import owner_evidence as evidence
import release_promotion as promotion


def verify_release(call,tag,source,receipt_bytes):
    evidence.require(isinstance(tag,str) and re.fullmatch(r'(beta-)?v'+promotion.STABLE_VERSION,tag)
        and re.fullmatch('[a-f0-9]{40}',source),'Audit tag/source identity')
    repository=call('')
    evidence.require(repository.get('full_name')==evidence.REPO
        and repository.get('id')==evidence.REPO_ID and repository['owner']['id']==evidence.OWNER,'Audit repository identity')
    receipt=evidence.parse(receipt_bytes,evidence.MAX_API)
    evidence.require(isinstance(receipt,dict) and set(receipt)=={'schema','intent','channel','version','source',
        'run','attempt','artifacts','files'} and type(receipt['schema']) is int and receipt['schema']==1,
        'Audit receipt schema')
    evidence.require((json.dumps(receipt,sort_keys=True,separators=(',',':'))+'\n').encode()==receipt_bytes,
                     'Noncanonical receipt')
    beta=tag.startswith('beta-')
    version=tag.removeprefix('beta-v').removeprefix('v')
    evidence.require(set(receipt['files'])=={'rolauncher-v'+version+s for s in
        ('-setup-x64.exe','-windows-x64.zip','-source.zip','-linux-x64.tar.gz','-SHA256SUMS.txt')},'Audit expected receipt files')
    evidence.require(receipt['source']==source and receipt['version']==version
        and receipt['channel']==('beta' if beta else 'stable'),'Audit receipt mismatch')
    release=call('/releases/tags/'+tag)
    marker='<!-- release-promotion:'+hashlib.sha256(receipt_bytes).hexdigest()+' -->'
    evidence.require(release['tag_name']==tag and release['target_commitish']==source
        and release['draft'] is False and release['prerelease'] is beta and marker in release.get('body',''),
        'Audit Release identity')
    evidence.require(promotion.promotion_state(call,tag,source,annotated=beta),'Audit tag missing')
    # Separate numeric-ID GET proves native Release state, independent of tag controls.
    current=call('/releases/'+str(release['id']))
    evidence.require(current['id']==release['id'] and current.get('immutable') is True
        and current['draft'] is False and current['tag_name']==tag
        and current['target_commitish']==source and current['prerelease'] is beta,'Audit immutable readback')
    expected=dict(receipt['files'],**{'release-promotion.json':hashlib.sha256(receipt_bytes).hexdigest()})
    assets=call('/releases/'+str(release['id'])+'/assets')
    evidence.require(len(assets)==len(expected) and {a['name'] for a in assets}==set(expected),'Audit asset inventory')
    verified=[]
    for asset in assets:
        evidence.require(type(asset['size']) is int and 0<=asset['size']<=promotion.MAX_ENTRY_BYTES,'Audit asset size limit')
        data=call('/releases/assets/'+str(asset['id']),raw=True)
        digest=hashlib.sha256(data).hexdigest()
        evidence.require(len(data)==asset['size'] and digest==expected[asset['name']]
            and asset.get('digest')=='sha256:'+digest,'Audit downloaded bytes differ')
        verified.append(dict(id=asset['id'],name=asset['name'],size=len(data),sha256=digest))
    evidence.require(call('/releases/'+str(release['id']))==current,'Audit Release changed during downloads')
    return dict(status='PASS',repository_id=evidence.REPO_ID,tag=tag,source=source,
                release_id=release['id'],immutable=True,assets=verified,
                receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest())


def denied_probe_plan(audit,target_sha):
    """Proposal only. Live denial requests need exact separate owner authorization."""
    evidence.require(audit['status']=='PASS' and audit['immutable'] is True
        and re.fullmatch('[a-f0-9]{40}',target_sha) and target_sha!=audit['source'],'Probe baseline required')
    tag=quote(audit['tag'],safe='')
    asset=audit['assets'][0]['id']
    return dict(status='NOT RUN',approval_required=True,release_id=audit['release_id'],tag=audit['tag'],
        operations=[dict(method='PATCH',path='/git/refs/tags/'+tag,body=dict(sha=target_sha,force=True)),
                    dict(method='DELETE',path='/git/refs/tags/'+tag),
                    dict(method='DELETE',path='/releases/assets/'+str(asset)),
                    dict(method='PATCH',path='/releases/assets/'+str(asset),body=dict(name='PHASE-D-DENIED.txt')),
                    dict(method='POST',path='https://uploads.github.com/repos/'+evidence.REPO+
                         '/releases/'+str(audit['release_id'])+'/assets?name=PHASE-D-DENIED.txt',
                         binary_sha256=hashlib.sha256(b'SANDBOX DENIED MUTATION PROBE\n').hexdigest())],
        acceptance='Actual GitHub denial AND unchanged independent before/after tag/assets; stop on any success',
        native_control='Repeat asset operations on separately approved immutable fixture outside version-tag Rulesets')


def cleanup_plan(audits):
    return dict(status='PROPOSAL ONLY',actions=[
        'Restore literal false && to any separately activated test workflow via reviewed protected PR',
        'Unset only separately approved Phase D activation variables',
        'Retain mutation ledgers, exact source/run/attempt identities and downloaded hashes',
        'Revoke temporary credentials only after separate owner approval',
        'Do not delete immutable tags/releases, change Rulesets/bypasses or alter production'],
        retained_immutable=[dict(release_id=a['release_id'],tag=a['tag'],source=a['source']) for a in audits],
        private_key='Never copied, automatically invoked, uploaded or enrolled as a secret')
