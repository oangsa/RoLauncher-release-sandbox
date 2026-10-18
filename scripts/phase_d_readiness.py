"""GET-only owner/runtime visibility probe. No signing and no mutation methods."""
import json
import os
from pathlib import Path

import owner_evidence as evidence
import release_promotion as promotion


def inspect(call,policy):
    metadata=evidence.collect(call,bypass=False)
    missing=[]
    for r in metadata['inventory']:
        raw=call('/rulesets/'+str(r['id']))
        if not isinstance(raw.get('bypass_actors'),list):missing.append(r['id'])
    result=dict(schema=1,repository_id=evidence.REPO_ID,owner_id=evidence.OWNER,
                inventory_count=len(metadata['inventory']),missing_bypass_arrays=missing,
                privileged_controls='BLOCKED',immutable_settings_visible=False)
    try:
        immutable=call('/immutable-releases')
        result['immutable_settings_visible']=isinstance(immutable,dict) and type(immutable.get('enforced_by_owner')) is bool
        if missing:return result
        snapshot=evidence.collect(call,bypass=True)
        evidence.validate_disclosure(snapshot,policy)
        promotion.protected_branches(evidence.controls_call(call,snapshot),strict=True)
        result.update(privileged_controls='PASS',controls_sha256=evidence.digest(snapshot))
    except (ValueError,RuntimeError,KeyError,TypeError):
        # Only visibility status is emitted; never partial privileged evidence or raw errors.
        result['privileged_controls']='BLOCKED'
    return result


def main():
    evidence.require(os.environ.get('PHASE_D_READ_ONLY_AUTHORIZED')=='true','Separate read-only dispatch approval required')
    evidence.require(os.environ.get('GITHUB_REPOSITORY')==evidence.REPO
        and os.environ.get('GITHUB_REPOSITORY_ID')==str(evidence.REPO_ID)
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch'
        and os.environ.get('GITHUB_REF')=='refs/heads/main'
        and os.environ.get('GITHUB_WORKFLOW_REF')==evidence.REPO+'/.github/workflows/phase-d-readiness.yml@refs/heads/main',
        'Trusted sandbox readiness context required')
    backend=promotion.github_api(os.environ['GITHUB_TOKEN'])
    def call(path):return backend(path,'GET')
    repository=call('')
    evidence.require(repository['id']==evidence.REPO_ID and repository['owner']['id']==evidence.OWNER
        and repository['full_name']==evidence.REPO,'Readiness repository mismatch')
    evidence.require(call('/branches/main')['commit']['sha']==os.environ['GITHUB_SHA'],'Stale readiness revision')
    policy,_=evidence.load_policy()
    result=inspect(call,policy)
    result.update(trusted_sha=os.environ['GITHUB_SHA'],run_id=int(os.environ['GITHUB_RUN_ID']),
                  attempt=int(os.environ['GITHUB_RUN_ATTEMPT']),event='workflow_dispatch',
                  permission_context='publisher-equivalent declarations; separate read-only workflow')
    Path('phase-d-readiness.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    # Preserve diagnostics, but never turn missing privilege into a green job.
    if result['privileged_controls']!='PASS':
        print('::error::Readiness BLOCKED; operational verification did not pass.')
        raise SystemExit(1)
    return result


if __name__=='__main__':main()
