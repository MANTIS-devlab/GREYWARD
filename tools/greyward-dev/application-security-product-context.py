#!/usr/bin/python3
"""Focused product adapter proof against the actual root development provider."""
import os
from pathlib import Path
import sys
import json

if os.getuid() != 1002 or Path('/proc/self/attr/current').read_text().strip('\n\0') != 'greyward_guard_u:greyward_guard_r:greyward_guard_t:s0':
    raise SystemExit('Separate enrolled account required')
sys.path.insert(0, '/usr/local/lib/greyward-application-security-product-context')
import dbus
from greyward_security_context.application_workflows import ApplicationSecurityWorkflows

pid = os.getpid()
ticks = int(Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19])
actor = (1002, pid, ticks)
api = ApplicationSecurityWorkflows()

grants = api.grants()
assert grants['enforcement_health'] == 'UNKNOWN'
if sys.argv[1:] == ['--preview-grant']:
    assert not grants['grants']
    page = json.loads(str(api.transport.call('ListProtectedResources', 'ubts', (100, False, 0, ''))))
    resources = page['resources']
    assert len(resources) == 1
    # Actual root AVC/SYSCALL evidence enters the existing history, without
    # pretending the ordinary denied process has a trusted app identity.
    api.reconcile_access_events()
    assert api.event_source == 'AVAILABLE'
    assert any(item['resource_ref'] == resources[0]['resource_ref'] for item in api.recent_access_blocks())
    preview = api.preview(actor, 'PreviewPolicyChange', 'sast',
                         ('/usr/bin/cat', [resources[0]['resource_ref']], grants['policy_revision']))
    result = api.operation(actor, preview['preview']['review']['operation_ref'], 'CancelOperation')
    assert result['outcome'] == 'CANCELLED' and not result['verified_readback']
    print('CONTEXT_WORKFLOW_PASS')
    raise SystemExit(0)
assert not sys.argv[1:] and len(grants['grants']) == 1
grant = grants['grants'][0]
revision = grants['policy_revision']

for member, signature, arguments in [
    ('PreviewGrantRevocation', 'sst', (grant['grant_ref'], '', revision)),
]:
    preview = api.preview(actor, member, signature, arguments)
    body = preview['preview'].get('review', preview['preview'])
    result = api.operation(actor, body['operation_ref'], 'CancelOperation')
    assert result['outcome'] == 'CANCELLED' and not result['verified_readback']

from greyward_security_context.safe_open import launch, SafeOpenError
os.environ['XDG_CONFIG_HOME'] = '/home/greyward-guard-probe/appsec-safe-open/config'
os.environ['XDG_DATA_HOME'] = '/home/greyward-guard-probe/appsec-safe-open/data'
process, selected = launch('/home/greyward-guard-probe/ordinary.txt',
                           [Path('/home/greyward-guard-probe')], workflows=api, actor=actor)
assert selected == Path('/home/greyward-guard-probe/ordinary.txt')
assert process.wait(timeout=15) == 0
try:
    launch('/home/greyward-guard-probe/registration-critical/synthetic',
           [Path('/home/greyward-guard-probe')], workflows=api, actor=actor)
except SafeOpenError:
    pass
else:
    raise RuntimeError('Protected selection unexpectedly exported')
print('CONTEXT_WORKFLOW_PASS')
