"""Reviewed transactions for the existing privileged network-policy service."""
import copy
import hashlib
import json
import secrets
import threading
import time

from greyward_security_context.network_rules import MAX_RULES, PolicyError, lifecycle, normalize


class RuleManager:
    def __init__(self, store, firewall=None, resolve_executable=None):
        self.store, self.firewall = store, firewall
        self.resolve_executable = resolve_executable
        self.pending = {}
        self.undo = {}
        self.lock = threading.RLock()

    def recover(self):
        """Restore only the exact native entries journaled by this service."""
        with self.store.locked() as policy:
            pending = policy.get('firewall_pending')
            if pending:
                if self.firewall is None:
                    raise PolicyError('Incoming recovery is pending while firewalld is unavailable.')
                self.firewall.restore(pending['native_before'])
                restored = copy.deepcopy(policy)
                restored.pop('firewall_pending')
                return self.store.write(restored, policy['revision'])
        return policy

    def listing(self, actor_uid, query):
        policy = self.store.read()
        if policy.get('firewall_pending'):
            raise PolicyError('An interrupted incoming-access change requires recovery before editing.')
        provider = query.get('provider', 'application')
        if provider not in ('application', 'incoming'):
            raise PolicyError('Unknown rule provider.')
        offset = query.get('offset', 0)
        if isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= MAX_RULES:
            raise PolicyError('Invalid page offset.')
        rules = [copy.deepcopy(r) for r in policy['rules'] if r.get('provider') == provider]
        health, catalog, observed, external = None, {}, {}, {'rules': [], 'truncated': False}
        if provider == 'incoming':
            try:
                if self.firewall is None:
                    raise PolicyError('firewalld is unavailable.')
                catalog = self.firewall.catalog()
                observed = self.firewall.observe(policy['rules'])
                if hasattr(self.firewall, 'external'):
                    external = self.firewall.external(policy['rules'])
            except Exception:
                health = 'firewalld state is unavailable. Rules have not been assumed active.'
        search = str(query.get('search', '')).casefold()[:160]
        for position, rule in enumerate(rules):
            rule['position'] = position
            rule['state'] = observed.get(rule['id'], lifecycle(rule))
            if health:
                rule['state'] = 'UNAVAILABLE'
            rule['owner'] = 'GREYWARD'
        if search:
            rules = [r for r in rules if search in json.dumps(r, sort_keys=True).casefold()]
        if query.get('state') == 'ACTIVE':
            rules = [r for r in rules if r['state'] in ('SAVED', 'LOADED', 'OBSERVED')]
        if query.get('state') in ('SAVED', 'LOADED', 'DISABLED', 'EXPIRED', 'UNAVAILABLE'):
            rules = [r for r in rules if r['state'] == query['state']]
        return {'ok': True, 'schema': 'greyward.network.rules/v2', 'revision': policy['revision'],
                'rules': rules[offset:offset + 100], 'total': len(rules), 'offset': offset,
                'next_offset': offset + 100 if offset + 100 < len(rules) else None,
                'actor_uid': actor_uid, 'provider': provider, 'catalog': catalog, 'external': external,
                'detail': health or self.store.error or self.store.backup_error,
                'capabilities': {'edit': not bool(health), 'flatpak_identity': False,
                                 'script_identity': False, 'interactive_prompts': False,
                                 'max_rules': MAX_RULES},
                'default_action': policy.get('default_action', 'allow')}

    def prepare(self, actor_uid, request):
        if not isinstance(request, dict) or request.get('provider') not in ('application', 'incoming'):
            raise PolicyError('Choose an application or incoming-access transaction.')
        policy = self.store.read()
        if policy.get('firewall_pending'):
            raise PolicyError('Incoming-access recovery must finish before editing rules.')
        if isinstance(request.get('revision'), bool) or not isinstance(request.get('revision'), int) or request['revision'] != policy['revision']:
            raise PolicyError('Policy changed. Reload and review your edits.')
        restore = None
        if request.get('undo'):
            with self.lock:
                restore = self.undo.get(request['undo'])
                if not restore or restore['actor_uid'] != actor_uid or restore['provider'] != request['provider'] or restore['revision'] != policy['revision'] or restore['deadline'] <= time.monotonic():
                    raise PolicyError('Undo expired or the policy changed. No changes were restored.')
            commands = [{'operation': '_restore'}]
        else:
            commands = request.get('commands')
        if not isinstance(commands, list) or not 1 <= len(commands) <= MAX_RULES:
            raise PolicyError('A bounded non-empty change list is required.')
        candidate = copy.deepcopy(policy)
        warnings, changes = [], []
        provider = request['provider']
        if provider == 'incoming' and self.firewall is None:
            raise PolicyError('firewalld is unavailable.')
        for command in commands:
            if not isinstance(command, dict):
                raise PolicyError('Invalid rule operation.')
            identifier = command.get('id')
            existing = next((r for r in candidate['rules'] if r.get('id') == identifier), None) if identifier else None
            reserved_delete = existing and existing.get('tier') == 'THREAT_EXCEPTION' and command.get('operation') == 'delete' and provider == 'application'
            if existing and not reserved_delete and (existing.get('provider') != provider or existing.get('tier')):
                raise PolicyError('This rule belongs to another provider or a reserved protection.')
            operation = command.get('operation')
            if operation == '_restore':
                if restore is None:
                    raise PolicyError('A server-issued undo reference is required.')
                candidate = copy.deepcopy(restore['before'])
                candidate['revision'] = policy['revision']
                old_rows = {r.get('id'): r for r in policy['rules']}
                new_rows = {r.get('id'): r for r in candidate['rules']}
                changes.extend({'operation': 'restore', 'rule': r} for identifier, r in new_rows.items() if old_rows.get(identifier) != r)
                changes.extend({'operation': 'remove', 'rule': r} for identifier, r in old_rows.items() if identifier not in new_rows)
                if list(old_rows) != list(new_rows):
                    changes.insert(0, {'operation': 'restore order', 'rule': {'name': f'{provider} rule order and membership'}})
                if not changes:
                    changes.append({'operation': 'restore', 'rule': {'name': 'Threat protection settings'}})
                warnings.append('Undo restores the previous reviewed configuration. Expired rules are not renewed.')
                continue
            if operation == 'threat_settings':
                if provider != 'application' or not isinstance(command.get('enabled'), bool):
                    raise PolicyError('Invalid threat-protection setting.')
                candidate['threat_intel'] = {'enabled': command['enabled'], 'provider': 'feodo-recommended'}
                changes.append({'operation': 'enable' if command['enabled'] else 'disable', 'rule': {'name': 'Feodo threat blocking'}})
                warnings.append('This changes malware destination blocking for the whole system.')
                continue
            if operation == 'threat_exception':
                import ipaddress
                import uuid
                value = command.get('rule', {})
                if provider != 'application' or not isinstance(value, dict) or value.get('action') != 'allow':
                    raise PolicyError('A threat exception must explicitly allow one application/IP/port.')
                path = value.get('path', '')
                address = str(ipaddress.ip_address(value.get('ip', '')))
                port = value.get('port')
                if not isinstance(path, str) or not path.startswith('/') or path.startswith('/app/') or isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                    raise PolicyError('A threat exception requires a host executable and exact IP/port.')
                rule = {'id': 'greyward-' + uuid.uuid4().hex[:20], 'tier': 'THREAT_EXCEPTION',
                        'path': path, 'ip': address, 'port': port, 'uid': actor_uid, 'action': 'allow',
                        'duration': 'always', 'name': 'GREYWARD Feodo false-positive exception'}
                candidate['rules'].append(rule)
                changes.append({'operation': 'create exception', 'rule': rule})
                warnings.append('This exact application/IP/port is exempted from Feodo threat blocking.')
                continue
            if operation in ('upsert', 'dns_exception'):
                value = command.get('rule')
                if not isinstance(value, dict) or value.get('tier') or value.get('provider', provider) != provider:
                    raise PolicyError('Reserved or mismatched rules cannot be imported.')
                if identifier and not existing:
                    raise PolicyError('The edited rule no longer exists.')
                value = dict(value, provider=provider)
                if operation == 'upsert' and value.get('dns_exception') and not (existing or {}).get('dns_exception'):
                    raise PolicyError('Use the explicit managed-DNS exception review.')
                if operation == 'dns_exception':
                    if provider != 'application':
                        raise PolicyError('DNS exceptions apply to application rules only.')
                    value['dns_exception'] = True
                    warnings.append('This explicitly bypasses managed DNS for this executable on the selected DNS ports.')
                if existing:
                    value['id'] = identifier
                else:
                    value.pop('id', None)
                rule = normalize(value, actor_uid, existing=existing)
                if provider == 'application':
                    if self.resolve_executable and rule['path'] != '*':
                        rule['path'] = self.resolve_executable(rule['path'])
                    if rule['path'] != '*':
                        warnings.append('Executable-path scope follows replacement of that file and includes its helpers only when they use the same executable. It is not a code-generation grant.')
                    if rule['path'] == '*':
                        warnings.append('This IP rule affects all applications in its selected user scope. It shares outgoing order with application rules; earlier matching rules take precedence.')
                    if rule['scope'] == 'system':
                        warnings.append('This rule applies to all users, not just this account.')
                    if rule['action'] == 'allow':
                        warnings.append('An Allow rule does not block other destinations when the default is Allow.')
                    if any(d['kind'] in ('host', 'domain') for d in rule['destinations']):
                        warnings.append('Hostname matching uses observed hostnames; it does not inspect URLs or encrypted content.')
                    if rule['path'].rsplit('/', 1)[-1].startswith(('python', 'bash', 'sh', 'node', 'ruby', 'perl', 'java')):
                        warnings.append('This executable scope includes other scripts or code running in the same interpreter.')
                if existing:
                    candidate['rules'][candidate['rules'].index(existing)] = rule
                else:
                    candidate['rules'].append(rule)
                changes.append({'operation': 'update' if existing else 'create', 'rule': rule})
            elif operation in ('delete', 'enable', 'move'):
                if not existing:
                    raise PolicyError('The rule no longer exists.')
                if operation == 'delete':
                    candidate['rules'].remove(existing)
                elif operation == 'enable':
                    if not isinstance(command.get('enabled'), bool):
                        raise PolicyError('Enabled must be boolean.')
                    existing['enabled'] = command['enabled']
                else:
                    position = command.get('position')
                    siblings = [r for r in candidate['rules'] if r.get('provider') == provider]
                    if isinstance(position, bool) or not isinstance(position, int) or not 0 <= position < len(siblings):
                        raise PolicyError('Invalid rule position.')
                    candidate['rules'].remove(existing)
                    siblings.remove(existing)
                    target = candidate['rules'].index(siblings[position]) if position < len(siblings) else (candidate['rules'].index(siblings[-1]) + 1 if siblings else len(candidate['rules']))
                    candidate['rules'].insert(target, existing)
                changes.append({'operation': operation, 'rule': copy.deepcopy(existing)})
            else:
                raise PolicyError('Unsupported rule operation.')
        if len(candidate['rules']) > MAX_RULES:
            raise PolicyError('The policy limit is 1,024 rules. No existing rules were removed.')
        if provider == 'incoming':
            catalog = self.firewall.catalog()
            for rule in candidate['rules']:
                if rule.get('provider') == 'incoming' and (rule['zone'] not in catalog['zones'] or (rule['service'] and rule['service'] not in catalog['services'])):
                    raise PolicyError('Choose an installed firewall zone and service.')
            warnings.append('Incoming rules affect the whole system. Established connections may remain open.')
            warnings.append('Other firewalld policies can also affect reachability. This is a condition preview, not a connection test.')
        fingerprints = {}
        for rule in candidate['rules']:
            if rule.get('provider') != provider or not rule.get('enabled', True):
                continue
            fields = {k: v for k, v in rule.items() if k not in ('id', 'name', 'description', 'created_at', 'updated_at', 'enabled', 'action')}
            fingerprint = hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()
            if fingerprint in fingerprints:
                warnings.append(f'An earlier rule with the same conditions shadows "{rule["name"]}".')
            fingerprints[fingerprint] = rule['id']
        now = time.monotonic()
        with self.lock:
            self.pending = {k: v for k, v in self.pending.items() if v['deadline'] > now}
            if len(self.pending) >= 32:
                raise PolicyError('Too many pending reviews. Close an existing review and retry.')
            token = secrets.token_urlsafe(32)
            self.pending[token] = {'actor_uid': actor_uid, 'provider': provider, 'before': policy,
                                   'after': candidate, 'deadline': now + 180, 'cancelled': False,
                                   'changes': copy.deepcopy(changes),
                                   'native_before': self.firewall.capture(policy['rules'], candidate['rules']) if provider == 'incoming' else None}
        return {'ok': True, 'state': 'REVIEW', 'transaction': token, 'revision': policy['revision'],
                'changes': changes, 'warnings': list(dict.fromkeys(warnings)), 'expires_in': 180,
                'detail': 'Review these exact changes, then authenticate to apply. No policy has changed.'}

    def cancel(self, actor_uid, token):
        with self.lock:
            transaction = self.pending.get(token)
            if transaction and transaction['actor_uid'] == actor_uid:
                transaction['cancelled'] = True
                return {'ok': True, 'state': 'CANCELLED'}
        raise PolicyError('Review not found.')

    def apply(self, actor_uid, token, authorize):
        with self.lock:
            transaction = self.pending.get(token)
            if not transaction or transaction['actor_uid'] != actor_uid or transaction['cancelled'] or transaction['deadline'] <= time.monotonic():
                raise PolicyError('This review expired, was cancelled, or belongs to another caller.')
            if transaction.get('applying'):
                raise PolicyError('This review is already being applied.')
            transaction['applying'] = True
        try:
            authorize(token, transaction)
            with self.store.locked() as policy:
                if transaction['cancelled'] or transaction['deadline'] <= time.monotonic():
                    raise PolicyError('The review was cancelled or expired during authentication.')
                if policy['revision'] != transaction['before']['revision']:
                    raise PolicyError('Policy changed during review. Nothing was applied.')
                before, after = transaction['before'], transaction['after']
                native_before = None
                if transaction['provider'] == 'incoming':
                    native_before = self.firewall.capture(before['rules'], after['rules'])
                    if native_before != transaction['native_before']:
                        raise PolicyError('firewalld changed during review. Nothing was applied.')
                    journal = copy.deepcopy(policy)
                    journal['firewall_pending'] = {'native_before': native_before}
                    policy = self.store.write(journal, policy['revision'])
                try:
                    if native_before is not None:
                        self.firewall.replace(before['rules'], after['rules'])
                    saved = self.store.write(after, policy['revision'])
                except Exception as error:
                    if native_before is not None:
                        try:
                            self.firewall.restore(native_before)
                            self.store.write(before, policy['revision'])
                        except Exception as rollback_error:
                            raise PolicyError('Policy save failed and firewall rollback is INCOMPLETE.') from rollback_error
                    raise error
            undo_token = secrets.token_urlsafe(32)
            with self.lock:
                self.undo = {k: v for k, v in self.undo.items() if v['deadline'] > time.monotonic()}
                if len(self.undo) >= 32:
                    self.undo.pop(next(iter(self.undo)))
                self.undo[undo_token] = {'actor_uid': actor_uid, 'provider': transaction['provider'],
                                         'before': transaction['before'], 'revision': saved['revision'],
                                         'deadline': time.monotonic() + 180}
            return {'ok': True, 'state': 'SAVED', 'revision': saved['revision'], 'undo': undo_token,
                    'detail': 'Policy saved. Application changes affect future decisions; this is not proof that a connection matched.'}
        finally:
            with self.lock:
                self.pending.pop(token, None)
