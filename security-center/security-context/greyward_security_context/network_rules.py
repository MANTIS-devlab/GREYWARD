"""Canonical bounded network rule model, matching and revisioned policy storage.

The OpenSnitch control plane and the authenticated editor share this module.
It contains no UI, transport, command execution or provider authorization.
"""
import contextlib
import copy
import hashlib
import ipaddress
import json
import math
import os
import re
import tempfile
import threading
import time
import uuid
from pathlib import Path

MAX_RULES = 1024
MAX_BYTES = 1024 * 1024
SCHEMA = "greyward.network.rules/v2"
POLICY_PATH = Path('/etc/greyward/opensnitch-policy.json')
_LOCK = threading.RLock()


class PolicyError(ValueError):
    pass


def boot_id():
    try:
        return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    except OSError:
        return None


def text(value, maximum=160):
    if not isinstance(value, str) or len(value) > maximum or any(not c.isprintable() for c in value):
        raise PolicyError('Text contains unsupported characters or exceeds its limit.')
    return value.strip()


def rule_id(rule):
    return rule.get('id') or 'greyward-' + hashlib.sha256(
        json.dumps(rule, sort_keys=True).encode()).hexdigest()[:20]


def host_name(value):
    value = text(value, 253).rstrip('.').lower()
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError as error:
        raise PolicyError('Invalid hostname.') from error
    if not value or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in value.split('.')):
        raise PolicyError('Enter a hostname without a URL, wildcard or path.')
    return value


def port_ranges(value):
    if isinstance(value, str):
        value = [part.strip() for part in value.split(',') if part.strip()]
    if not isinstance(value, list) or len(value) > 32:
        raise PolicyError('Use at most 32 ports or ranges.')
    ranges = []
    for part in value:
        if isinstance(part, list) and len(part) == 2:
            parts = part
        else:
            parts = str(part).split('-')
        try:
            if len(parts) not in (1, 2) or any(isinstance(p, bool) for p in parts):
                raise ValueError()
            if any(not re.fullmatch(r'\d{1,5}', str(p).strip()) for p in parts):
                raise ValueError()
            start, end = int(parts[0]), int(parts[-1])
        except (ValueError, TypeError) as error:
            raise PolicyError('Ports must be numbers or ranges, such as 443, 8000-8010.') from error
        if not 1 <= start <= end <= 65535:
            raise PolicyError('Ports must be between 1 and 65535, in ascending order.')
        ranges.append([start, end])
    merged = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(end, merged[-1][1])
        else:
            merged.append([start, end])
    return merged


def normalize(value, actor_uid, *, existing=None, current_time=None, current_boot=None):
    if not isinstance(value, dict):
        raise PolicyError('A structured rule is required.')
    if isinstance(actor_uid, bool) or not isinstance(actor_uid, int) or not 0 <= actor_uid < 2 ** 32 - 1:
        raise PolicyError('Invalid user identity.')
    now = time.time() if current_time is None else current_time
    current_boot = boot_id() if current_boot is None else current_boot
    provider = value.get('provider', 'application')
    if provider not in ('application', 'incoming'):
        raise PolicyError('Unknown rule provider.')
    action = value.get('action', 'deny')
    if action not in ('allow', 'deny'):
        raise PolicyError('Choose Allow or Block.')
    family = value.get('family', 'any')
    if family not in ('any', 'ipv4', 'ipv6'):
        raise PolicyError('Unsupported address family.')
    protocols = value.get('protocols', ['tcp', 'udp'])
    if not isinstance(protocols, list) or not protocols or any(p not in ('tcp', 'udp', 'any') for p in protocols) or ('any' in protocols and len(protocols) != 1):
        raise PolicyError('Choose TCP, UDP or both.')
    lifetime = value.get('lifetime', 'permanent')
    if lifetime not in ('permanent', 'boot', '15m', '1h'):
        raise PolicyError('Unsupported rule lifetime.')
    if lifetime == 'boot' and not current_boot and not (existing or {}).get('boot_id'):
        raise PolicyError('The boot identity is unavailable.')
    enabled = value.get('enabled', True)
    if not isinstance(enabled, bool):
        raise PolicyError('Enabled must be boolean.')
    identifier = (existing or {}).get('id') or value.get('id') or 'greyward-' + uuid.uuid4().hex[:20]
    if not isinstance(identifier, str) or not re.fullmatch(r'greyward-[a-f0-9]{20}', identifier):
        raise PolicyError('Invalid rule identifier.')
    result = {
        'id': identifier, 'provider': provider, 'name': text(value.get('name') or 'Network rule'),
        'description': text(value.get('description', ''), 500), 'action': action,
        'enabled': enabled, 'family': family, 'protocols': sorted(set(protocols)),
        'ports': port_ranges(value.get('ports', [])), 'lifetime': lifetime,
        'created_at': (existing or {}).get('created_at', now), 'updated_at': now,
        'expires_at': None, 'boot_id': ((existing or {}).get('boot_id', current_boot)
                                     if lifetime == 'boot' and not value.get('renew', False)
                                     else current_boot if lifetime == 'boot' else None),
    }
    if lifetime in ('15m', '1h'):
        if existing and existing.get('lifetime') == lifetime and not value.get('renew', False):
            result['expires_at'] = existing.get('expires_at')
        else:
            result['expires_at'] = now + (900 if lifetime == '15m' else 3600)
    for stamp in ('created_at', 'updated_at', 'expires_at'):
        number = result[stamp]
        if number is None and stamp == 'expires_at' and lifetime not in ('15m', '1h'):
            continue
        if isinstance(number, bool) or not isinstance(number, (int, float)) or not math.isfinite(number) or number < 0:
            raise PolicyError('Invalid rule timestamp.')
    if provider == 'application':
        path = text(value.get('path', ''), 4096)
        if (not path.startswith('/') and not (path == '*' and value.get('all_applications') is True)) or '..' in Path(path).parts or path.startswith('/app/'):
            raise PolicyError('Use a host executable path; ambiguous Flatpak sandbox paths are unsupported.')
        scope = value.get('scope', 'user')
        if scope not in ('user', 'system'):
            raise PolicyError('Unsupported user scope.')
        result.update(path=path, uid=None if scope == 'system' else int(actor_uid), scope=scope, destinations=[])
        if path == '*':
            result['all_applications'] = True
        if value.get('required_host'):
            result['required_host'] = host_name(value['required_host'])
        destinations = value.get('destinations', [])
        if not isinstance(destinations, list) or len(destinations) > 32:
            raise PolicyError('Use at most 32 destinations.')
        for destination in destinations:
            if not isinstance(destination, dict):
                raise PolicyError('Invalid destination.')
            kind, address = destination.get('kind'), text(destination.get('value'), 253)
            try:
                if kind in ('host', 'domain'):
                    address = host_name(address)
                elif kind == 'ip':
                    address = str(ipaddress.ip_address(address))
                elif kind == 'network':
                    address = str(ipaddress.ip_network(address, strict=False))
                else:
                    raise PolicyError('Unsupported destination type.')
            except (ValueError, TypeError) as error:
                raise PolicyError('Invalid destination address.') from error
            item = {'kind': kind, 'value': address}
            if item not in result['destinations']:
                result['destinations'].append(item)
        if value.get('dns_exception'):
            if action != 'allow' or path == '*' or not result['ports'] or any(a != b or a not in (53, 853) for a, b in result['ports']):
                raise PolicyError('A DNS exception requires a specific executable and exact DNS ports.')
            result['dns_exception'] = True
    else:
        if 'any' in result['protocols']:
            raise PolicyError('Incoming custom ports require TCP or UDP.')
        zone = text(value.get('zone', ''), 80)
        service = text(value.get('service', ''), 80)
        if not re.fullmatch(r'[a-zA-Z0-9_-]+', zone):
            raise PolicyError('Choose an installed firewall zone.')
        if service and not re.fullmatch(r'[a-zA-Z0-9_-]+', service):
            raise PolicyError('Choose an installed firewall service.')
        if bool(service) == bool(result['ports']):
            raise PolicyError('Choose either a service or custom ports.')
        if service and result['protocols'] != ['tcp', 'udp']:
            raise PolicyError('Installed services use their own protocols; select custom ports to restrict TCP or UDP.')
        source = text(value.get('source', ''), 80)
        if source:
            try:
                source = str(ipaddress.ip_network(source, strict=False))
            except ValueError as error:
                raise PolicyError('Invalid source address or subnet.') from error
            source_family = 'ipv4' if ipaddress.ip_network(source).version == 4 else 'ipv6'
            if family not in ('any', source_family):
                raise PolicyError('The source and address family disagree.')
            result['family'] = source_family
        result.update(zone=zone, service=service, source=source, scope='system')
    return result


def lifecycle(rule, *, current_time=None, current_boot=None):
    if not rule.get('enabled', True):
        return 'DISABLED'
    current_time = time.time() if current_time is None else current_time
    if rule.get('review_required'):
        return 'REVIEW_REQUIRED'
    if rule.get('expires_at') is not None and current_time >= rule['expires_at']:
        return 'EXPIRED'
    if rule.get('lifetime') == 'boot' and rule.get('boot_id') != (current_boot or boot_id()):
        return 'EXPIRED'
    return 'SAVED'


def matches(rule, connection, *, current_time=None, current_boot=None):
    if rule.get('provider') != 'application' or lifecycle(rule, current_time=current_time, current_boot=current_boot) != 'SAVED':
        return False
    if rule['path'] not in ('*', getattr(connection, 'process_path', '')):
        return False
    if rule.get('uid') is not None and rule['uid'] != getattr(connection, 'user_id', None):
        return False
    protocol = str(getattr(connection, 'protocol', '')).lower().removesuffix('6')
    if 'any' not in rule['protocols'] and protocol not in rule['protocols']:
        return False
    try:
        address = ipaddress.ip_address(getattr(connection, 'dst_ip', ''))
    except ValueError:
        address = None
    if rule['family'] != 'any' and (address is None or rule['family'] != ('ipv4' if address.version == 4 else 'ipv6')):
        return False
    if rule['ports'] and not any(a <= int(getattr(connection, 'dst_port', 0)) <= b for a, b in rule['ports']):
        return False
    host = str(getattr(connection, 'dst_host', '')).rstrip('.').lower()
    if rule.get('required_host') and host != rule['required_host']:
        return False
    if not rule['destinations']:
        return True
    for destination in rule['destinations']:
        kind, value = destination['kind'], destination['value']
        if kind == 'host' and host == value:
            return True
        if kind == 'domain' and (host == value or host.endswith('.' + value)):
            return True
        if kind == 'ip' and address is not None and address == ipaddress.ip_address(value):
            return True
        if kind == 'network' and address is not None and address in ipaddress.ip_network(value):
            return True
    return False


def migrate(policy):
    if not isinstance(policy, dict) or not isinstance(policy.get('rules', []), list) or any(not isinstance(r, dict) for r in policy.get('rules', [])):
        raise PolicyError('Invalid network policy.')
    result = copy.deepcopy(policy)
    result.setdefault('default_action', 'allow')
    result.setdefault('default_duration', 'once')
    result.setdefault('interactive_prompts', False)
    result.setdefault('dns_policy', {'enforce': True, 'ports': [53, 853]})
    result.setdefault('threat_intel', {'enabled': True, 'provider': 'feodo-recommended'})
    if result.get('default_action', 'allow') not in ('allow', 'deny', 'reject'):
        raise PolicyError('Invalid default action.')
    if result.get('dns_policy', {'enforce': True, 'ports': [53, 853]}) != {'enforce': True, 'ports': [53, 853]}:
        raise PolicyError('Managed DNS policy is invalid.')
    if result.get('schema') == SCHEMA:
        if isinstance(result.get('revision'), bool) or not isinstance(result.get('revision'), int) or result['revision'] < 0:
            raise PolicyError('Invalid policy revision.')
        identifiers = []
        for item in result['rules']:
            if item.get('tier') == 'THREAT_EXCEPTION':
                if item.get('action') != 'allow' or not item.get('path', '').startswith('/') or not 1 <= int(item.get('port', 0)) <= 65535:
                    raise PolicyError('Invalid threat exception.')
                ipaddress.ip_address(item.get('ip'))
                identifiers.append(rule_id(item))
                continue
            normalized = normalize(item, item.get('uid') or 0, existing=item, current_time=item.get('updated_at', time.time()))
            if normalized != item:
                raise PolicyError('Stored network rule is not canonical.')
            identifiers.append(item['id'])
        if len(set(identifiers)) != len(identifiers):
            raise PolicyError('Duplicate rule identifiers.')
    else:
        legacy = result.get('rules', [])
        legacy = sorted(legacy, key=lambda r: (r.get('path') != '*', bool(r.get('host') or r.get('ip') or r.get('port'))), reverse=True)
        rules = []
        for item in legacy:
            if item.get('tier') == 'THREAT_EXCEPTION':
                rules.append(dict(item, id=rule_id(item)))
                continue
            destinations = []
            for key, kind in (('host', 'host'), ('ip', 'ip')):
                if item.get(key):
                    destinations.append({'kind': kind, 'value': item[key]})
            if item.get('host') and item.get('ip'):
                destinations = [{'kind': 'ip', 'value': item['ip']}]
            migrated = normalize({'id': rule_id(item), 'path': item.get('path'), 'name': item.get('name') or 'Migrated network rule',
                                  'action': 'allow' if item.get('action') == 'allow' else 'deny', 'scope': 'system',
                                  'all_applications': item.get('path') == '*',
                                  'protocols': ['any'],
                                  'dns_exception': item.get('action') == 'allow' and item.get('port') in (53, 853),
                                  'required_host': item.get('host') if item.get('ip') else None,
                                  'ports': [item['port']] if item.get('port') else [], 'destinations': destinations}, 0)
            if item.get('duration', 'always') != 'always':
                migrated['enabled'] = migrated['action'] != 'allow'
                migrated['description'] = 'Legacy temporary scope: choose a new lifetime before enabling.'
            rules.append(migrated)
        result.update(schema=SCHEMA, revision=0, rules=rules)
    if len(result['rules']) > MAX_RULES:
        raise PolicyError('The policy limit is 1,024 rules; no existing rule was removed.')
    return result


class PolicyStore:
    def __init__(self, path):
        self.path = Path(path)
        self.last_good = None
        self.error = None
        self.signature = None
        self.backup_error = None

    def read(self, copy_result=True):
        try:
            info = self.path.stat()
            signature = (info.st_mtime_ns, info.st_size)
            if self.last_good is not None and self.signature == signature and self.error is None:
                return copy.deepcopy(self.last_good) if copy_result else self.last_good
            data = self.path.read_bytes()
            if len(data) > MAX_BYTES:
                raise PolicyError('Network policy exceeds its size limit.')
            policy = migrate(json.loads(data))
            self.last_good, self.error = copy.deepcopy(policy), None
            self.signature = signature
            return policy
        except (OSError, ValueError, TypeError, KeyError) as error:
            self.error = str(error)
            if self.last_good is not None:
                return copy.deepcopy(self.last_good) if copy_result else self.last_good
            backup = self.path.with_suffix('.last-good.json')
            try:
                data = backup.read_bytes()
                if len(data) > MAX_BYTES:
                    raise PolicyError('Backup exceeds its size limit.')
                self.last_good = migrate(json.loads(data))
                return copy.deepcopy(self.last_good)
            except (OSError, ValueError, TypeError, KeyError) as backup_error:
                raise PolicyError('Network policy unavailable; no validated last-known-good policy.') from backup_error

    @contextlib.contextmanager
    def locked(self):
        with _LOCK:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path) + '.lock', os.O_CREAT | os.O_RDWR, 0o600)
            try:
                if os.name == 'posix':
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_EX)
                yield self.read()
            finally:
                os.close(fd)

    def write(self, policy, expected_revision):
        previous = self.read()
        if previous['revision'] != expected_revision:
            raise PolicyError('Policy changed. Review the current rules before applying again.')
        candidate = migrate(policy)
        candidate['revision'] = expected_revision + 1
        data = (json.dumps(candidate, sort_keys=True, separators=(',', ':')) + '\n').encode()
        if len(data) > MAX_BYTES:
            raise PolicyError('Policy exceeds its size limit; no rules were changed.')
        previous_data = (json.dumps(previous, sort_keys=True, separators=(',', ':')) + '\n').encode()
        backup = self.path.with_suffix('.last-good.json')
        backup_refreshed = False
        for index, (target, content) in enumerate(((backup, previous_data), (self.path, data), (backup, data))):
            temporary = None
            try:
                fd, temporary = tempfile.mkstemp(prefix='.network-', dir=target.parent)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, target)
                if index == 2:
                    backup_refreshed = True
            except OSError:
                if index != 2:
                    raise
                # The authoritative file has already committed. Do not report
                # it as an unapplied transaction or roll providers back against
                # a now-current policy; report redundancy degradation instead.
                self.backup_error = 'Policy saved, but its recovery copy could not be refreshed.'
                break
            finally:
                if temporary:
                    with contextlib.suppress(OSError):
                        os.unlink(temporary)
        self.last_good = copy.deepcopy(candidate)
        if backup_refreshed:
            self.backup_error = None
        return candidate
