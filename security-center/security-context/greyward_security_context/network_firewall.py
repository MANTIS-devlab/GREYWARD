"""Typed firewalld adapter. No frontend-supplied rich-language strings."""
import math
import time

from greyward_security_context.network_rules import PolicyError, lifecycle


def rich_rules(rule, position=0):
    """Compile a canonical incoming rule; alternatives become native rules."""
    families = [rule['family']] if rule['family'] != 'any' else ['ipv4', 'ipv6']
    entries = []
    for family in families:
        prefix = f'rule family="{family}" priority="{-20000 + position}"'
        if rule['source']:
            prefix += f' source address="{rule["source"]}"'
        elements = [f'service name="{rule["service"]}"'] if rule['service'] else [
            f'port port="{start if start == end else str(start) + "-" + str(end)}" protocol="{protocol}"'
            for start, end in rule['ports'] for protocol in rule['protocols']]
        entries.extend(prefix + ' ' + element + (' accept' if rule['action'] == 'allow' else ' drop') for element in elements)
    # Compare the provider's canonical representation, not attribute order.
    # Fedora firewalld returns priority before family and normalizes quoting.
    try:
        from firewall.core.rich import Rich_Rule
    except ImportError:
        return entries  # Pure model tests may run outside Fedora.
    return [str(Rich_Rule(rule_str=entry)) for entry in entries]


class Firewall:
    @staticmethod
    def _object(bus, path):
        """Keep a lazy proxy that survives firewalld startup and restarts.

        The systemd unit that owns this service is not ordered after
        firewalld.  Looking up the owner at process startup can therefore
        permanently disable incoming rules when firewalld acquires its D-Bus
        name a moment later.  Avoid eager introspection and follow name-owner
        changes so the next request can reconnect to the live daemon.
        """
        return bus.get_object('org.fedoraproject.FirewallD1', path,
                             introspect=False, follow_name_owner_changes=True)

    def __init__(self, bus):
        import dbus
        obj = self._object(bus, '/org/fedoraproject/FirewallD1')
        self.runtime = dbus.Interface(obj, 'org.fedoraproject.FirewallD1.zone')
        self.config = dbus.Interface(self._object(bus, '/org/fedoraproject/FirewallD1/config'),
                                     'org.fedoraproject.FirewallD1.config')
        self.bus = bus
        self.definitions = dbus.Interface(obj, 'org.fedoraproject.FirewallD1')
        self._definition_cache = None

    def permanent(self, zone):
        import dbus
        path = self.config.getZoneByName(zone, timeout=5)
        return dbus.Interface(self._object(self.bus, path),
                              'org.fedoraproject.FirewallD1.config.zone')

    def catalog(self):
        names = sorted(str(s) for s in self.config.getServiceNames(timeout=5))
        if len(names) > 1024:
            raise PolicyError('The installed service catalog exceeds its bounded capacity.')
        cached = getattr(self, '_definition_cache', None)
        if not cached or cached[0] < time.monotonic() or cached[1] != names:
            deadline, details = time.monotonic() + 2, []
            for name in names:
                if time.monotonic() >= deadline:
                    break
                try:
                    definition = self.definitions.getServiceSettings2(name, timeout=.35)
                    ports = [[str(p), str(protocol)] for p, protocol in definition.get('ports', [])[:64]]
                    complex_scope = any(definition.get(k) for k in ('protocols', 'source_ports', 'destinations', 'includes', 'helpers', 'modules'))
                    truncated = len(definition.get('ports', [])) > 64
                    details.append({'id': name, 'label': str(definition.get('short') or name)[:120],
                                    'description': str(definition.get('description', ''))[:280], 'ports': ports,
                                    'simple': bool(ports) and not complex_scope and not truncated,
                                    'additional_conditions': bool(complex_scope or truncated)})
                except Exception:
                    # A missing definition never becomes an invented port mapping.
                    continue
            self._definition_cache = (time.monotonic() + 30, names, details)
        else:
            details = cached[2]
        return {'zones': sorted(str(z) for z in self.runtime.getZones(timeout=5)),
                'services': names, 'service_details': details,
                'definitions_incomplete': len(details) != len(names),
                'definitions_source': 'firewalld-runtime'}

    def external(self, rules):
        """Read existing active-zone exposure without adopting provider policy."""
        own = {(zone, native, plane) for zone, native, plane, _ in self.entries(rules)}
        records = {}
        zones = sorted(str(z) for z in self.runtime.getActiveZones(timeout=5))[:16]
        for zone in zones:
            for plane in ('runtime', 'permanent'):
                provider = self.runtime if plane == 'runtime' else self.permanent(zone)
                args = (zone,) if plane == 'runtime' else ()
                values = [('service', str(v)) for v in provider.getServices(*args, timeout=5)]
                values += [('port', f'{v[0]}/{v[1]}') for v in provider.getPorts(*args, timeout=5)]
                values += [('rich', str(v)) for v in provider.getRichRules(*args, timeout=5)
                           if (zone, str(v), plane) not in own]
                for kind, value in values[:256]:
                    key = (zone, kind, value)
                    if key not in records:
                        records[key] = {'owner': 'firewalld', 'zone': zone, 'kind': kind,
                                        'value': value[:1000], 'mutable': False,
                                        'runtime': False, 'permanent': False}
                    records[key][plane] = True
        return {'rules': list(records.values())[:128], 'truncated': len(records) > 128}

    def observe(self, rules):
        result = {}
        snapshots = {}
        for index, rule in enumerate(r for r in rules if r.get('provider') == 'incoming'):
            state = lifecycle(rule)
            if state == 'SAVED':
                expected = set(rich_rules(rule, index))
                if rule['zone'] not in snapshots:
                    snapshots[rule['zone']] = (
                        set(str(r) for r in self.runtime.getRichRules(rule['zone'], timeout=5)),
                        set(str(r) for r in self.permanent(rule['zone']).getRichRules(timeout=5)))
                runtime, permanent = snapshots[rule['zone']]
                state = 'LOADED' if expected <= runtime and (rule['lifetime'] != 'permanent' or expected <= permanent) else 'SAVED'
            result[rule['id']] = state
        return result

    @staticmethod
    def entries(rules):
        found = set()
        for index, rule in enumerate(r for r in rules if r.get('provider') == 'incoming'):
            if lifecycle(rule) == 'SAVED':
                for native in rich_rules(rule, index):
                    found.add((rule['zone'], native, 'runtime', rule.get('expires_at')))
                    if rule['lifetime'] == 'permanent':
                        found.add((rule['zone'], native, 'permanent', None))
        return found

    def capture(self, before, after):
        old, new = self.entries(before), self.entries(after)
        changed = old.symmetric_difference(new)
        if len(changed) > 128:
            raise PolicyError('Apply incoming changes in smaller batches (at most 128 native changes).')
        snapshots, records, seen = {}, [], set()
        old_expiry = {(z, n, p): e for z, n, p, e in old}
        for zone, native, plane, expires in sorted(changed, key=lambda e: e[:3]):
            if (zone, native, plane) in seen:
                continue
            seen.add((zone, native, plane))
            key = (zone, plane)
            if key not in snapshots:
                provider = self.runtime if plane == 'runtime' else self.permanent(zone)
                snapshots[key] = set(str(r) for r in (provider.getRichRules(zone, timeout=5) if plane == 'runtime' else provider.getRichRules(timeout=5)))
            records.append({'zone': zone, 'rule': native, 'plane': plane,
                            'present': native in snapshots[key], 'expires_at': old_expiry.get((zone, native, plane))})
        return records

    def restore(self, records):
        errors = []
        for record in reversed(records):
            try:
                zone, native, plane = record['zone'], record['rule'], record['plane']
                provider = self.runtime if plane == 'runtime' else self.permanent(zone)
                actual = set(str(r) for r in (provider.getRichRules(zone, timeout=5) if plane == 'runtime' else provider.getRichRules(timeout=5)))
                present = record['present'] and (not record['expires_at'] or record['expires_at'] > time.time())
                if (native in actual) != present:
                    seconds = max(1, math.ceil(record['expires_at'] - time.time())) if record['expires_at'] else 0
                    self._change(provider, zone, native, plane, not present, seconds)
                actual = set(str(r) for r in (provider.getRichRules(zone, timeout=5) if plane == 'runtime' else provider.getRichRules(timeout=5)))
                if (native in actual) != present:
                    raise PolicyError('firewalld did not confirm rollback.')
            except Exception as error:
                errors.append(str(error))
        if errors:
            raise PolicyError('Incoming-access rollback is INCOMPLETE; its recovery journal is retained.')

    def replace(self, before, after):
        """Change only exact owned entries; reverse completed steps on failure."""
        catalog = self.catalog()
        for rule in after:
            if rule.get('provider') == 'incoming':
                if rule['zone'] not in catalog['zones'] or (rule['service'] and rule['service'] not in catalog['services']):
                    raise PolicyError('The selected zone or service is no longer installed.')
        old, new = self.entries(before), self.entries(after)
        if len(old.symmetric_difference(new)) > 128:
            raise PolicyError('Apply incoming changes in smaller batches.')
        completed = []
        try:
            for remove, changes in ((True, old - new), (False, new - old)):
                for zone, native, plane, expires in sorted(changes, key=lambda e: e[:3]):
                    provider = self.runtime if plane == 'runtime' else self.permanent(zone)
                    actual = set(str(r) for r in (provider.getRichRules(zone, timeout=5) if plane == 'runtime' else provider.getRichRules(timeout=5)))
                    if remove and native not in actual:
                        continue
                    if not remove and native in actual:
                        raise PolicyError('An identical external firewall rule already exists; it was not adopted or changed.')
                    seconds = max(1, math.ceil(expires - time.time())) if expires else 0
                    self._change(provider, zone, native, plane, remove, seconds)
                    completed.append((provider, zone, native, plane, not remove, seconds))
                    actual = set(str(r) for r in (provider.getRichRules(zone, timeout=5) if plane == 'runtime' else provider.getRichRules(timeout=5)))
                    if (native in actual) == remove:
                        raise PolicyError('firewalld did not confirm the requested rule change.')
        except Exception as error:
            rollback_errors = []
            for provider, zone, native, plane, remove, seconds in reversed(completed):
                try:
                    self._change(provider, zone, native, plane, remove, seconds)
                except Exception as rollback_error:
                    rollback_errors.append(str(rollback_error))
            if rollback_errors:
                raise PolicyError('Firewall apply failed; rollback is INCOMPLETE. Review incoming access.') from error
            raise
        return completed

    @staticmethod
    def _change(provider, zone, native, plane, remove, seconds):
        method = provider.removeRichRule if remove else provider.addRichRule
        if plane == 'runtime':
            method(zone, native, timeout=5) if remove else method(zone, native, seconds, timeout=5)
        else:
            method(native, timeout=5)
