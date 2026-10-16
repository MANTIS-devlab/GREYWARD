#!/usr/bin/python3
"""Existing root network boundary: typed, reviewed, freshly authenticated edits."""
import concurrent.futures
import datetime as dt
import grp
import json
import os
import pwd
import re
import stat
from pathlib import Path
import threading
import time

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

from greyward_security_context.network_rules import POLICY_PATH, MAX_BYTES, PolicyError, PolicyStore, rule_id
from greyward_security_context.network_rule_transactions import RuleManager
from greyward_security_context.network_firewall import Firewall

BUS_NAME = "systems.mantis.greyward.OpenSnitchPolicy1"
OBJECT_PATH = "/systems/mantis/greyward/OpenSnitchPolicy1"
ACTION = "org.greyward.NetworkRules1.manage"


def resolve_executable(path):
    resolved = Path(path).resolve(strict=True)
    info = resolved.stat()
    if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
        raise PolicyError('Choose an installed executable file.')
    return str(resolved)


def decode(payload):
    if not isinstance(payload, str) or len(payload.encode()) > MAX_BYTES or "\x00" in payload:
        raise PolicyError("Network request exceeds its size limit.")
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise PolicyError("A structured network request is required.")
    return value


def failure(error):
    return json.dumps({"ok": False, "state": "REFUSED", "detail": str(error)[:500]})


def legacy_remove_id(value):
    if not isinstance(value, str) or len(value) != 29 or not re.fullmatch(r'greyward-[a-f0-9]{20}', value):
        raise PolicyError('A bounded GREYWARD rule identifier is required.')
    return value


def engine_projection():
    with Path('/run/greyward-security-context/network-protection.json').open('rb') as stream:
        info = os.fstat(stream.fileno())
        raw = stream.read(8 * 1024 * 1024 + 1)
    if info.st_uid != 0 or info.st_mode & 0o022 or len(raw) > 8 * 1024 * 1024:
        raise PolicyError('The network engine projection is not trusted or exceeds its limit.')
    return json.loads(raw), info.st_mtime


class OpenSnitchPolicy(dbus.service.Object):
    def __init__(self, bus):
        super().__init__(bus, OBJECT_PATH)
        self.bus = bus
        firewall = Firewall(bus) if bus.name_has_owner('org.fedoraproject.FirewallD1') else None
        self.manager = RuleManager(PolicyStore(POLICY_PATH), firewall, resolve_executable)
        self.manager.recover()
        self.workers = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        self.slots = threading.BoundedSemaphore(2)
        self.authorizations = {}

    def peer(self, sender, admin=False):
        if not sender:
            raise PolicyError('Authenticated D-Bus sender is required.')
        uid = int(self.bus.get_unix_user(sender))
        if admin and uid != 0:
            user = pwd.getpwuid(uid)
            wheel = grp.getgrnam('wheel')
            if user.pw_gid != wheel.gr_gid and user.pw_name not in wheel.gr_mem:
                raise PolicyError('An administrator account is required.')
        return uid

    def engine_live_since(self):
        manager = dbus.Interface(self.bus.get_object('org.freedesktop.systemd1', '/org/freedesktop/systemd1'), 'org.freedesktop.systemd1.Manager')
        started = 0
        for name in ('greyward-opensnitch-control-plane.service', 'opensnitch.service'):
            path = manager.GetUnit(name, timeout=3)
            props = dbus.Interface(self.bus.get_object('org.freedesktop.systemd1', path), 'org.freedesktop.DBus.Properties')
            if str(props.Get('org.freedesktop.systemd1.Unit', 'ActiveState', timeout=3)) != 'active' or int(props.Get('org.freedesktop.systemd1.Service', 'MainPID', timeout=3)) <= 1:
                raise PolicyError('The application connection engine is unavailable.')
            if name == 'greyward-opensnitch-control-plane.service':
                started = int(props.Get('org.freedesktop.systemd1.Service', 'ExecMainStartTimestamp', timeout=3)) / 1_000_000
        if not started:
            raise PolicyError('The engine generation could not be verified.')
        return started

    def engine_ready(self):
        projection, modified = engine_projection()
        if projection.get('policy_error') or projection.get('rules_schema') != 'greyward.network.rules/v2' or projection.get('opensnitch', {}).get('state') not in ('OPERATING', 'DEGRADED'):
            raise PolicyError('The matching network engine is unavailable or has not confirmed the new rule contract. No rules were changed.')
        # OpenSnitch sends no Ping when it has no changed statistics. A stale
        # activity timestamp is not a dead decision provider. Bind the schema
        # acknowledgement to the current live service instance instead. Listing
        # still requires fresh evidence to claim Loaded/Observed.
        if modified < self.engine_live_since() or not projection.get('opensnitch', {}).get('last_seen'):
            raise PolicyError('The current engine generation has not acknowledged this rule contract.')
        return projection

    def authorize(self, sender, uid, token, transaction):
        if self.peer(sender, True) != uid:
            raise PolicyError('The originating caller changed.')
        # Root already owns the underlying policy and is the explicit technical
        # maintenance authority. Desktop callers never inherit this path.
        if uid == 0:
            return
        # A worker's synchronous connection must not attach disconnect watches
        # to the service's GLib main context or terminate its process on close.
        bus = dbus.SystemBus(private=True, mainloop=dbus.mainloop.NULL_MAIN_LOOP)
        bus.set_exit_on_disconnect(False)
        try:
            login = dbus.Interface(bus.get_object('org.freedesktop.login1', '/org/freedesktop/login1'), 'org.freedesktop.login1.Manager')
            user_path = login.GetUser(dbus.UInt32(uid), timeout=5)
            props = dbus.Interface(bus.get_object('org.freedesktop.login1', user_path), 'org.freedesktop.DBus.Properties')
            if str(props.Get('org.freedesktop.login1.User', 'State', timeout=5)) != 'active':
                raise PolicyError('An active local administrator session is required.')
            display = props.Get('org.freedesktop.login1.User', 'Display', timeout=5)
            if not display[0]:
                raise PolicyError('A local desktop session is required.')
            session = dbus.Interface(bus.get_object('org.freedesktop.login1', display[1]), 'org.freedesktop.DBus.Properties')
            facts = session.GetAll('org.freedesktop.login1.Session', timeout=5)
            if facts.get('Remote') or facts.get('LockedHint') or not facts.get('Active') or not facts.get('Seat', ['', ''])[0]:
                raise PolicyError('An active, unlocked local desktop session is required.')
            authority = dbus.Interface(bus.get_object('org.freedesktop.PolicyKit1', '/org/freedesktop/PolicyKit1/Authority'), 'org.freedesktop.PolicyKit1.Authority')
            self.authorizations[token] = authority
            changed = transaction['changes']
            summaries = []
            for change in changed[:8]:
                rule = change['rule']
                target = rule.get('path') or rule.get('service') or rule.get('name') or str(rule.get('ports', []))
                destinations = rule.get('destinations') or rule.get('source') or rule.get('ip') or 'any destination'
                scope = 'all users' if rule.get('uid') is None else f"user {rule['uid']}"
                summaries.append(f"{change['operation']} {rule.get('action', '')}: {target} — {destinations} — {rule.get('protocols', 'any protocol')} ports {rule.get('ports') or rule.get('port') or 'any'} — {scope} — {rule.get('lifetime', 'permanent')}")
            message = f"Apply {transaction['provider']} network policy changes?\n" + '\n'.join(summaries)
            if len(changed) > 8:
                message += f"\nAnd {len(changed) - 8} more reviewed changes."
            if not changed:
                message += '\nChange system-wide threat blocking.'
            details = {'polkit.message': message[:3500], 'greyward.transaction': token,
                       'greyward.policy_revision': str(transaction['before']['revision'])}
            subject = ('system-bus-name', {'name': dbus.String(sender, variant_level=1)})
            authorized, challenge, result_details = authority.CheckAuthorization(
                subject, ACTION, details, dbus.UInt32(1), token, timeout=100)
            if not authorized or challenge or result_details.get('polkit.temporary_authorization_id'):
                raise PolicyError('Fresh authentication was cancelled or refused.')
            if self.peer(sender, True) != uid:
                raise PolicyError('The originating caller exited or changed.')
            self.engine_ready()
        finally:
            self.authorizations.pop(token, None)
            bus.close()

    def dispatch(self, payload, sender, reply, error, legacy=None):
        if not self.slots.acquire(blocking=False):
            reply(failure('Another network review is being authenticated. Retry when it completes.'))
            return
        def work():
            try:
                uid = self.peer(sender, True)
                self.engine_ready()
                value = decode(str(payload)) if legacy != 'remove' else {'id': legacy_remove_id(payload)}
                if legacy:
                    revision = self.manager.store.read()['revision']
                    if legacy == 'remove':
                        commands = [{'operation': 'delete', 'id': value['id']}]
                    elif legacy == 'threat-setting':
                        commands = [{'operation': 'threat_settings', 'enabled': value['enabled']}]
                    elif legacy == 'threat-exception':
                        destination = value.get('destination') or {}
                        if value.get('action') != 'allow' or destination.get('host') or value.get('duration', 'always') != 'always':
                            raise PolicyError('A threat exception must allow an exact IP and port.')
                        commands = [{'operation': 'threat_exception', 'rule': {'path': value.get('application'), 'action': 'allow', 'ip': destination.get('ip'), 'port': destination.get('port')}}]
                    else:
                        destination = value.get('destination') or {}
                        if value.get('action') not in ('allow', 'deny', 'block', 'reject'):
                            raise PolicyError('Unsupported network action.')
                        duration = value.get('duration', 'always')
                        if duration == 'once':
                            raise PolicyError('Allow once requires a live pending request; use the rule editor for temporary rules.')
                        lifetime = 'boot' if duration in ('until_restart', 'until restart') else 'permanent'
                        if duration not in ('always', 'until_restart', 'until restart'):
                            raise PolicyError('Unsupported legacy duration.')
                        rule = {'path': value.get('application'), 'name': value.get('name') or 'Application connection rule',
                                'action': 'allow' if value.get('action') == 'allow' else 'deny', 'lifetime': lifetime,
                                'ports': [destination['port']] if destination.get('port') else [],
                                'destinations': [{'kind': key, 'value': destination[key]} for key in ('host', 'ip') if destination.get(key)]}
                        if destination.get('host') and destination.get('ip'):
                            rule['required_host'] = destination['host']
                            rule['destinations'] = [{'kind': 'ip', 'value': destination['ip']}]
                        # Legacy Allow is still an ordinary rule. Only the
                        # explicit reviewed DNS-exception operation may opt out.
                        commands = [{'operation': 'upsert', 'rule': rule}]
                    preview = self.manager.prepare(uid, {'provider': 'application', 'revision': revision, 'commands': commands})
                    value = {'transaction': preview['transaction']}
                token = value.get('transaction')
                if not isinstance(token, str):
                    raise PolicyError('A reviewed transaction is required.')
                result = self.manager.apply(uid, token, lambda t, prepared: self.authorize(sender, uid, t, prepared))
                response = json.dumps(result)
            except Exception as exception:
                response = failure(exception)
            finally:
                self.slots.release()
            GLib.idle_add(lambda: (reply(response), False)[1])
        self.workers.submit(work)

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s', sender_keyword='sender')
    def GetRules(self, payload, sender=None):
        try:
            uid = self.peer(sender)
            result = self.manager.listing(uid, decode(str(payload)))
            result['applications'] = []
            try:
                projection = self.engine_ready()
                result['applications'] = [{'path': a.get('executable'), 'name': a.get('application')}
                                          for a in projection.get('applications', [])[:256] if a.get('executable')]
                fresh = dt.datetime.fromisoformat(projection['fresh_until'].replace('Z', '+00:00')) > dt.datetime.now(dt.timezone.utc)
                loaded = fresh and projection.get('policy_revision') == result['revision'] and projection.get('opensnitch', {}).get('state') == 'OPERATING'
                for rule in result['rules']:
                    if rule['provider'] == 'application' and rule['state'] == 'SAVED' and loaded:
                        rule['state'] = 'LOADED'
                        observed = projection.get('policy_matches', {}).get(rule['id'], {})
                        if observed.get('version') == rule.get('updated_at') and observed.get('decisions', 0) > 0:
                            rule.update(state='OBSERVED', observed=observed)
            except (OSError, ValueError, KeyError, TypeError, dbus.DBusException) as exception:
                result['capabilities']['edit'] = False
                result['detail'] = str(exception)[:240]
            try:
                self.peer(sender, True)
            except PolicyError:
                result['capabilities']['edit'] = False
            return json.dumps(result)
        except Exception as exception:
            return failure(exception)

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s', sender_keyword='sender')
    def Preview(self, payload, sender=None):
        try:
            self.engine_ready()
            return json.dumps(self.manager.prepare(self.peer(sender, True), decode(str(payload))))
        except Exception as exception:
            return failure(exception)

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s', sender_keyword='sender', async_callbacks=('reply', 'error'))
    def Apply(self, payload, reply, error, sender=None):
        self.dispatch(payload, sender, reply, error)

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s', sender_keyword='sender')
    def Cancel(self, payload, sender=None):
        try:
            token = decode(str(payload)).get('transaction')
            result = self.manager.cancel(self.peer(sender, True), token)
            authority = self.authorizations.get(token)
            if authority is not None:
                try:
                    authority.CancelCheckAuthorization(token, timeout=3)
                except dbus.DBusException:
                    pass
            return json.dumps(result)
        except Exception as exception:
            return failure(exception)

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s', sender_keyword='sender', async_callbacks=('reply', 'error'))
    def SetRule(self, payload, reply, error, sender=None):
        self.dispatch(payload, sender, reply, error, 'rule')

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s', sender_keyword='sender', async_callbacks=('reply', 'error'))
    def SetThreatException(self, payload, reply, error, sender=None):
        self.dispatch(payload, sender, reply, error, 'threat-exception')

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s', sender_keyword='sender', async_callbacks=('reply', 'error'))
    def SetThreatIntelEnabled(self, payload, reply, error, sender=None):
        # Legacy callers send a JSON boolean, not an object.
        try:
            enabled = json.loads(str(payload))
            if not isinstance(enabled, bool):
                raise PolicyError('Enablement must be boolean.')
        except (ValueError, TypeError) as exception:
            reply(failure(exception))
            return
        self.dispatch(json.dumps({'enabled': enabled}), sender, reply, error, 'threat-setting')

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s', sender_keyword='sender', async_callbacks=('reply', 'error'))
    def RemoveRule(self, payload, reply, error, sender=None):
        self.dispatch(payload, sender, reply, error, 'remove')

    @dbus.service.method(BUS_NAME, in_signature='', out_signature='s')
    def ListRules(self):
        try:
            rows = []
            for rule in self.manager.store.read()['rules']:
                destination = {'host': rule.get('required_host'), 'ip': rule.get('ip'), 'port': rule.get('port')}
                rows.append({'id': rule_id(rule), 'name': rule['name'], 'action': rule['action'].upper(),
                             'source': 'GREYWARD', 'mutable': True, 'enabled': rule.get('enabled', True),
                             'duration': rule.get('lifetime', 'always').upper(), 'tier': rule.get('tier', 'GREYWARD'),
                             'scope': {'application': rule.get('path'), 'destination': destination}})
            return json.dumps({'ok': True, 'rules': rows})
        except Exception as exception:
            return failure(exception)


def main():
    if os.geteuid() != 0:
        raise SystemExit('greyward-opensnitch-policy must run as root')
    dbus.mainloop.glib.threads_init()
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    name = dbus.service.BusName(BUS_NAME, bus=bus)
    service = OpenSnitchPolicy(bus)
    GLib.MainLoop().run()


if __name__ == '__main__':
    main()
