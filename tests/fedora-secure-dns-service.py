#!/usr/bin/python3
"""Bounded installed-service canary on an explicitly selected development host.

Temporarily substitutes one resolved link's DNS metadata, tests the packaged
service and its typed mode changes, then restores metadata and policy in finally.
No network profile/interface, desktop or authentication is changed. Never run on
a user test VM.
"""
import argparse
import ipaddress
import json
import os
import pwd
import socket
import struct
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import dbus


def unit(action):
    options = ['--runtime'] if action in {'mask', 'unmask'} else []
    subprocess.run(['systemctl', action, *options, 'greyward-secure-dns.service'], check=True, timeout=30)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-address', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Root is required for this development-only canary.')
    requester = pwd.getpwuid(int(os.environ['SUDO_UID'])).pw_name
    assert requester != 'root', 'typed mode checks require the invoking development user'
    def set_mode(mode):
        # Mutations are wheel-authorized on the system bus; root is not the
        # session requester. Exercise the same identity as the typed UI path.
        script = ('import dbus,sys; b=dbus.SystemBus(); '
                  'p=dbus.Interface(b.get_object("systems.mantis.greyward.SecureDns1", '
                  '"/systems/mantis/greyward/SecureDns1"), "systems.mantis.greyward.SecureDns1"); '
                  'print(p.SetMode(sys.argv[1], timeout=60))')
        return json.loads(subprocess.check_output(['runuser', '-u', requester, '--',
                                                 '/usr/bin/python3', '-c', script, mode], text=True, timeout=70))
    address = subprocess.check_output(['nmcli', '-g', 'IP4.ADDRESS', 'device', 'show', 'eth0'], text=True).splitlines()[0].split('/')[0]
    assert address == args.expected_address, 'development host identity mismatch'
    sys.path.insert(0, '/usr/lib/greyward-security-context')
    from greyward_security_context import secure_dns_reconciler as dns
    from greyward_security_context import secure_dns_split as split
    from greyward_security_context import control_plane
    bus = dbus.SystemBus()
    manager = dbus.Interface(bus.get_object('org.freedesktop.resolve1', '/org/freedesktop/resolve1'), 'org.freedesktop.resolve1.Manager')
    index = socket.if_nametoindex('eth0')
    original = dns._link(bus, index)
    original_policy = dns._policy()
    assert original_policy['desired_policy'] == 'Automatic', 'canary requires the development default policy'
    assert dns._managed_provider(original), 'canary requires an already healthy managed development link'
    assert not original.get('Domains'), 'do not replace a real private-domain installation'
    assert not split.CONFIG_PATH.exists(), 'an existing public/private scope is not a canary target'
    assert not Path('/run/systemd/system/greyward-secure-dns.service').exists(), 'do not replace an existing runtime unit override'
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((address, 53))
    server.settimeout(0.2)
    running = threading.Event()
    running.set()
    queries = []
    def answer():
        while running.is_set():
            try:
                request, sender = server.recvfrom(4096)
            except socket.timeout:
                continue
            offset, labels = 12, []
            while request[offset]:
                size = request[offset]
                labels.append(request[offset+1:offset+1+size].decode())
                offset += size + 1
            queries.append('.'.join(labels))
            record = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + ipaddress.ip_address('192.0.2.123').packed
            server.sendto(request[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + request[12:offset+5] + record, sender)
    thread = threading.Thread(target=answer, daemon=True)
    thread.start()
    try:
        # Prevent normal UI polling from D-Bus-activating the service while
        # the controlled fixture is being prepared/restored.
        unit('mask')
        unit('stop')
        manager.SetLinkDefaultRoute(index, False)
        manager.SetLinkDomains(index, dbus.Array([('mshome.net', False)], signature='(sb)'))
        manager.SetLinkDNSEx(index, dbus.Array([(socket.AF_INET, dbus.Array(list(ipaddress.ip_address(address).packed), signature='y'), 53, '')], signature='(iayqs)'))
        manager.SetLinkDNSOverTLS(index, 'no')
        manager.SetLinkDNSSEC(index, 'no')
        unit('unmask')
        unit('start')
        proxy = dbus.Interface(bus.get_object(dns.BUS_NAME, dns.OBJECT_PATH), dns.BUS_NAME)
        value = json.loads(str(proxy.GetState(timeout=30)))
        print(json.dumps(value, sort_keys=True), flush=True)
        assert value['effective_policy'] == 'SecureProvider', 'installed service public scope failed'
        assert value['route_domains'] == ['mshome.net']
        assert value['public_scope'] == 'system'
        assert control_plane._active_private_dns_addresses() == {address}
        private = manager.ResolveHostname(0, 'greyward-fixture.mshome.net', socket.AF_INET, dbus.UInt64(6144), timeout=8)
        assert ipaddress.ip_address(bytes(private[0][0][2])) == ipaddress.ip_address('192.0.2.123')
        assert queries and set(queries) == {'greyward-fixture.mshome.net'}, queries
        print('INSTALLED_UNIT_PUBLIC_DOT_DNSSEC=PASS PRIVATE_QUERY=PASS SCOPED_ADMISSION=PASS NO_PUBLIC_PRIVATE_LEAK=PASS', flush=True)
        selected = set_mode('NetworkDefault')
        assert selected['ok'] and selected['result']['effective_policy'] == 'NetworkDefault', selected
        assert not split.CONFIG_PATH.exists()
        assert split._global(bus)['Domains'] == [], 'public route retained after explicit opt-out'
        assert control_plane._active_network_default_dns_addresses() == {address}
        for process, target, expected in (('/usr/lib/systemd/systemd-resolved', address, 'allow'),
                                          ('/usr/lib/systemd/systemd-resolved', '192.0.2.254', 'deny'),
                                          ('/usr/bin/greyward-test-app', address, 'deny')):
            connection = SimpleNamespace(process_path=process, dst_ip=target, dst_host='', dst_port=53, protocol='udp')
            assert control_plane.select_policy_rule(connection)[0] == expected
        private = manager.ResolveHostname(0, 'greyward-fixture.mshome.net', socket.AF_INET, dbus.UInt64(6144), timeout=8)
        assert ipaddress.ip_address(bytes(private[0][0][2])) == ipaddress.ip_address('192.0.2.123')
        selected = set_mode('Automatic')
        assert selected['ok'] and selected['result']['effective_policy'] == 'SecureProvider', selected
        assert control_plane._active_network_default_dns_addresses() == set()
        print('EXPLICIT_NETWORK_DEFAULT=PASS RESOLVED_ONLY_ADMISSION=PASS RETURN_TO_AUTOMATIC=PASS', flush=True)
    finally:
        try:
            unit('mask')
            unit('stop')
            split.restore(bus)
            dns._write(dns.POLICY_PATH, original_policy, 0o640)
            manager.SetLinkDNSEx(index, dbus.Array(original['DNSEx'], signature='(iayqs)'))
            manager.SetLinkDNSOverTLS(index, original['DNSOverTLS'])
            manager.SetLinkDNSSEC(index, original['DNSSEC'])
            manager.SetLinkDomains(index, dbus.Array(original['Domains'], signature='(sb)'))
            manager.SetLinkDefaultRoute(index, original['DefaultRoute'])
            unit('unmask')
            unit('start')
            restored = dns._link(bus, index)
            for key in ('DNSEx', 'Domains', 'DefaultRoute', 'DNSOverTLS', 'DNSSEC'):
                assert restored[key] == original[key], f'canary restoration changed {key}'
            assert not split.CONFIG_PATH.exists()
            assert split._global(bus)['Domains'] == [], 'public route retained after restoration'
            print('INSTALLED_UNIT_RESTORE=PASS', flush=True)
        finally:
            if Path('/run/systemd/system/greyward-secure-dns.service').is_symlink():
                unit('unmask')
                unit('start')
            running.clear()
            thread.join(timeout=1)
            server.close()


if __name__ == '__main__':
    main()
