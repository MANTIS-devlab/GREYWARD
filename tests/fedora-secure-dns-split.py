#!/usr/bin/python3
"""Real resolved split-DNS acceptance in a private mount namespace and bus.

Run as root on the Fedora build host. It neither stops the host resolver nor
changes network interfaces. --module-root can select extracted RPM modules.
"""
import argparse
import contextlib
import ipaddress
import json
import os
import pwd
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--module-root', type=Path, required=True)
    parser.add_argument('--child', action='store_true')
    parser.add_argument('--work', type=Path)
    parser.add_argument('--address')
    parser.add_argument('--domain', default='home.arpa')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run this isolated acceptance check as root.')
    if not args.child:
        address = subprocess.check_output(['nmcli', '-g', 'IP4.ADDRESS', 'device', 'show', 'eth0'], text=True).splitlines()[0].split('/')[0]
        with tempfile.TemporaryDirectory(prefix='greyward-dns-acceptance-', dir='/var/tmp') as work:
            os.chmod(work, 0o755)
            subprocess.run(['unshare', '--mount', '--propagation', 'private', sys.executable, __file__,
                            '--child', '--work', work, '--address', address,
                            '--domain', args.domain,
                            '--module-root', str(args.module_root.resolve())], check=True, timeout=90)
        return
    work = args.work
    subprocess.run(['mount', '-t', 'tmpfs', 'tmpfs', '/run/systemd'], check=True)
    subprocess.run(['mount', '-t', 'tmpfs', 'tmpfs', '/run/greyward-secure-dns'], check=True)
    (Path('/run/systemd/resolved.conf.d')).mkdir()
    Path('/run/systemd/resolved.conf.d/00-acceptance.conf').write_text(
        '[Resolve]\nDNS=\nDomains=\nDNSOverTLS=no\nDNSSEC=no\nDNSStubListener=no\nLLMNR=no\nMulticastDNS=no\n')
    runtime = Path('/run/systemd/resolve')
    runtime.mkdir()
    account = pwd.getpwnam('systemd-resolve')
    os.chown(runtime, account.pw_uid, account.pw_gid)
    config = work / 'dbus.conf'
    config.write_text(f'<busconfig><type>system</type><listen>unix:path={work}/bus</listen>'
                      '<auth>EXTERNAL</auth><policy context="default"><allow user="root"/>'
                      '<allow user="systemd-resolve"/><allow own="*"/><allow send_destination="*"/>'
                      '<allow receive_sender="*"/></policy></busconfig>')
    os.environ['DBUS_SYSTEM_BUS_ADDRESS'] = f'unix:path={work}/bus'
    processes = []
    queries = []
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((args.address, 0))
    server.settimeout(0.2)
    running = threading.Event()
    running.set()
    def answer_private():
        while running.is_set():
            try:
                request, source = server.recvfrom(4096)
            except socket.timeout:
                continue
            offset, labels = 12, []
            while request[offset]:
                size = request[offset]
                labels.append(request[offset+1:offset+1+size].decode())
                offset += size + 1
            end = offset + 5
            query = '.'.join(labels)
            queries.append(query)
            question = request[12:end]
            record = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + ipaddress.ip_address('192.0.2.123').packed
            response = request[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + question + record
            server.sendto(response, source)
    thread = threading.Thread(target=answer_private, daemon=True)
    thread.start()
    try:
        with (work / 'daemon.log').open('w') as log:
            processes.append(subprocess.Popen(['dbus-daemon', '--nofork', '--config-file', str(config)], stdout=log, stderr=log))
            for _ in range(100):
                if (work / 'bus').exists():
                    break
                time.sleep(0.03)
            processes.append(subprocess.Popen(['/usr/lib/systemd/systemd-resolved'], stdout=log, stderr=log))
            sys.path.insert(0, str(args.module_root))
            import dbus
            from greyward_security_context import secure_dns_reconciler as dns
            from greyward_security_context import secure_dns_split as split
            bus = dbus.SystemBus()
            for _ in range(150):
                if bus.name_has_owner('org.freedesktop.resolve1'):
                    break
                time.sleep(0.03)
            assert bus.name_has_owner('org.freedesktop.resolve1'), 'isolated resolver did not start'
            manager = dbus.Interface(bus.get_object('org.freedesktop.resolve1', '/org/freedesktop/resolve1'), 'org.freedesktop.resolve1.Manager')
            index = socket.if_nametoindex('eth0')
            entries = dbus.Array([(dbus.Int32(socket.AF_INET), dbus.Array(list(ipaddress.ip_address(args.address).packed), signature='y'),
                                   dbus.UInt16(server.getsockname()[1]), dbus.String(''))], signature='(iayqs)')
            manager.SetLinkDNSEx(index, entries)
            manager.SetLinkDNSOverTLS(index, 'no')
            manager.SetLinkDNSSEC(index, 'no')
            manager.SetLinkDomains(index, dbus.Array([(args.domain, False)], signature='(sb)'))
            manager.SetLinkDefaultRoute(index, True)
            original = dns._link(bus, index)
            with patch.object(split, '_reload', side_effect=lambda _bus: os.kill(processes[-1].pid, signal.SIGHUP)):
                try:
                    value = split.reconcile(bus, {'ifindex': index, 'interface': 'eth0'}, original,
                                            {'route_domains': [args.domain]}, {'provider_order': list(dns.PROVIDERS)})
                    print(json.dumps(value, sort_keys=True), flush=True)
                    assert value['effective_policy'] == 'SecureProvider', 'public encrypted probe failed'
                    name = f'greyward-fixture.{args.domain}'
                    private = manager.ResolveHostname(0, name, socket.AF_INET, dbus.UInt64(6144), timeout=8)
                    assert ipaddress.ip_address(bytes(private[0][0][2])) == ipaddress.ip_address('192.0.2.123')
                    assert queries and set(queries) == {name}, f'public traffic reached private DNS: {queries}'
                    assert split.active_private_addresses(bus) == {args.address}
                    split.restore(bus)
                    assert split._global(bus)['Domains'] == [], 'public route retained after restoration'
                    restored = dns._link(bus, index)
                    for key in ('DNSEx', 'Domains', 'DefaultRoute', 'DNSOverTLS', 'DNSSEC'):
                        assert restored[key] == original[key], f'rollback changed {key}'
                    print('PUBLIC_DOT_DNSSEC=PASS PRIVATE_QUERY=PASS NO_PUBLIC_PRIVATE_LEAK=PASS RESTORE=PASS', flush=True)
                finally:
                    split.restore(bus)
    except BaseException:
        print((work / 'daemon.log').read_text(), file=sys.stderr)
        raise
    finally:
        running.clear()
        thread.join(timeout=1)
        server.close()
        for process in reversed(processes):
            process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=3)


if __name__ == '__main__':
    main()
