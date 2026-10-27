#!/usr/bin/python3 -I
"""Read current kernel decisions after desktop compatibility policy changes.

Run through PID 1 as root on the enrolled development system. No policy,
account, service or resource is modified; no secret contents are read.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, '/usr/lib/greyward/application-security/desktop')
from verify import kernel_decision

if os.getuid():
    raise RuntimeError('Trusted root kernel readback required')


def enrolled_broker_readback():
    """A matching ELF/kernel policy does not establish the session broker mode."""
    def read(*args):
        return subprocess.run(args, check=True, capture_output=True,
                              text=True, timeout=10).stdout.strip()
    workflow = 'greyward-application-security-workflows.service'
    if read('systemctl', 'show', workflow, '-p', 'ActiveState', '--value') != 'active':
        raise RuntimeError('Enrolled workflow broker is not active')
    if read('systemctl', 'show', 'greyward-application-security.service',
            '-p', 'ActiveState', '--value') != 'inactive':
        raise RuntimeError('Conflicting read-only broker must be inactive')
    pid = read('systemctl', 'show', workflow, '-p', 'MainPID', '--value')
    if not re.fullmatch(r'[1-9][0-9]*', pid):
        raise RuntimeError('Enrolled broker has no live PID')
    command = (Path('/proc') / pid / 'cmdline').read_bytes().split(b'\0')
    if command != [b'/usr/libexec/greyward-application-security', b'--workflows', b'']:
        raise RuntimeError('Broker is not running in enrolled workflow mode')
    # Bind the exposed method to the exact running workflow service, not just
    # an introspection string from a different owner of the well-known name.
    owner = read('gdbus', 'call', '--system', '--dest', 'org.freedesktop.DBus',
                 '--object-path', '/org/freedesktop/DBus', '--method',
                 'org.freedesktop.DBus.GetConnectionUnixProcessID',
                 'systems.mantis.greyward.ApplicationSecurity1')
    if not re.fullmatch(r'\(uint32 ' + re.escape(pid) + r',\)', owner):
        raise RuntimeError('Application Security bus owner does not match workflow PID')
    interface = read('gdbus', 'introspect', '--system', '--dest',
                     'systems.mantis.greyward.ApplicationSecurity1', '--object-path',
                     '/systems/mantis/greyward/ApplicationSecurity1')
    if not re.search(r'^\s+StartDesktop\(out b ', interface, re.MULTILINE):
        raise RuntimeError('Enrolled session admission method is unavailable')
    if read('systemctl', 'show', workflow, '-p', 'MainPID', '--value') != pid:
        raise RuntimeError('Workflow broker changed during readback')
    return True


broker_verified = enrolled_broker_readback()
ordinary = json.loads(Path('/usr/lib/greyward/application-security/desktop/ordinary.json').read_text())['ordinary']
checks = 0
for domain in ordinary:
    subject = f'greyward_guard_u:greyward_guard_r:{domain}:s0'
    for role, target in [('greyward_admin_r','greyward_admin_t'),
                         ('greyward_admin_r','greyward_admin_sudo_t'),
                         ('greyward_admin_r','greyward_admin_password_t'),
                         ('sysadm_r','sysadm_t'),('sysadm_r','sysadm_sudo_t')]:
        for cls, rights in [('process',['ptrace','signal','sigkill','sigstop','setpgid']),('fd',['use'])]:
            allowed, _ = kernel_decision(subject, f'greyward_admin_u:{role}:{target}:s0', cls, rights)
            assert allowed == 0, (domain, target, cls)
            checks += 1
    for target, cls, rights in [
            ('greyward_admin_password_exec_t','file',['execute','entrypoint']),
            ('greyward_admin_runtime_t','file',['open','read','write']),
            ('greyward_admin_devpts_t','chr_file',['open','read','write','ioctl']),
            ('greyward_flatpak_service_t','file',['write','append','unlink']),
            ('greyward_flatpak_service_t','dir',['write','add_name','remove_name'])]:
        allowed, _ = kernel_decision(subject, f'system_u:object_r:{target}:s0', cls, rights)
        assert allowed == 0, (domain, target, cls)
        checks += 1

subject = 'greyward_guard_u:greyward_guard_r:greyward_guard_t:s0'
for target, cls, rights, expected in [
        ('greyward_flatpak_service_t','dir',['watch'],True),
        ('home_cert_t','dir',['mounton'],True),
        ('dma_device_t','chr_file',['getattr','mounton'],True),
        ('dma_device_t','chr_file',['open','read','write','ioctl'],False),
        ('hsa_device_t','chr_file',['getattr','mounton'],True),
        ('hsa_device_t','chr_file',['open','read','write','ioctl'],False),
        ('flatpak_helper_t','unix_stream_socket',['read','write'],True),
        ('flatpak_helper_t','unix_stream_socket',['connectto'],False),
        ('flatpak_helper_t','file',['open','read','write'],False),
        ('flatpak_helper_t','process',['ptrace','signal','sigkill'],False),
        ('fusefs_t','lnk_file',['create','rename','unlink'],True),
        ('var_lib_t','file',['write','append','unlink','relabelto'],False),
        ('greyward_as_display_t','unix_stream_socket',['read','write','getattr','getopt'],True),
        ('greyward_as_auth_t','unix_stream_socket',['connectto','read','write'],False),
        ('user_tmp_t','service',['start','stop','reload'],True)]:
    # Newly created revokefs symlinks retain the ordinary caller's SELinux user;
    # the create constraint intentionally rejects system_u-owned objects.
    target_user = 'greyward_guard_u' if target == 'fusefs_t' else 'system_u'
    target_context = f'{target_user}:object_r:{target}:s0'
    if target == 'greyward_as_display_t':
        target_context = 'greyward_guard_u:greyward_guard_r:greyward_as_display_t:s0'
    elif target == 'greyward_as_auth_t':
        target_context = 'system_u:system_r:greyward_as_auth_t:s0'
    allowed, _ = kernel_decision(subject, target_context, cls, rights)
    permissions = Path('/sys/fs/selinux/class') / cls / 'perms'
    expected_mask = sum(1 << (int((permissions / right).read_text()) - 1)
                        for right in rights) if expected else 0
    assert allowed == expected_mask, (target, rights, allowed, expected_mask)
    checks += 1

subject = 'greyward_guard_u:greyward_guard_r:greyward_as_display_t:s0'
for target, expected in [('usr_t', True), ('var_lib_t', False)]:
    allowed, _ = kernel_decision(subject, f'system_u:object_r:{target}:s0', 'file', ['open', 'read'])
    assert bool(allowed) == expected, (target, allowed)
    checks += 1

print(json.dumps({'schema':'greyward.desktop-kernel-check/v1','checks':checks,
                  'enrolled_broker_mode_verified':broker_verified,
                  'ordinary_administration_denied':True,'public_metadata_readonly':True,
                  'dma_access_denied':True,'hsa_compute_access_denied':True}))
