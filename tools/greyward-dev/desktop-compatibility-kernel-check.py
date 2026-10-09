#!/usr/bin/python3 -I
"""Read current kernel decisions after desktop compatibility policy changes.

Run through PID 1 as root on the enrolled development system. No policy,
account, service or resource is modified; no secret contents are read.
"""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, '/usr/lib/greyward/application-security/desktop')
from verify import kernel_decision

if os.getuid():
    raise RuntimeError('Trusted root kernel readback required')

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
        ('user_tmp_t','service',['start','stop','reload'],True)]:
    allowed, _ = kernel_decision(subject, f'system_u:object_r:{target}:s0', cls, rights)
    assert bool(allowed) == expected, (target, rights, allowed)
    checks += 1

subject = 'greyward_guard_u:greyward_guard_r:greyward_as_display_t:s0'
for target, expected in [('usr_t', True), ('var_lib_t', False)]:
    allowed, _ = kernel_decision(subject, f'system_u:object_r:{target}:s0', 'file', ['open', 'read'])
    assert bool(allowed) == expected, (target, allowed)
    checks += 1

print(json.dumps({'schema':'greyward.desktop-kernel-check/v1','checks':checks,
                  'ordinary_administration_denied':True,'public_metadata_readonly':True,
                  'dma_access_denied':True}))
