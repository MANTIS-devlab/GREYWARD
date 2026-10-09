#!/usr/bin/python3 -I
"""Fixed trusted USBGuard READ projection. No caller-selected method or mutation."""
import json
import os
import sys
if os.getuid() or os.geteuid():
    raise RuntimeError('Trusted system projection required')
sys.path.insert(0, '/usr/lib/greyward-security-context')
from greyward_security_context.usbguard import UsbGuardAdapter
print(json.dumps({'schema':'greyward.device-projection/v1', 'devices':UsbGuardAdapter().list_devices()}))
