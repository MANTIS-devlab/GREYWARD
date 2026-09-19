"""Narrow USBGuard adapter. Enforcement and persistent policy remain upstream."""
import hashlib
import re
import dbus

USB_SERVICE = 'org.usbguard1'
DEVICES_PATH = '/org/usbguard1/Devices'
POLICY_PATH = '/org/usbguard1/Policy'
DEVICES_INTERFACE = 'org.usbguard.Devices1'
POLICY_INTERFACE = 'org.usbguard.Policy1'
ALLOW, BLOCK = 0, 1
DEVICE_ID = re.compile(r'^[1-9][0-9]*$')
DEVICE_IDENTIFIER = re.compile(r'\bid\s+([0-9a-fA-F]{4}:[0-9a-fA-F]{4})\b')
ATTR = re.compile(r'\b(?P<key>name|serial|hash|via-port)\s+"(?P<value>[^"]*)"')
INTERFACE = re.compile(r'with-interface\s+(\{[^}]*\}|"[^"]*"|\S+)')
DBUS_CALL_TIMEOUT = 8

class UsbGuardError(RuntimeError):
    def __init__(self, detail, state='FAILED'):
        super().__init__(detail)
        self.state = state


def parse_rule(rule):
    value = str(rule)
    attrs = {m.group('key'): m.group('value')[:160] for m in ATTR.finditer(value)}
    identifier = DEVICE_IDENTIFIER.search(value)
    interfaces = INTERFACE.search(value)
    classes = re.findall(r'\b([0-9a-fA-F]{2}):[0-9a-fA-F*]{2}:[0-9a-fA-F*]{2}', interfaces.group(1) if interfaces else '')
    classes = [item.lower() for item in classes]
    if '08' in classes: device_class = 'EXTERNAL_STORAGE'
    elif '06' in classes: device_class = 'EXTERNAL_MEDIA'
    elif '0e' in classes: device_class = 'EXTERNAL_CAMERA'
    elif '02' in classes: device_class = 'EXTERNAL_NETWORK'
    elif classes and all(item in {'09', '03', '01', 'e0'} for item in classes): device_class = 'INTERNAL_OR_UNSUPPORTED'
    else: device_class = 'EXTERNAL_UNKNOWN' if attrs.get('via-port') and not re.search(r'controller|hub|internal', attrs.get('name', ''), re.I) else 'UNKNOWN'
    stable = attrs.get('serial') or attrs.get('hash')
    return {'state': value.split(maxsplit=1)[0].upper() if value else 'UNKNOWN',
            'name': ''.join(c for c in attrs.get('name', 'USB device') if c.isprintable())[:80],
            'specific_id': bool(identifier), 'stable_identity': bool(stable),
            'stable_material': stable or attrs.get('via-port'),
            'vendor_id': identifier.group(1).split(':')[0] if identifier else None,
            'product_id': identifier.group(1).split(':')[1] if identifier else None,
            'interface': classes[0] if classes else None, 'device_class': device_class,
            'controller': attrs.get('via-port', '').startswith('usb')}


def persistent_rule_is_narrow(rule):
    parsed = parse_rule(rule)
    return parsed['specific_id'] and parsed['stable_identity']


class UsbGuardAdapter:
    def __init__(self, bus=None):
        self.bus = bus or dbus.SystemBus()
        self._policy_cache = None

    def method(self, path, interface, name):
        return self.bus.get_object(USB_SERVICE, path).get_dbus_method(name, interface)

    def authorized_call(self, path, interface, name, signature, args):
        # dbus-python's proxy does not set ALLOW_INTERACTIVE_AUTHORIZATION.
        # USBGuard only asks its existing Polkit authority when this flag is set.
        from dbus.lowlevel import MethodCallMessage
        message = MethodCallMessage(destination=USB_SERVICE, path=path, interface=interface, method=name)
        message.set_allow_interactive_authorization(True)
        message.append(*args, signature=signature)
        reply = self.bus.send_message_with_reply_and_block(message, 120)
        values = reply.get_args_list()
        return values[0] if values else None

    def list_devices(self):
        try:
            owner = str(self.bus.get_name_owner(USB_SERVICE))
            listing = self.method(DEVICES_PATH, DEVICES_INTERFACE, 'listDevices')
            devices = listing('match', timeout=DBUS_CALL_TIMEOUT)
            rules = self.method(POLICY_PATH, POLICY_INTERFACE, 'listRules')('', timeout=DBUS_CALL_TIMEOUT)
            # Ask USBGuard to match rules. String equality fails for policy rules
            # omitting instance-only attributes or using set expressions.
            cache_key = (owner, tuple((int(i), str(r)) for i, r in devices), tuple((int(i), str(r)) for i, r in rules))
            if self._policy_cache and self._policy_cache[0] == cache_key:
                persistent = self._policy_cache[1]
            else:
                persistent, decided = set(), set()
                for _, rule in rules:
                    target, _, attributes = str(rule).partition(' ')
                    if target not in {'allow', 'block', 'reject'}:
                        continue
                    matched = {str(int(i)) for i, _ in listing('match ' + attributes, timeout=DBUS_CALL_TIMEOUT)} - decided
                    if target == 'allow':
                        persistent.update(matched)
                    decided.update(matched)
                    if len(decided) == len(devices):
                        break
                self._policy_cache = (cache_key, persistent)
        except dbus.DBusException as error:
            raise UsbGuardError('USBGuard device state is unavailable.') from error
        output = []
        for device_id, rule in devices:
            parsed = parse_rule(rule)
            reference = hashlib.sha256(f'{owner}:{int(device_id)}'.encode()).hexdigest()[:32]
            output.append({'device_id': str(int(device_id)), 'connection_ref': reference,
                           'name': parsed['name'], 'state': parsed['state'],
                           'authorized': parsed['state'] == 'ALLOW',
                           'trusted': str(int(device_id)) in persistent, 'controller': parsed['controller'],
                           'can_persist': persistent_rule_is_narrow(rule), 'device_class': parsed['device_class'],
                           'identity_metadata': {'stable_id': parsed['stable_material'], 'vendor_id': parsed['vendor_id'],
                                                 'product_id': parsed['product_id'], 'interface': parsed['interface'],
                                                 'device_class': parsed['device_class']}})
        return output

    def apply(self, device_id, target, permanent):
        if not DEVICE_ID.fullmatch(str(device_id)):
            raise UsbGuardError('Invalid USBGuard device reference.')
        try:
            return int(self.authorized_call(DEVICES_PATH, DEVICES_INTERFACE, 'applyDevicePolicy', 'uub',
                (dbus.UInt32(int(device_id)), dbus.UInt32(target), dbus.Boolean(permanent))))
        except dbus.DBusException as error:
            name = error.get_dbus_name()
            if 'NoReply' in name or 'Timeout' in name:
                raise UsbGuardError('Authorization timed out; checking device state.', 'INDETERMINATE') from error
            if 'Cancel' in name or 'Dismiss' in name:
                raise UsbGuardError('Authorization was cancelled.', 'CANCELLED') from error
            if 'ServiceUnknown' in name or 'Disconnected' in name:
                raise UsbGuardError('USBGuard is unavailable.', 'UNAVAILABLE') from error
            raise UsbGuardError('USBGuard did not authorize the device change.', 'DENIED') from error

    def allow_once(self, device_id):
        return self.apply(device_id, ALLOW, False)

    def always_allow(self, device_id):
        device = next((item for item in self.list_devices() if item['device_id'] == str(device_id)), None)
        if device is None:
            raise UsbGuardError('USB device is no longer connected.')
        if not device['can_persist']:
            raise UsbGuardError('No narrow stable device identity is available; persistent trust was not created.')
        return self.apply(device_id, ALLOW, True)

    def keep_blocked(self, device_id):
        return self.apply(device_id, BLOCK, False)

    def revoke(self, device_id, rule_id):
        if not DEVICE_ID.fullmatch(str(device_id)) or not DEVICE_ID.fullmatch(str(rule_id)):
            raise UsbGuardError('Invalid USBGuard device or rule reference.')
        try:
            self.authorized_call(POLICY_PATH, POLICY_INTERFACE, 'removeRule', 'u', (dbus.UInt32(int(rule_id)),))
        except dbus.DBusException as error:
            raise UsbGuardError('USBGuard or Polkit denied removal of this trust rule.') from error
        return self.keep_blocked(device_id)
