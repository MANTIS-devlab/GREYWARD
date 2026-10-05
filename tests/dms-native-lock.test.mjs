import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import test from 'node:test';
import vm from 'node:vm';

// Execute the assembled startup hook, or reconstruct its changed hunk locally.
const patch = readFileSync(fileURLToPath(new URL('../environment/patches/dms/greyward-native-lock-recovery.patch', import.meta.url)), 'utf8');
const changed = patch.split(/\r?\n/).filter(line => /^[ +]/.test(line) && !line.startsWith('+++')).map(line => line.slice(1)).join('\n');
const qml = process.env.GREYWARD_LOCK_QML ? readFileSync(process.env.GREYWARD_LOCK_QML, 'utf8') : changed;
const marker = 'Component.onCompleted: {';
const start = qml.indexOf(marker) + marker.length;
assert.ok(start >= marker.length);
const body = qml.slice(start, qml.indexOf('\n    }', start));
function attach({locked=false, integration=true, custom='', startup=false, greeter=false}={}) {
  let calls=0;
  const scope={IdleService:{}, SettingsData:{loginctlLockIntegration:integration, customPowerActionLock:custom, lockAtStartup:startup}, SessionService:{locked}, lock(){calls++;}, freshGreeterLogin(){return greeter;}};
  vm.runInNewContext(body, scope);
  assert.ok(scope.IdleService.lockComponent);
  return calls;
}
test('late attachment restores an already locked native session even after greeter login', () => {
  assert.equal(attach({locked:true, greeter:true}),1);
});
test('unlocked sessions stay unlocked and existing startup policy is preserved', () => {
  assert.equal(attach(),0);
  assert.equal(attach({startup:true}),1);
  assert.equal(attach({startup:true, greeter:true}),0);
});
test('disabled integration and configured external handoffs are not reclaimed', () => {
  assert.equal(attach({locked:true,integration:false}),0);
  assert.equal(attach({locked:true,custom:'/test/locker'}),0);
});
