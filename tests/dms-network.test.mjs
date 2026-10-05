import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';

const math = vm.createContext({});
const source = fs.readFileSync(new URL('../environment/session/dankmaterialshell/plugins/greywardNetworkTraffic/NetworkTrafficMath.js', import.meta.url), 'utf8');
vm.runInContext(source.replace(/^\.pragma library\s*\n/, ''), math);

test('physical-link aggregate excludes loopback, VPN and duplicate counters', () => {
    const snapshot = [{name: 'eth0', rx: 1500, tx: 3000}, {name: 'eth0', rx: 1500, tx: 3000},
        {name: 'lo', rx: 9000, tx: 9000}, {name: 'wg0', rx: 9000, tx: 9000}];
    const result = math.calculateRates(snapshot, {eth0: {rx: 1000, tx: 2000}}, 500, []);
    assert.equal(JSON.stringify(result.interfaces), '["eth0"]');
    assert.equal(result.rxRate, 1000);
    assert.equal(result.txRate, 2000);
});

test('internal dgop total counters warm up before reporting byte rates', () => {
    const first = math.calculateRates([{interface: 'enp0s1', rxtotal: 1000, txtotal: 2000}], {}, 1000, ['enp0s1']);
    assert.equal(first.rxRate, 0);
    assert.equal(first.txRate, 0);
    const next = math.calculateRates([{name: 'enp0s1', rxtotal: 4000, txtotal: 6000}], first.counters, 2000, ['enp0s1']);
    assert.equal(next.rxRate, 1500);
    assert.equal(next.txRate, 2000);
});

test('counter reset or wrap skips that direction without a fabricated spike', () => {
    const result = math.calculateRates([{name: 'eth0', rx: 10, tx: 1200}], {eth0: {rx: 4294967290, tx: 1000}}, 1000, []);
    assert.equal(result.rxRate, 0);
    assert.equal(result.txRate, 200);
    const absent = math.calculateRates([], result.counters, 1000, []);
    assert.equal(absent.rxRate, 0);
    assert.equal(absent.txRate, 0);
    assert.equal(JSON.stringify(absent.interfaces), '[]');
});
