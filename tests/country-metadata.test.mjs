import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import test from 'node:test';

const source = readFileSync(new URL('../security-center/tauri/frontend/app.js', import.meta.url), 'utf8');
const block = source.slice(source.indexOf('function networkCountrySignal'), source.indexOf('function networkActivityMeta'));
test('country hint renders local source and stale file age without inventing unknown locations', () => {
  const context = {esc: String, i18n: {locale: 'en'}, copy: (key, values = {}) => `${key} ${JSON.stringify(values)}`};
  vm.createContext(context);
  vm.runInContext(`${block}; globalThis.render = networkCountryFlag`, context);
  const stale = context.render({country_code: 'FR', country_confidence: 'VERY_LOW', country_availability: 'STALE', country_sources: [{source: 'GEOFEED', available: true, age_days: 181.7, freshness: 'STALE'}]});
  assert.match(stale, /country\.source\.GEOFEED/);
  assert.match(stale, /country\.fileAge.*181/);
  assert.match(stale, /country\.stale/);
  assert.match(stale, /confidence\.very_low/);
  const unknown = context.render({country_availability: 'UNKNOWN', country_sources: []});
  assert.match(unknown, /country\.unknown/);
  assert.match(unknown, /data-country="UN"/);
  assert.doesNotMatch(unknown, /country\.inferred|country\.fileAge/);
});
