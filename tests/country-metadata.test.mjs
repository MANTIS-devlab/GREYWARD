import {readFileSync} from 'node:fs';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import test from 'node:test';

const source = readFileSync(new URL('../security-center/tauri/frontend/app.js', import.meta.url), 'utf8');
const catalog = readFileSync(new URL('../security-center/tauri/frontend/assets/country-flags/catalog.js', import.meta.url), 'utf8');
const block = source.slice(source.indexOf('function networkCountrySignal'), source.indexOf('function networkActivityMeta'));
test('country hint renders local source and stale file age without inventing unknown locations', () => {
  const context = {esc: String, i18n: {locale: 'en'}, copy: (key, values = {}) => `${key} ${JSON.stringify(values)}`};
  vm.createContext(context);
  vm.runInContext(`${catalog}; ${block}; globalThis.render = networkCountryFlag`, context);
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

test('all bundled country codes render real local SVG images and invalid codes stay neutral',()=>{
 const context={esc:String,i18n:{locale:'en'},copy:key=>key};vm.createContext(context);
 vm.runInContext(`${catalog}; ${block}; globalThis.render=networkCountryFlag;`,context);
 const codes=Object.keys(context.GREYWARD_COUNTRY_FLAGS);assert.equal(codes.length,250);
 for(const code of codes){
  const flag=context.render({country_code:code});
  assert.match(flag,new RegExp(`data-country="${code}"`));
  assert.ok(flag.includes(`src="./assets/country-flags/${code.toLowerCase()}.svg"`));
  assert.doesNotMatch(flag,/https?:|<text|flag-code/);
 }
 for(const code of ['ZZ','__proto__','../../private','']){
  const flag=context.render({country_code:code});assert.match(flag,/data-country="UN"/);assert.doesNotMatch(flag,/<img/);
 }
});
