import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';
const context={performance};context.window=context;vm.createContext(context);
vm.runInContext(readFileSync(new URL('./behavioral.js',import.meta.url),'utf8'),context);
const ui=context.GREYWARD_BEHAVIORAL;
test('unanalysed rows stay neutral and retained evidence cannot inject markup',()=>{
 assert.match(ui.badge({}),/Not assessed/);assert.doesNotMatch(ui.badge({}),/>0</);
 const markup=ui.explanation({binary:'<img src=x>',classification:'HIGH_THREAT',score:80},null);
 assert.match(markup,/&lt;img src=x&gt;/);assert.doesNotMatch(markup,/<img src=x>/);
 assert.match(markup,/80/);assert.match(markup,/not probability/);
});
test('channel queries remain bounded and network attempts do not invent firewall decisions',async()=>{
 let filters;
 const view=ui.create({request:async(_,arg)=>{filters=arg.filters;return {schema:'greyward.intelligence/v1',sensor:{state:'ACTIVE'},events:[{event_id:'one',binary:'/usr/bin/curl',score:0,classification:'NORMAL',destination:{ip:'1.1.1.1',port:443}}]};}});
 await view.read('NETWORK');assert.equal(filters.channel,'NETWORK');assert.equal(filters.limit,60);
 assert.equal(view.networkEvents,undefined); // raw kernel attempts never become firewall decision rows
});
test('failed refresh retains rows and known gaps but marks evidence historical',async()=>{
 let calls=0;
 const view=ui.create({request:async()=>{if(calls++)throw new Error('offline');return {schema:'greyward.intelligence/v1',sensor:{state:'ACTIVE',dropped:3},events:[{event_id:'one'}],incidents:[]};}});
 await view.read('SYSTEM');const failed=await view.read('SYSTEM',{force:true});
 assert.equal(failed.sensor.state,'UNAVAILABLE');assert.equal(failed.sensor.dropped,3);assert.equal(failed.events.length,1);
 assert.match(view.status(failed,'SYSTEM'),/3 reported gaps/);
});
test('legacy Intelligence workspace is removed and log inspection is the presentation boundary',()=>{
 const app=readFileSync(new URL('./app.js',import.meta.url),'utf8');
 assert.doesNotMatch(app,/GREYWARD_INTELLIGENCE|intelligence\.(markup|summary|load)|\["intelligence",/);
 assert.match(app,/behavioral\.inspection\(item.behavioral/);
 assert.match(app,/!item.observed_attempt && networkActivityState.mutationAvailable/);
 assert.equal(typeof ui.create({request:async()=>({})}).markup,'undefined');
});

test('network decisions retain their labels and share one aligned header contract',()=>{
 const app=readFileSync(new URL('./app.js',import.meta.url),'utf8');
 const source=app.slice(app.indexOf('function networkActivitySource()'),app.indexOf('function networkActivityProtocols()'));
 assert.doesNotMatch(source,/networkEvents|behavioral.read/);
 assert.doesNotMatch(app,/Observed attempt|data-network-source|data-network-behavior[=\]\s]/);
 const css=readFileSync(new URL('./behavioral.css',import.meta.url),'utf8');
 assert.match(css,/grid-template-columns:var\(--activity-columns\)/);
 assert.match(ui.badge({classification:'NORMAL',score:10}),/Low concern/);
 assert.match(ui.badge({classification:'NORMAL',score:0}),/Nothing suspicious/);
 assert.match(ui.badge({classification:'SUSPICIOUS',score:40}),/Review/);
});

test('clear assessments use plain language while unassessed rows never get a reassuring zero',()=>{
 const clear=ui.badge({classification:'NORMAL',score:0});
 assert.match(clear,/Nothing suspicious/);assert.match(clear,/No suspicious indicators found in the assessed evidence/);
 assert.doesNotMatch(clear,/<strong>0<\/strong>/);assert.match(clear,/data-assessment="clear"/);
 const unknown=ui.badge({classification:'UNKNOWN',score:0});
 assert.match(unknown,/Not assessed/);assert.doesNotMatch(unknown,/Nothing suspicious|<strong>/);
 assert.match(ui.badge({classification:'NORMAL',score:8}),/<strong>8<small>\/100<\/small><\/strong>/);
 assert.doesNotMatch(clear,/Allowed|Blocked|Safe|guaranteed/);
});

test('malformed indices stay unassessed instead of being clamped to a reassuring zero',()=>{
 for(const score of [-1,101,NaN,Infinity,'0'])assert.match(ui.badge({classification:'NORMAL',score}),/Not assessed/);
});


test('network risk uses six readable levels with independent firewall outcomes',()=>{
 for(const [score,level,tone] of [[0,1,'low'],[1,2,'low'],[19,2,'low'],[20,3,'medium'],[49,3,'medium'],[50,4,'medium'],[69,4,'medium'],[70,5,'high'],[89,5,'high'],[90,6,'high'],[100,6,'high']]){
  const badge=ui.networkBadge({classification:'NORMAL',score});
  assert.match(badge,new RegExp(`Risk ${level}/6`));assert.match(badge,new RegExp(`data-risk="${tone}"`));
  assert.doesNotMatch(badge,/Allowed|Blocked|Nothing suspicious|\/100/);
 }
 for(const score of [null,undefined,-1,101,NaN,'0'])assert.match(ui.networkBadge({classification:'NORMAL',score}),/Risk not assessed/);
 assert.match(ui.networkBadge({classification:'UNKNOWN',score:0}),/Risk not assessed/);
});


test('network explanations separate risk, coverage and historical losses',()=>{
 const markup=ui.explanation({risk_scale:6,score:35,classification:'SUSPICIOUS',confidence:'MEDIUM',sensor_state:'ACTIVE',sensor_detail:'Current probes verified',historical_gaps:20323,context_partial:true,coverage:{reputation_provider:'Feodo',reputation:'FRESH',reputation_indicators:1},score_components:{strongest_evidence:35,independent_support:0},factors:[{code:'SERVICE_HOST_SWEEP',points:35,explanation:'16 destinations on one service in 60 seconds'}]});
 assert.match(markup,/Risk 3\/6/);assert.match(markup,/Current probes verified/);
 assert.match(markup,/not threats or current health/);assert.match(markup,/1 current indicators/);
 assert.match(markup,/Domain reputation is not evaluated/);assert.match(markup,/Partial retained window/);
 assert.match(markup,/Weight 35/);assert.match(markup,/Overlapping indicators are not added/);
 assert.doesNotMatch(markup,/proof of safety|Safe connection/);
});
