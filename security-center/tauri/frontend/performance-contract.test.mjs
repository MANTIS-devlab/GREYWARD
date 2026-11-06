import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';
const source=readFileSync(new URL('./app.js',import.meta.url),'utf8');
function extract(start,end,context){vm.runInNewContext(source.slice(source.indexOf(start),source.indexOf(end,source.indexOf(start))),context);return context;}
test('route mounting retains chrome and marks the correct parent destination',()=>{
 const root={setAttribute:(k,v)=>root[k]=v},frame={},status={};
 const buttons=['overview','system','activity'].map(page=>({dataset:{page},classList:{toggle:(k,v)=>{}},setAttribute(k,v){this[k]=v;}}));
 const app={querySelector:s=>({'.app-shell':root,'.content-frame':frame,'[data-live-status]':status})[s],querySelectorAll:()=>buttons};
 const c=extract('function mountPage(','function pageHeader(',{app,currentPage:'devices',pageParents:{devices:'system'},normalizePage:v=>v,deviationState:{feedback:'Readback complete'},shell:()=>{throw Error('Chrome rebuilt');}});
 c.mountPage('new route',{busy:true});assert.equal(frame.innerHTML,'new route');assert.equal(root['aria-busy'],'true');assert.equal(buttons[1]['aria-current'],'page');assert.equal(buttons[0]['aria-current'],'false');assert.equal(status.textContent,'Readback complete');
 c.currentPage='activity';c.mountPage('activity');assert.equal(root['aria-busy'],'false');assert.equal(buttons[2]['aria-current'],'page');assert.equal(buttons[1]['aria-current'],'false');
});
for(const failure of [false,true])test(`departed Activity ${failure?'failure':'success'} cannot overwrite the current view`,async()=>{
 let resolve,reject,paint=0;
 const c=extract('async function refreshNetworkActivity()','async function loadNetworkHistory(',{networkActivityState:{mode:'live',requestBusy:false,state:'AVAILABLE'},currentPage:'activity',requestSequence:3,document:{hidden:false},readNetworkActivity:()=>new Promise((a,b)=>{resolve=a;reject=b;}),syncNetworkActivityData:()=>paint++,renderNetworkActivityView:()=>paint++,actionError:()=>{throw Error('Old error painted');},copy:x=>x});
 const pending=c.refreshNetworkActivity();c.requestSequence++;c.currentPage='overview';failure?reject(Error('late')):resolve({});await pending;assert.equal(paint,0);assert.equal(c.networkActivityState.state,'AVAILABLE');assert.equal(c.networkActivityState.requestBusy,false);
});
test('a scan response belongs to both its operation and its route visit',async()=>{
 let resolve,paint=0,resume=0;
 const c=extract('async function refreshFileSecurityOperation()','function startFileSecurityPolling()',{currentPage:'files',requestSequence:4,fileSecurityState:{operationId:'old',requestBusy:false},document:{hidden:false},invokeBounded:()=>new Promise(r=>{resolve=r;}),app:{querySelector:s=>s.includes('is-active')?{}:{set innerHTML(v){paint++;}}},fileSecurityOperationMarkup:()=>{throw Error('Stale operation rendered');},scheduleFileSecurityPolling:()=>resume++});
 const pending=c.refreshFileSecurityOperation();c.requestSequence++;c.fileSecurityState.operationId='new';resolve({state:'COMPLETED'});await pending;assert.equal(paint,0);assert.equal(resume,1);assert.equal(c.fileSecurityState.requestBusy,false);
});

test('Overview history distinguishes loading, unavailable and authoritative empty results',()=>{
 const c=extract('function overviewActivitySection(','function updateHistoryMarkup(',{copy:x=>x,esc:x=>x,emptyState:(title)=>title,activityMarkup:x=>x.title});
 assert.match(c.overviewActivitySection({activity_state:'LOADING'}),/loading.status/);
 assert.match(c.overviewActivitySection({activity_state:'UNAVAILABLE'}),/activity.unavailable.title/);
 assert.doesNotMatch(c.overviewActivitySection({activity_state:'UNAVAILABLE'}),/activity.empty.title/);
 assert.match(c.overviewActivitySection({activity_state:'AVAILABLE',activity:[]}),/activity.empty.title/);
 assert.match(c.overviewActivitySection({activity_state:'AVAILABLE',activity:[{title:'old'}]},{source_state:{state:'UNAVAILABLE'}}),/activity.unavailable.title/);
 assert.doesNotMatch(c.overviewActivitySection({activity_state:'AVAILABLE',activity:[{title:'old'}]},{recent_activity:[]}),/old/);
});
test('late Overview history cannot populate another route or a newer Overview visit',()=>{
 const c=extract('function updateOverviewActivity(','function overviewActivity(',{currentPage:'overview',requestSequence:8,pageCache:{get:()=>{throw Error('Stale history accepted');}}});
 c.updateOverviewActivity({},7);c.currentPage='files';c.updateOverviewActivity({},8);
});

test('Recovery omits unrelated device history; the device view retains the normal provider read',async()=>{
 const calls=[];
 const c=extract('function getPageData(','async function refreshUpdates(',{window:{},pageDataRequests:new Map(),invokeBounded:(command,args)=>{calls.push({command,args});return Promise.resolve({});}});
 await c.getPageData('recovery');await c.getPageData('devices');
 assert.equal(calls.length,2);assert.equal(calls[0].command,'get_devices');assert.equal(calls[0].args.includeHistory,false);assert.equal(calls[1].command,'get_devices');assert.equal(calls[1].args,undefined);
});


test('Live polling is rearmed after entering a page in History and switching back',()=>{
 let callback,cleared=0,reads=0;
 const c=extract('function startNetworkActivityPolling()','async function loadNetworkHistory(',{updatePoll:42,currentPage:'activity',networkActivityState:{mode:'history'},window:{clearInterval:()=>cleared++,setInterval:(f,ms)=>{assert.equal(ms,2000);callback=f;return 43;}},refreshNetworkActivity:()=>reads++});
 c.startNetworkActivityPolling();assert.equal(c.updatePoll,null);assert.equal(reads,0);
 c.networkActivityState.mode='live';c.startNetworkActivityPolling();assert.equal(c.updatePoll,43);assert.equal(reads,1);callback();assert.equal(reads,2);
 c.startNetworkActivityPolling();assert.equal(cleared,2);assert.equal(c.networkActivityState.assessmentRefreshAt,0);
 const binding=source.slice(source.indexOf('app.querySelectorAll("[data-activity-mode]")'),source.indexOf('bindOnce(app.querySelector("[data-activity-load-more]")'));
 assert.match(binding,/startNetworkActivityPolling\(\)/);
});

test('retained connection scores are refreshed after late process evidence without a new sequence',async()=>{
 let cursor;
 const c=extract('async function refreshNetworkActivity()','function startNetworkActivityPolling(',{networkActivityState:{mode:'live',requestBusy:false,nextSequence:900,assessmentRefreshAt:1},currentPage:'activity',requestSequence:3,document:{hidden:false},Date:{now:()=>20000},readNetworkActivity:async value=>{cursor=value;return {};},syncNetworkActivityData:()=>{},renderNetworkActivityView:()=>{},actionError:()=>'',copy:x=>x});
 await c.refreshNetworkActivity();assert.equal(cursor,0);assert.equal(c.networkActivityState.assessmentRefreshAt,20000);
 c.Date.now=()=>21000;await c.refreshNetworkActivity();assert.equal(cursor,900);
});

test('reassessment snapshots do not count existing paused rows as new activity',()=>{
 const state={sessionId:'same',events:[{event_id:'one',sequence:1,behavioral:{score:0}}],expanded:new Set(),paused:true,pending:0,nextSequence:1};
 const c=extract('function syncNetworkActivityData(','function renderNetworkActivityView(',{networkActivityState:state,copy:x=>x});
 c.syncNetworkActivityData({session_id:'same',reset:true,next_sequence:1,events:[{event_id:'one',sequence:1,behavioral:{score:35}}]},{trackPending:true});
 assert.equal(state.pending,0);assert.equal(state.events[0].behavioral.score,35);
 state.pending=5;c.syncNetworkActivityData({session_id:'same',reset:true,next_sequence:1,events:state.events},{trackPending:true});assert.equal(state.pending,5);
});

test('a focused row button cannot indefinitely freeze all risk badges',()=>{
 let focused=0,bound=0;
 const control={focus:options=>{assert.equal(options.preventScroll,true);focused++;}};
 const row={dataset:{activityEvent:'one'},querySelectorAll:()=>[control],querySelector:()=>control};
 const active={closest:()=>row,matches:()=>false};row.querySelectorAll=()=>[active];
 const replacement={dataset:{activityEvent:'one'},querySelectorAll:()=>[control],querySelector:()=>control};
 const list={contains:()=>true,querySelectorAll:()=>[replacement],innerHTML:'old'};
 const c=extract('function renderNetworkActivityView(','async function refreshNetworkActivity()',{currentPage:'activity',document:{activeElement:active},networkActivityState:{renderedListMarkup:'old'},app:{querySelector:s=>s==='[data-network-activity-list]'?list:null},networkActivityRowsMarkup:()=>'<new risk=3>',readPageScrollPosition:()=>1,applyPageScroll:()=>{},bindNetworkActivityContent:()=>bound++,networkActivitySummaryMarkup:()=>'',syncNetworkActivityControls:()=>{}});
 c.renderNetworkActivityView();assert.equal(list.innerHTML,'<new risk=3>');assert.equal(focused,1);assert.equal(bound,1);
 active.matches=()=>true;list.innerHTML='editing';c.networkActivityState.renderedListMarkup='different';c.renderNetworkActivityView();assert.equal(list.innerHTML,'editing');
});
