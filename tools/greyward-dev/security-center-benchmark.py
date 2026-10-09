#!/usr/bin/python3
"""Read-only installed-desktop profiling through the real local WebKit driver.
No mock provider data, policy mutation, private display, or credential capture.
"""
import argparse,json,statistics,time,urllib.request,urllib.error
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--endpoint',default='http://127.0.0.1:49951');p.add_argument('--session',required=True);p.add_argument('--output',required=True);p.add_argument('--cycles',type=int,default=10);p.add_argument('--idle',type=int,default=30);a=p.parse_args()
if not 1 <= a.cycles <= 100 or not 0 <= a.idle <= 600:
 p.error('Use 1–100 cycles and 0–600 idle seconds')
base=a.endpoint+'/session/'+a.session

def req(path,value=None,read_only=False):
 r=urllib.request.Request(base+path,data=None if value is None else json.dumps(value).encode(),headers={'Content-Type':'application/json'})
 for attempt in range(3):
  try:
   with urllib.request.urlopen(r,timeout=20) as s:return json.load(s)['value']
  except (ConnectionError,urllib.error.URLError):
   if (value is not None and not read_only) or attempt==2:raise
   time.sleep(.1)

def js(source,read_only=False):return req('/execute/sync',{'script':source,'args':[]},read_only)
def wait_ready(route):
 deadline=time.monotonic()+20
 while time.monotonic()<deadline:
  s=js('''return {ready:document.querySelector('.app-shell')?.getAttribute('aria-busy')==='false',error:!!document.querySelector('.error-state'),route:document.querySelector('.nav-item.active')?.dataset.page,appsReady:!!document.querySelector('.inventory-section'),title:document.querySelector('h1')?.textContent}''',True)
  if s['ready'] and s['route']==route and (route!='applications' or s['appsReady']):return s
  time.sleep(.025)
 raise RuntimeError('Route did not settle: '+route+' '+str(s))

js('''if(window.__gwPerf?.observer)window.__gwPerf.observer.disconnect();
window.__gwPerf={calls:[],renders:{},mutations:{},errors:[],installed:Date.now()};
const perf=window.__gwPerf;
const original=requestAdapter.__gwOriginal||requestAdapter;
requestAdapter=function(command,args,timeout){const start=performance.now();return original(command,args,timeout).then(v=>{if(perf.calls.length<4096)perf.calls.push({command,ms:performance.now()-start,ok:true});return v},e=>{if(perf.calls.length<4096)perf.calls.push({command,ms:performance.now()-start,ok:false});throw e})};requestAdapter.__gwOriginal=original;
for(const name of ['overviewMarkup','renderContent','shell','bind','bindContent','updateGuardOverview','updateGuardWorkspace','renderNetworkActivityView']){const f=window[name]?.__gwOriginal||window[name];if(typeof f==='function'){const wrapped=function(...args){const start=performance.now();try{return f.apply(this,args)}finally{const v=perf.renders[name]||={count:0,ms:0,max:0};const elapsed=performance.now()-start;v.count++;v.ms+=elapsed;v.max=Math.max(v.max,elapsed)}};wrapped.__gwOriginal=f;window[name]=wrapped}}
perf.observer=new MutationObserver(records=>{for(const r of records){const name=r.target.id||r.target.className;if(typeof name==='string')perf.mutations[name]=(perf.mutations[name]||0)+1}});perf.observer.observe(document.querySelector('#app'),{childList:true,subtree:true});
perf.errorListener=e=>perf.errors.push({type:'error',message:String(e.message).slice(0,200)});perf.rejectionListener=e=>perf.errors.push({type:'rejection',message:String(e.reason).slice(0,200)});window.addEventListener('error',perf.errorListener);window.addEventListener('unhandledrejection',perf.rejectionListener);return true''')
try:
 report={'cycles':a.cycles,'routes':{},'started_at':time.time(),'startup_marks':js('return window.__greywardStartupMarks'),'samples':[]}
 routes=['overview','applications','protected-data','files','network','system','history','updates','recovery','privacy','activity']
 for cycle in range(a.cycles):
  for route in routes:
   start=time.perf_counter()
   js("document.querySelector('.nav-item[data-page=\""+route+"\"]').click();return true")
   state=wait_ready(route);elapsed=(time.perf_counter()-start)*1000
   report['routes'].setdefault(route,[]).append(round(elapsed,2))
   # Allow actual queued DOM/layout work to reach its next painted frame.
   req('/execute/async',{'script':'const done=arguments[arguments.length-1];requestAnimationFrame(()=>done(true))','args':[]},True)
   if state['error']:report.setdefault('route_errors',[]).append(state)
  Path(a.output+'.partial').write_text(json.dumps(report))
  print(json.dumps({'cycle':cycle+1,'last_route_ms':elapsed}),flush=True)
  if cycle%5==0:report['samples'].append(js("return {at:Date.now(),nodes:document.querySelectorAll('*').length,domSize:document.documentElement.outerHTML.length}"))
 js("document.querySelector('.nav-item[data-page=overview]').click();return true");wait_ready('overview')
 before=js('return {calls:window.__gwPerf.calls.length,renders:JSON.parse(JSON.stringify(window.__gwPerf.renders)),mutations:JSON.parse(JSON.stringify(window.__gwPerf.mutations))}')
 for index in range(a.idle):time.sleep(1)
 after=js('return {calls:window.__gwPerf.calls,renders:window.__gwPerf.renders,mutations:window.__gwPerf.mutations,errors:window.__gwPerf.errors}')
 report.update(instrumentation=after,idle_seconds=a.idle,idle_calls=after['calls'][before['calls']:],idle_before=before)
 for route,values in list(report['routes'].items()):
  ordered=sorted(values);report['routes'][route]={'median_ms':statistics.median(values),'p95_ms':ordered[min(len(ordered)-1,int(.95*len(ordered)))],'min_ms':min(values),'max_ms':max(values),'samples_ms':values}
 Path(a.output).write_text(json.dumps(report,indent=2));print(json.dumps({'output':a.output,'routes':report['routes'],'errors':after['errors'],'idle_call_count':len(report['idle_calls'])}),flush=True)
finally:
 # Restore adapters even when a route times out.
 js("""const p=window.__gwPerf;p.observer.disconnect();window.removeEventListener('error',p.errorListener);window.removeEventListener('unhandledrejection',p.rejectionListener);requestAdapter=requestAdapter.__gwOriginal||requestAdapter;for(const name of ['overviewMarkup','renderContent','shell','bind','bindContent','updateGuardOverview','updateGuardWorkspace','renderNetworkActivityView']){if(window[name]?.__gwOriginal)window[name]=window[name].__gwOriginal}return true""")
