/* Shared log presentation. Assessment remains in the UID-scoped provider. */
(() => {
  'use strict';
  const names={NORMAL:'Normal',POLICY_BLOCKED:'Policy blocked',SUSPICIOUS:'Suspicious',HIGH_THREAT:'High threat',UNKNOWN:'Not evaluated'};
  const escape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const numeric=value=>Number.isFinite(value)&&value>=0&&value<=100?Math.round(value):null;
  const basename=value=>String(value||'Unknown process').split('/').pop();
  function networkBadge(value){
    const score=value?.classification==='UNKNOWN'?null:numeric(value?.score);
    const level=score===null?null:score===0?1:score<20?2:score<50?3:score<70?4:score<90?5:6;
    const tone=level===null?'unknown':level<=2?'low':level<=4?'medium':'high';
    const label=level===null?'Risk not assessed: insufficient evidence.':`Risk ${level}/6 · ${level<=2?'Low priority':level<=4?'Inspect':'Inspect first'}. Based on available evidence, not a probability. Expand for reasons.`;
    return `<span class="intel-badge network-risk" data-risk="${tone}" role="img" aria-label="${escape(label)}" title="${escape(label)}"><strong>${level??'—'}<small>/6</small></strong><span>${level===null?'Not assessed':level<=2?'Low':level<=4?'Inspect':'High'}</span></span>`;
  }
  function badge(value){
    const v=value&&names[value.classification]?value:{classification:'UNKNOWN',score:null};const score=v.classification==='UNKNOWN'?null:numeric(v.score);
    const text=score===null?'Not assessed':score===0?'Nothing suspicious':score<35?'Low concern':score<75?'Review':'High';
    const label=score===null?'Not assessed: there is insufficient evidence for an assessment.':score===0?`No suspicious indicators found in the assessed evidence. 0/100 · ${v.confidence||'UNKNOWN'} confidence`:`${score}/100 · ${text} · ${v.confidence||'UNKNOWN'} confidence`;
    return `<span class="intel-badge" data-grade="${v.classification}" data-assessment="${score===null?'unknown':score===0?'clear':'scored'}" role="img" aria-label="${escape(label)}" title="${escape(label)}"><i aria-hidden="true">${score===0?'\u2713':score===null?'\u2014':''}</i>${score===null||score===0?'':`<strong>${score}<small>/100</small></strong>`}<span>${escape(text)}</span></span>`;
  }
  function explanation(value,incident){
    const e=value||{},factors=incident?.factors||e.factors||[],chain=incident?.chain||[],lookup=new Map(chain.map(p=>[p.id,p]));
    const fact=(label,v)=>v==null?'':`<div><dt>${escape(label)}</dt><dd>${escape(v)}</dd></div>`;
    return `<section class="behavioral-evidence"><div class="behavioral-evidence-heading"><strong>Security assessment</strong>${e.risk_scale===6?networkBadge(e):badge(e)}</div><p class="behavioral-limit">Severity index, not probability of compromise. ${e.scope==='PROCESS_INSTANCE'?'Latest related process assessment, matched by kernel process instance; this does not change the connection decision.':e.scope==='NETWORK_REPUTATION'?'Destination reputation assessment; process behavior is not established for this connection.':e.source==='TETRAGON_KERNEL'?'Kernel observation; policy outcome is not established.':''}</p><dl class="behavioral-facts">${fact('Assessment scope',e.scope?.replaceAll('_',' '))}${fact('Sensor',e.sensor_state)}${fact('Sensor coverage',e.sensor_detail||null)}${fact('Earlier reported losses',e.historical_gaps?`${e.historical_gaps} (legacy counter; not threats or current health)`:null)}${fact('Network evidence window',e.context_partial?'Partial retained window; patterns may be missed':e.risk_scale===6?'Bounded connection history; evaluated at each event time':null)}${fact('Reputation coverage',e.coverage?`${e.coverage.reputation_provider}: ${e.coverage.reputation==='FRESH'?e.coverage.reputation_indicators+' current indicators':'unavailable or stale'}. Domain reputation is not evaluated.`:null)}${fact('Detection confidence',e.confidence||'UNKNOWN')}${fact('Process',e.binary||e.executable)}${fact('PID',e.pid)}${fact('Execution identity',e.exec_id)}${fact('Rules',e.rules)}${incident?fact('Correlated incident score',`${incident.score}/100 · ${incident.confidence} confidence`):''}</dl>${factors.length?`<ul class="behavioral-factors">${factors.map(f=>`<li><strong>${e.risk_scale===6?'Weight ':'+'}${numeric(f.points)??0} · ${escape(f.code?.replaceAll('_',' ')||'Observed factor')}</strong><p>${escape(f.explanation)}</p>${f.evidence?`<small>${escape(f.evidence.occurred_at)} · ${escape(basename(f.evidence.binary))} · PID ${escape(f.evidence.pid)}</small>`:''}</li>`).join('')}</ul>`:`<p>${e.classification==='UNKNOWN'?'This observation was not evaluated.':'No additional suspicious factor was identified in the available evidence.'}</p>`}${e.score_components?`<p class="behavioral-limit">Score uses the strongest evidence weight (${escape(e.score_components.strongest_evidence)}) plus capped independent support (${escape(e.score_components.independent_support)}). Overlapping indicators are not added together.</p>`:''}${chain.length?`<h4>Related processes</h4><ol class="behavioral-chain">${chain.map(p=>`<li><strong title="${escape(p.binary)}">${escape(basename(p.binary))}</strong><span>PID ${escape(p.pid??'—')} · ${lookup.has(p.parent)?'Parent: '+escape(basename(lookup.get(p.parent).binary))+' · PID '+escape(lookup.get(p.parent).pid??'—'):'Parent not retained in this view'}</span></li>`).join('')}</ol>`:''}${incident?.timeline?.length?`<h4>Correlated sequence</h4><ol class="behavioral-timeline">${incident.timeline.map(t=>`<li><time>${escape(t.occurred_at?.slice(11,19)||'—')}</time><span>${escape(t.title)} · ${escape(basename(t.binary))}</span><strong>${numeric(t.score)??'—'}</strong></li>`).join('')}</ol>${incident.timeline_truncated?`<small>${incident.timeline.length} retained of ${escape(incident.total_events)} observations</small>`:''}`:''}<p class="behavioral-limit">${escape(e.detail||incident?.response||'Existing security controls remain the enforcement authority.')}</p></section>`;
  }
  function create({request,onChange=()=>{}}){
    const views=new Map(),cache=new Map(),offsets=new Map();let focusId='';
    const focus=value=>{if(value!==undefined){focusId=/^incident-[a-f0-9]{24}$/.test(String(value))?String(value):'';cache.clear();offsets.clear();}return focusId;};
    const reset=channel=>{offsets.set(channel,0);cache.clear();};
    async function read(channel,options={}){
      const filters={channel,limit:60,offset:offsets.get(channel)||0,...options,...(focusId?{incident_id:focusId}:{})};delete filters.force;
      const key=JSON.stringify(filters),hit=cache.get(key);if(!options.force&&hit&&performance.now()-hit.at<10000)return hit.value;
      let value;
      try{
        value=await request('get_behavioral_intelligence',{filters},10000);
        if(value?.schema!=='greyward.intelligence/v1'||!value.sensor)throw new Error('Unavailable observation');
        if(!['ACTIVE','DEGRADED'].includes(value.sensor.state))value={...value,historical:true};
      }catch{
        const previous=views.get(channel)||{};
        value={...previous,schema:'greyward.intelligence/v1',historical:true,sensor:{...(previous.sensor||{}),state:'UNAVAILABLE',detail:'Observation unavailable; retained rows are historical.'},events:previous.events||[],incidents:(previous.incidents||[]).map(i=>({...i,state:'HISTORICAL'}))};
      }
      views.set(channel,value);cache.set(key,{at:performance.now(),value});return value;
    }
    const snapshot=channel=>views.get(channel)||null;
    const caseFor=(id,value)=>value?.incidents?.find(i=>i.id===id);
    function status(value,channel){
      const sensor=value?.sensor||{},state=sensor.state||'UNAVAILABLE';
      return `<details class="behavioral-status" data-observation-state="${escape(state)}"><summary>Behavioral observation: <strong>${escape(state)}</strong>${sensor.dropped?` · ${sensor.dropped} earlier gaps`:""}</summary><span>${escape(sensor.detail||'Coverage not confirmed.')}</span>${Number.isFinite(sensor.dropped)?`<small>${sensor.dropped} reported gaps</small>`:''}${focusId?'<button class="text-button" data-behavioral-all>Show all events</button>':''}</details><div class="behavioral-pagination">${(offsets.get(channel)||0)>0?`<button class="text-button" data-behavioral-latest="${channel}">Latest process observations</button>`:''}${value?.next_offset!=null?`<button class="text-button" data-behavioral-more="${channel}">Older process observations →</button>`:''}</div>`;
    }
    function inspection(event,incident){
      return `<div data-behavioral-evidence>${explanation(event,incident)}</div>${event?.incident_id&&!incident?`<button class="text-button" data-behavioral-load="${escape(event.incident_id)}" data-behavioral-event="${escape(event.event_id)}">Load correlated case</button>`:''}`;
    }
    function historyRow(event,value){
      const incident=caseFor(event.incident_id,value);
      return `<article class="history-event behavioral-event" data-history-event="${escape(event.event_id)}"><span class="history-marker" aria-hidden="true">${event.kind==='process_exit'?'↘':'↗'}</span><div class="history-event-copy"><div class="history-actor"><strong title="${escape(event.binary)}">${escape(basename(event.binary))}</strong><span>Observed process · PID ${escape(event.pid??'—')}</span></div><h3>${escape(event.title)}</h3><details class="technical-disclosure" data-behavioral-case="${escape(event.incident_id||'')}"><summary>Score and related activity</summary><div data-behavioral-evidence>${explanation(event,incident)}</div>${event.incident_id&&!incident?`<button class="text-button" data-behavioral-load="${escape(event.incident_id)}" data-behavioral-event="${escape(event.event_id)}">Load correlated case</button>`:''}</details></div><div class="history-event-end">${badge(event)}<span class="history-decision unknown">Observed · outcome not established</span><time>${escape(event.occurred_at)}</time></div></article>`;
    }
    function bind(root){
      root.querySelectorAll('[data-behavioral-load]').forEach(b=>{if(b.dataset.bound)return;b.dataset.bound='true';b.addEventListener('click',async()=>{b.disabled=true;try{const data=await request('get_behavioral_intelligence',{filters:{incident_id:b.dataset.behavioralLoad,limit:1}},10000),incident=data?.incidents?.find(i=>i.id===b.dataset.behavioralLoad);if(incident){const box=b.parentElement.querySelector('[data-behavioral-evidence]');if(box){const event=Array.from(views.values()).flatMap(v=>v.events||[]).find(e=>e.event_id===b.dataset.behavioralEvent)||{classification:'UNKNOWN',score:null};box.innerHTML=explanation(event,incident);}b.remove();}else b.textContent='Correlated case is not retained';}catch{b.textContent='Case temporarily unavailable';}finally{b.disabled=false;}});});
      root.querySelectorAll('[data-behavioral-more],[data-behavioral-latest],[data-behavioral-all]').forEach(b=>{if(b.dataset.bound)return;b.dataset.bound='true';b.addEventListener('click',async()=>{const channel=b.dataset.behavioralMore||b.dataset.behavioralLatest;if(b.hasAttribute('data-behavioral-all'))focus('');else offsets.set(channel,b.dataset.behavioralMore?(snapshot(channel)?.next_offset||0):0);cache.clear();await onChange(channel);});});
      if(focusId){const target=Array.from(root.querySelectorAll('[data-behavioral-case]')).find(e=>e.dataset.behavioralCase===focusId);if(target){target.open=true;target.scrollIntoView?.({block:'nearest'});}}
    }
    return Object.freeze({read,snapshot,reset,focus,status,historyRow,explanation,inspection,caseFor,bind,badge,networkBadge});
  }
  globalThis.GREYWARD_BEHAVIORAL=Object.freeze({create,badge,networkBadge,explanation,names});
})();
