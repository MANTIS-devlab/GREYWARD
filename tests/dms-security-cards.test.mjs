import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';

const model = vm.createContext({});
vm.runInContext(fs.readFileSync(new URL('../environment/session/dms-2.0-plugins/greywardSecure/StatusModel.js', import.meta.url), 'utf8').replace(/^\.pragma library\s*\n/, ''), model);
const healthy = () => ({posture:'PROTECTED', severity:'INFO', label:'Protected', reason:'Protection is operating',
    details:[{label:'Firewall',value:'Secure'},{label:'Network protection',value:'Healthy'},{label:'Secure DNS',value:'Encrypted'},{label:'Device protection',value:'Secure'}],
    activity:[], notification_items:[]});

test('only a fresh confirmed posture is green, including taskbar color', () => {
    for (const posture of ['PROTECTED','SECURE']) assert.equal(model.protectionTone({...healthy(),posture},true),'positive');
    for (const posture of ['UNAVAILABLE','REVIEW NEEDED','unexpected','']) assert.equal(model.protectionTone({...healthy(),posture},true),'warning');
    assert.equal(model.protectionTone(healthy(),false),'warning');
    assert.equal(model.protectionTone({...healthy(),loading:true},true),'warning');
    assert.equal(model.protectionTone({...healthy(),activity:[{id:'definitions-initializing'}]},true),'warning');
    assert.equal(model.protectionTone({...healthy(),severity:'WARNING'},true),'warning');
    assert.equal(model.protectionTone({...healthy(),severity:undefined},true),'warning');
});
test('critical evidence cannot be masked by a positive headline', () => {
    assert.equal(model.protectionTone({...healthy(),severity:'CRITICAL'},true),'critical');
    assert.equal(model.protectionTone({...healthy(),notification_items:[{severity:'CRITICAL',route:'devices'}]},true),'critical');
});
test('network requires both firewall and application-filtering evidence', () => {
    assert.equal(model.card('network',healthy(),true,true).tone,'positive');
    const partial={...healthy(),details:[{label:'Firewall',value:'Secure'}]};
    assert.equal(model.card('network',partial,true,true).tone,'warning');
    assert.equal(model.card('network',partial,true,true).value,'Status unavailable');
    assert.equal(model.card('network',{...healthy(),details:[]},true,true).tone,'warning');
    assert.equal(model.card('network',{...healthy(),details:[]},true,true).value,'Status unavailable');
    assert.equal(model.card('network',{...partial,notification_items:[{route:'network',severity:'WARNING',detail:'Actual finding'}]},true,true).value,'Review needed');
    assert.equal(model.card('network',{...healthy(),notification_items:[{route:'network',severity:'WARNING',detail:'Provider unavailable'}]},true,true).tone,'warning');
    assert.equal(model.card('network',{...healthy(),details:[{label:'Firewall',value:'Disabled'}]},true,true).tone,'critical');
});
test('an unrelated alert does not turn healthy network controls red', () => {
    const snapshot={...healthy(),severity:'CRITICAL',notification_items:[{route:'devices',severity:'CRITICAL'}]};
    assert.equal(model.card('network',snapshot,true,true).tone,'positive');
});
test('observed operating filtering and VPN-owned DNS are healthy information', () => {
    for (const value of ['Vpnowned', 'VPNOwned', 'VPN_OWNED']) {
        const snapshot={...healthy(),details:[{label:'Firewall',value:'Secure'},
            {label:'Network protection',value:'Operating'},{label:'Secure DNS',value}],
            notification_items:[{route:'network',severity:'INFO',title:'Connection blocked',detail:'A blocked connection is informational.'}]};
        const result=model.card('network',snapshot,true,true);
        assert.equal(result.tone,'positive'); assert.equal(result.value,'Protection active');
        assert.equal(result.detail,'VPN active');
        assert.ok(!/encrypted|all traffic|kill switch/i.test(JSON.stringify(result)));
        assert.equal(result.rows[2].label,'VPN'); assert.equal(result.rows[2].tone,'info');
        for (const severity of ['WARNING','ACTION','CRITICAL']) {
            const alert=model.card('network',{...snapshot,notification_items:[{route:'network',severity,detail:'Actual finding'}]},true,true);
            assert.equal(alert.tone,severity==='CRITICAL'?'critical':'warning');
            assert.equal(alert.detail,'VPN active · Actual finding');
        }
        assert.equal(model.card('network',snapshot,false,true).tone,'warning');
        assert.equal(model.card('network',{...snapshot,details:snapshot.details.slice(1)},true,true).tone,'warning');
    }
    const unavailable={...healthy(),details:[{label:'Firewall',value:'Secure'},
        {label:'Network protection',value:'Not operating'},{label:'Secure DNS',value:'VPNOwned'}]};
    assert.equal(model.card('network',unavailable,true,true).tone,'warning');
    const explicit={...healthy(),details:[{label:'Firewall',value:'Secure'},
        {label:'Network protection',value:'Operating'},{label:'Secure DNS',value:'VPNOwned',state:'UNAVAILABLE'}]};
    assert.equal(model.card('network',explicit,true,true).detail,'VPN status unavailable');
});
test('reviewed exceptions, unknown text and negative substrings never become green', () => {
    for (const value of ['Not secure','Insecure provider','Reviewed exception','System default','Protected?','Sécurisé',null]) {
        assert.notEqual(model.detailTone({value}),'positive');
    }
    assert.equal(model.detailTone({state:'UNAVAILABLE',value:'Secure'}),'warning');
    assert.equal(model.detailTone({state:'',value:'Secure'}),'warning');
    assert.equal(model.detailTone({state:0,value:'Secure'}),'warning');
});
test('updates never inherit overall protection or invent idle update counts', () => {
    const result=model.card('updates',healthy(),true,true);
    assert.equal(result.tone,'warning'); assert.equal(result.value,'Check updates');
    assert.ok(!JSON.stringify(result).includes('Up to date'));
    const busy=model.card('updates',{...healthy(),activity:[{kind:'update',title:'Updating your system',detail:'42% completed'}]},true,true);
    assert.equal(busy.detail,'42% completed'); assert.equal(busy.tone,'warning');
    const failed=model.card('updates',{...healthy(),notification_items:[{id:'update-failed',route:'updates',severity:'WARNING',title:'Update could not finish'}]},true,true);
    assert.equal(failed.tone,'critical');
});
test('stale or unavailable integration clears all formerly positive rows', () => {
    for (const section of ['protection','network','updates']) {
        const stale=model.card(section,healthy(),false,true), missing=model.card(section,healthy(),true,false);
        assert.equal(stale.tone,'warning'); assert.equal(stale.rows.length,0);
        assert.equal(missing.tone,'warning'); assert.equal(missing.value,'Integration unavailable');
    }
});

test('VPN is secondary and confirmed Off never downgrades active filtering', () => {
    for (const [state, expected] of [['ACTIVE','VPN active'],['OFF','VPN off'],['UNAVAILABLE','VPN status unavailable']]) {
        const snapshot={...healthy(),details:[...healthy().details,{label:'VPN',state,value:'display text'}]};
        const result=model.card('network',snapshot,true,true);
        assert.equal(result.value,'Protection active'); assert.equal(result.detail,expected);
        assert.equal(result.tone,'positive'); assert.equal(result.rows[2].label,'VPN');
        assert.equal(model.card('protection',snapshot,true,true).value,'Protected');
    }
    // No inference of Off from encrypted DNS or an explicit unavailable probe.
    assert.equal(model.card('network',healthy(),true,true).detail,'VPN status unavailable');
    const snapshot={...healthy(),details:[...healthy().details.filter(row=>row.label!=='Secure DNS'),
        {label:'Secure DNS',value:'VPNOwned'},{label:'VPN',state:'UNAVAILABLE',value:'Unavailable'}]};
    assert.equal(model.card('network',snapshot,true,true).detail,'VPN status unavailable');
});
test('explicitly disabled filtering is inactive even while a VPN is active', () => {
    const snapshot={...healthy(),details:[{label:'Firewall',value:'Disabled'},
        {label:'Network protection',value:'Operating'},{label:'VPN',state:'ACTIVE'}]};
    const result=model.card('network',snapshot,true,true);
    assert.equal(result.value,'Protection inactive'); assert.equal(result.tone,'critical');
    assert.match(result.detail,/VPN active/);
});
