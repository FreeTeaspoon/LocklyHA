import {JSDOM} from 'jsdom';
import fs from 'node:fs';
import assert from 'node:assert/strict';
const js = fs.readFileSync(new URL('../custom_components/lockly/www/management-card.js', import.meta.url),'utf8');
const dom = new JSDOM('<html><body></body></html>', {runScripts:'outside-only',url:'https://example.invalid'});
dom.window.eval(js);
const data = {lock_id:'test',name:'Door',timezone:'Asia/Hong_Kong',updated_at:'2026-11-20T00:00Z',hub_volume:2,
  settings:{keypad_sound:true},credentials:[{slot:0,name:'Owner',editable:false,schedule:{type:'always'}},
    {slot:7,name:'<img src=x onerror=alert(1)>',editable:true,schedule:{type:'always'}}],history:[]};
const calls=[];
const card=dom.window.document.createElement('lockly-management-card'); card.setConfig({}); dom.window.document.body.append(card);
card.hass={user:{is_admin:true},callWS:async msg=>{calls.push(msg);return msg.lock_id?structuredClone(data):{locks:[structuredClone(data)]};}};
await new Promise(resolve=>setImmediate(resolve));
assert.equal(card.shadowRoot.querySelector('#credentials img'),null);
assert.equal(card.shadowRoot.querySelectorAll('#credentials button').length,2);
assert.match(card.shadowRoot.querySelector('#credentials').textContent, /<img/);
card.edit(data.credentials[1]);
assert.equal(card.$('pin').type,'password');assert.equal(card.$('pin').required,false);
card.$('name').value='Updated';card.$('pin').value='875938';
card.$('schedule').value='recurring';card.scheduleChanged();
card.$('days').querySelector('input').checked=true;
card.$('time-start').value='09:00';card.$('time-end').value='17:00';
await card.save();
assert.equal(card.$('pin').value,'');assert.equal(card.$('editor').hidden,true);
assert.equal(calls.at(-1).action,'save_pin');assert.equal(calls.at(-1).slot,7);
assert.equal(calls.at(-1).schedule.weekdays,1);
// The card clears its request object's secret after submission.
assert.equal(calls.at(-1).pin,'875938');
assert.equal(calls.some(c => c.action === 'media_start'), false);
card.edit();card.$('schedule').value='one_time';card.$('name').value='Once';card.$('pin').value='923457';
await card.save();assert.equal(calls.at(-1).one_time,true);assert.equal(calls.at(-1).schedule.type,'always');
card.data.fingerprints=[{slot:1,name:'<script>bad()</script>',revision:'finger',delegated:false}];
card.data.shares=[{id:'share',name:'<img src=x>',slot:7,revision:'key'}];
card.render();assert.equal(card.$('fingers').querySelector('script'),null);assert.equal(card.$('shares').querySelector('img'),null);
const ws = card._hass.callWS;
card._hass.callWS = async msg => {
  calls.push(msg);
  if(msg.action==='reveal_share')return {token:'private-token'};
  if(msg.action==='media_start')return {session:'media-token'};
  if(msg.action==='media_poll')return {ended:false};
  if(msg.action.startsWith('media_'))return {};
  return ws(msg);
};
await card.revealShare(card.data.shares[0]);assert.equal(card.$('share-secret').value,'private-token');
card.hideShare();assert.equal(card.$('share-secret').value,'');
let closed=false,stopped=false;
dom.window.AudioContext=class {
 constructor(){this.currentTime=0;this.sampleRate=48000;this.destination={};}
 async resume(){} async close(){closed=true;}
 createMediaStreamSource(){return {connect(){},disconnect(){}};}
 createScriptProcessor(){return {connect(){},disconnect(){}};}
};
Object.defineProperty(dom.window.navigator,'mediaDevices',{value:{getUserMedia:async()=>({getTracks:()=>[{stop(){stopped=true;}}]})}});
await card.startMedia();assert.equal(card.mediaToken,'media-token');
await card.toggleTalk();assert.equal(card.$('talk').getAttribute('aria-pressed'),'true');
assert.equal(card.alaw(0),0xd5);assert.equal(card.alaw(1),0xaa);
await card.stopMedia();assert.equal(card.mediaToken,null);assert.equal(stopped,true);assert.equal(closed,true);
assert.equal(card.$('talk').getAttribute('aria-pressed'),'false');
assert.equal(card.$('media-image').hasAttribute('src'),false);
// A delayed server response must not reopen the microphone or camera after close.
let finishTalk;
const mediaWS = card._hass.callWS;
card._hass.callWS = msg => msg.action === 'media_talk' && msg.enabled
  ? new Promise(resolve => {finishTalk = resolve;}) : mediaWS(msg);
await card.startMedia();
const pendingTalk = card.toggleTalk();
await new Promise(resolve=>setImmediate(resolve));
await card.stopMedia();finishTalk({});await pendingTalk;
assert.equal(card.mediaToken,null);assert.equal(card.processor,null);
assert.equal(card.micStream,null);
let finishStart;
card._hass.callWS = msg => msg.action === 'media_start'
  ? new Promise(resolve => {finishStart = resolve;}) : mediaWS(msg);
const pendingStart = card.startMedia();
await new Promise(resolve=>setImmediate(resolve));
await card.stopMedia();finishStart({session:'late-session'});await pendingStart;
assert.equal(card.mediaToken,null);
assert.equal(calls.some(c=>c.action==='media_stop' && c.session==='late-session' && c.lock_id==='test'),true);
card.edit();card.$('pin').value='875938';card.remove();assert.equal(card.$('pin').value,'');
const other=dom.window.document.createElement('lockly-management-card');other.setConfig({});
let requests=0;other.hass={user:{is_admin:false},callWS:()=>{requests++;}};
assert.equal(requests,0);assert.equal(other.$('editor').hidden,true);
console.log('Access-card DOM checks passed: media/microphone cleanup, no automatic camera, secret clearing, once-PINs, administrator gate, escaped names, protected owner, schedules and PIN clearing.');
