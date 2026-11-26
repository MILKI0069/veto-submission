// Veto web app. Everything here runs in the browser. The engine is imported straight from /engine.
import { analyze, rescore, redact, fuse, scriptStages, STAGES, PRE_ASK_WARNING, REPORTING, KB_VERSION, INSTITUTIONS } from '/engine/index.js';
import { checkListing } from '/engine/ledger.js';
import { QUIZ } from './quiz.js';
import { ACTIONS, TACTICS } from '/engine/lexicon.js';
import { t } from './i18n.js';
import { EXAMPLES, CALL_SCRIPTS } from './examples.js';
import { mountPet } from './pet.js';
import { icon } from './icons.js';

const $ = id => document.getElementById(id);
const store = {
  get(k, d) { try { return localStorage.getItem(k) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } }
};
const state = {
  lang: store.get('veto.lang', (navigator.language || '').startsWith('ar') ? 'ar' : 'en'),
  channel: 'sms', report: null, input: null, health: { xray: false, ai: false }, xrays: new Map(),
  // Session memory for scam-in-progress fusion. In memory only: gone when the tab closes.
  session: { recent: [] }
};
function remember(report, source) {
  const rec = state.session.recent;
  if (source === 'call') { const i = rec.findIndex(x => x.source === 'call'); if (i >= 0) rec.splice(i, 1); }
  rec.push({ t: Date.now(), report, source });
  if (rec.length > 20) rec.shift();
}
const T = (k, v) => t(state.lang, k, v);
const L = o => (o == null ? '' : typeof o === 'string' ? o : o[state.lang] ?? o.en ?? '');

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(Infinity)) if (c != null && c !== false) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}

// ---------------- static UI ----------------
const CHANNELS = ['sms', 'whatsapp', 'call', 'email', 'other'];
function renderStatic() {
  document.documentElement.lang = state.lang;
  document.documentElement.dir = state.lang === 'ar' ? 'rtl' : 'ltr';
  $('langBtn').replaceChildren(icon('languages'), state.lang === 'ar' ? 'EN' : 'ع');
  $('tagline').textContent = T('tagline');
  $('onDevice').textContent = T('onDevice');
  $('privacyBtn').setAttribute('aria-label', T('onDevice')); // the label text is hidden on phones
  $('privacyBtn').title = T('onDevice');
  $('tabCheck').replaceChildren(icon('message-square-text'), T('tabCheck'));
  $('tabCall').replaceChildren(icon('phone-call'), T('tabCall'));
  $('tabListing').replaceChildren(icon('map-pin'), T('tabListing'));
  $('qrBtn').replaceChildren(icon('qr-code'), T('qrBtn'));
  $('quizBtn').replaceChildren(icon('graduation-cap'), T('quizBtn'));
  $('lstTitle').replaceChildren(icon('map-pin'), T('lstTitle'));
  $('lstHelp').textContent = T('lstHelp');
  $('lstNameL').textContent = T('lstName'); $('lstName').placeholder = T('lstNamePh');
  $('lstPhoneL').textContent = T('lstPhone');
  $('lstSiteL').textContent = T('lstSite');
  $('lstBtn').replaceChildren(icon('shield-check'), T('check'));
  $('lstPrivacy').textContent = T('lstPrivacy');
  const ls = $('lstExample');
  ls.replaceChildren(h('option', { value: '' }, T('lstExamples')), ...LISTING_EXAMPLES.map((x, i) => h('option', { value: String(i) }, L(x.label))));
  $('msg').placeholder = T('placeholder');
  $('fromLabel').textContent = T('fromLabel');
  $('sender').placeholder = T('fromPh');
  $('pasteBtn').replaceChildren(icon('clipboard-paste'), T('paste'));
  $('clearBtn').replaceChildren(icon('eraser'), T('clear'));
  $('checkBtn').replaceChildren(icon('shield-check'), T('check'));
  const sel = $('exampleSel');
  sel.replaceChildren(h('option', { value: '' }, T('examples')), ...EXAMPLES.map(e => h('option', { value: e.id }, L(e.label))));
  $('chips').replaceChildren(...CHANNELS.map(c => h('button', {
    class: 'chip', type: 'button', role: 'radio', 'aria-checked': String(state.channel === c),
    onclick: () => { state.channel = c; renderStatic(); }
  }, T('ch_' + c))));
  $('callHelp').textContent = T('callHelp');
  $('callPrivacy').textContent = T('callPrivacy');
  $('listenBtn').replaceChildren(icon(call.listening ? 'square' : 'mic'), call.listening ? T('stop') : T('listen'));
  $('demoBtn').replaceChildren(icon('play'), T('demoCall'));
  $('codeBtn').replaceChildren(icon('lock'), T('gotCode'));
  $('demoAudioLabel').textContent = T('demoAudio');
  $('callRiskLabel').textContent = T('callRisk');
  $('modalClose').textContent = T('close');
  $('footer').textContent = T('footer');
  for (const id of ['ctxSummary', 'ctxContactsLabel', 'ctxSavedNameLabel', 'ctxHistoryLabel', 'ctxFirstLabel', 'ctxNewAccLabel', 'ctxVerifiedLabel', 'ctxSavedListLabel', 'ctxCallLabel', 'ctxBankLabel']) $(id).textContent = T(id);
  const opts = $('ctxContacts').options;
  opts[0].textContent = T('ctxUnknown'); opts[1].textContent = T('ctxYes'); opts[2].textContent = T('ctxNo');
  pet?.refresh();
  if (!call.lines.length) $('transcript').replaceChildren(h('p', { class: 'muted tiny' }, T('callIdle')));
  if (state.report) renderResult();
}

// ---------------- check ----------------
function runCheck() {
  const text = $('msg').value.trim();
  if (!text) { $('result').replaceChildren(h('div', { class: 'card muted' }, T('empty'))); return; }
  const mark = performance.now();
  state.input = { text, sender: $('sender').value.trim(), channel: state.channel, context: readContext() };
  state.report = fuse(analyze(state.input), state.session.recent);
  remember(state.report, 'message');
  state.netAfter = mark;
  state.xrays.clear();
  renderResult();
  petForReport(state.report);
  $('result').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ---------------- sender / phone context (filled automatically by the Android companion) ----------------
function parseSavedList(s) {
  return String(s || '').split(/\n+/).map(l => l.split(/[:：]/)).filter(p => p.length >= 2 && p[0].trim() && p[1].trim())
    .map(([name, ...rest]) => ({ name: name.trim(), number: rest.join(':').trim() }));
}
function readContext() {
  const ctx = {};
  const c = $('ctxContacts').value;
  if (c) ctx.inContacts = c === 'yes';
  if ($('ctxSavedName').value.trim()) ctx.savedName = $('ctxSavedName').value.trim();
  const hist = parseInt($('ctxHistory').value, 10);
  if (!Number.isNaN(hist)) ctx.priorMessages = hist;
  if ($('ctxFirst').checked) ctx.firstContact = true;
  if ($('ctxNewAcc').checked) ctx.accountNew = true;
  if ($('ctxVerified').checked) ctx.verifiedSender = true;
  else if (state.channel === 'whatsapp' && ctx.inContacts === false) ctx.verifiedSender = false;
  if (state.channel === 'whatsapp' || state.channel === 'sms') ctx.app = state.channel;
  const saved = parseSavedList($('ctxSavedList').value);
  if (saved.length) ctx.savedContacts = saved;
  if ($('ctxCall').value.trim()) ctx.onCall = { number: $('ctxCall').value.trim(), inContacts: false };
  if ($('ctxBank').checked) ctx.bankAppOpen = true;
  return Object.keys(ctx).length ? ctx : null;
}
function fillContext(ctx = {}) {
  $('ctxContacts').value = ctx.inContacts === true ? 'yes' : ctx.inContacts === false ? 'no' : '';
  $('ctxSavedName').value = ctx.savedName || '';
  $('ctxHistory').value = ctx.priorMessages ?? '';
  $('ctxFirst').checked = !!ctx.firstContact;
  $('ctxNewAcc').checked = !!ctx.accountNew;
  $('ctxVerified').checked = !!ctx.verifiedSender;
  $('ctxSavedList').value = ctx.savedList || $('ctxSavedList').value || '';
  $('ctxCall').value = ctx.onCallNumber || '';
  $('ctxBank').checked = !!ctx.bankAppOpen;
  $('ctxPanel').open = Object.keys(ctx).length > 0;
}
function contextChips(r) {
  const c = r.context;
  if (!c) return null;
  const chips = [];
  if (c.triage) chips.push(T(c.triage.mode === 'sleep' ? 'chipSleep' : c.triage.mode === 'light' ? 'chipLight' : 'chipWatch'));
  if (c.inContacts === false) chips.push(T('chipNotSaved'));
  if (c.country && c.country.code !== 'AE') chips.push(T('chipCountry', { c: L(c.country.name) }));
  if (c.firstContact) chips.push(T('chipFirst'));
  if (c.accountNew) chips.push(T('chipNewAcc'));
  if (c.verifiedSender === false) chips.push(T('chipUnverified'));
  if (c.onCall) chips.push(T('chipOnCall'));
  return chips.length ? h('div', { class: 'chips-ctx' }, chips.map(x => h('span', {}, x))) : null;
}

// ---------------- Kiki the pet: hidden, appears only when there is something to do ----------------
let pet = null;
function petForReport(r) {
  if (!pet) return;
  const trig = r.context?.triage;
  if (trig?.mode === 'sleep' && r.verdict === 'clear') return pet.hide(); // trusted chat: Kiki stays away
  if (r.verdict === 'scam') return pet.set('stop', L(r.reason || r.headline), 0);
  if (r.verdict === 'high' || r.verdict === 'caution') return pet.set('caution', L(r.reason || r.headline));
  if (r.verdict === 'otp') return pet.set('advising', `${T('otpTitle')}: ${L(r.otp.unlocks)}. ${T('neverShareCode')}`);
  const verified = r.positives.find(p => ['official_link', 'sender', 'history', 'phone'].includes(p.kind));
  if (verified) return pet.set('verified', L(verified));
  return pet.hide(); // nothing to do, the result card says it
}

const VERDICT_ICON = { scam: 'octagon-alert', high: 'shield-alert', caution: 'triangle-alert', otp: 'lock', clear: 'shield-check' };
const ICON = { stop: 'octagon-alert', lock: 'lock', phone: 'phone', link: 'link', device: 'smartphone', money: 'hand', report: 'siren', info: 'info' };

function renderResult() {
  const r = state.report;
  const out = [];
  const claims = r.claims.filter(c => !c.generic);
  out.push(h('div', { class: `verdict ${r.verdict}` },
    h('div', { class: 'icon' }, icon(VERDICT_ICON[r.verdict])),
    h('h2', {}, L(r.headline)),
    r.reason && r.verdict !== 'clear' ? h('p', {}, L(r.reason)) : null,
    r.verdict === 'clear' ? h('p', {}, L(r.next.find(n => n.icon === 'info'))) : null,
    claims.length ? h('div', { class: 'claims' }, `${T('claims')}: ${claims.map(c => L(c.name)).join(' · ')}`) : null,
    contextChips(r),
    r.verdict !== 'otp' ? h('div', { class: 'meter-row' }, h('span', {}, T('risk')), h('div', { class: 'meter' }, h('i', { style: `width:${Math.round(r.risk * 100)}%` })), h('b', {}, `${Math.round(r.risk * 100)}%`)) : null
  ));

  const st = scriptStages(r);
  if (st.count >= 2 && r.verdict !== 'otp') out.push(renderStages(st, true));
  if (r.otp) out.push(renderOtp(r.otp));

  const todo = r.next.filter(n => !(r.verdict === 'clear' && n.icon === 'info'));
  if (todo.length) {
    out.push(h('div', { class: 'card' }, h('h3', { class: 'section-title' }, T('whatToDo')),
      h('ul', { class: 'todo' }, todo.map(n => h('li', {}, h('span', { class: 'ic' }, icon(ICON[n.icon] || 'info')), h('span', {}, L(n)),
        n.tel ? h('a', { class: 'call', href: `tel:${n.tel}` }, icon('phone'), n.telLabel || n.tel) : null)))));
  }

  if (r.verdict !== 'clear') { const mk = markedMessage(state.input?.text || '', r.findings); if (mk) out.push(mk); }

  if (r.findings.length || r.positives.length) {
    out.push(h('div', { class: 'card' }, h('h3', { class: 'section-title' }, T('why')),
      r.findings.map(renderFinding),
      r.positives.length ? h('div', { class: 'positives' }, r.positives.map(p => h('div', {}, icon('circle-check'), L(p)))) : null));
  }

  const links = r.links.filter(l => !l.isEmail);
  if (links.length) out.push(h('div', { class: 'card' }, h('h3', { class: 'section-title' }, T('links')), links.map(renderLink)));

  if (r.playbook) {
    const pb = r.playbook[state.lang] || r.playbook.en;
    out.push(h('details', { class: 'card', open: r.verdict === 'caution' }, h('summary', {}, icon('info'), T('howWorks') + ': ' + pb.title),
      pb.common ? h('div', { class: 'seen' }, icon('users'), h('span', {}, h('b', {}, T('seenBefore') + ': '), pb.common)) : null,
      h('ol', {}, pb.steps.map(s => h('li', {}, s))),
      h('div', { class: 'tell' }, h('b', {}, T('theTell') + ': '), pb.tell),
      h('div', { class: 'tiny' }, h('b', {}, T('ifActed') + ': '), pb.acted)));
  }

  const tools = [];
  if (['scam', 'high', 'caution'].includes(r.verdict)) tools.push(h('button', { class: 'primary danger', type: 'button', onclick: openReport }, icon('siren'), T('report')));
  if (['scam', 'high'].includes(r.verdict)) tools.push(h('button', { class: 'ghost', type: 'button', onclick: () => warnFamily(r) }, icon('users'), T('warnFamily')));
  tools.push(h('button', { class: 'ghost', type: 'button', onclick: openAi, title: state.health.ai ? '' : T('aiOff') }, icon('sparkles'), T('aiCheck')));
  out.push(h('div', { class: 'card' }, h('div', { class: 'tools-row' }, tools)));

  const net = performance.getEntriesByType('resource').filter(e => e.startTime >= (state.netAfter || 0) && !/\/api\//.test(e.name)).length;
  out.push(h('div', { class: 'meta' },
    T('meta', { ms: r.meta.ms, kb: KB_VERSION, n: INSTITUTIONS.length }), ' · ',
    h('button', { type: 'button', onclick: showPrivacy }, icon('lock'), T('netProof', { n: net }))));
  $('result').replaceChildren(...out);
}

// The user's own message with the exact phrases that gave it away marked (evidence snippets from the engine).
function markedMessage(text, findings) {
  if (!text) return null;
  const low = text.toLowerCase();
  const ranges = [];
  for (const f of findings) {
    const ev = String(f.phrase || f.evidence || '').replace(/^…|…$/g, '').trim();
    if (ev.length < 3) continue;
    const i = low.indexOf(ev.toLowerCase());
    if (i >= 0) ranges.push([i, i + ev.length, f]);
  }
  if (!ranges.length) return null;
  ranges.sort((a, b) => a[0] - b[0]);
  const merged = [];
  for (const r of ranges) { const last = merged[merged.length - 1]; if (last && r[0] < last[1]) last[1] = Math.max(last[1], r[1]); else merged.push([...r]); }
  const parts = [];
  let pos = 0;
  for (const [a, b, f] of merged) {
    if (a > pos) parts.push(text.slice(pos, a));
    parts.push(h('mark', { class: f.severity || 'medium', title: L(f.title) }, text.slice(a, b)));
    pos = b;
  }
  parts.push(text.slice(pos));
  return h('div', { class: 'card' }, h('h3', { class: 'section-title' }, T('gaveAway')), h('p', { class: 'marked', dir: 'auto' }, parts),
    h('div', { class: 'tiny muted' }, T('gaveAwayHelp')));
}

function renderFinding(f) {
  return h('div', { class: `finding ${f.severity}` },
    h('div', { class: 'ft' }, L(f.title), f.id === 'ai' ? h('span', { class: 'badge ai' }, T('aiBadge')) : null,
      f.severity === 'critical' || f.severity === 'high' ? h('span', { class: `badge ${f.severity}` }, T('sev_' + f.severity)) : null),
    f.detail ? h('div', { class: 'fd' }, L(f.detail)) : null,
    f.evidence ? h('div', { class: 'ev' }, `${T('evidence')}: “${f.evidence}”`) : null,
    f.cite ? h('div', { class: 'src' }, `${T('source')}: `, h('a', { href: f.cite.url, target: '_blank', rel: 'noopener noreferrer' }, f.cite.title),
      f.cite.quote ? h('span', { class: 'quote' }, `“${f.cite.quote}”`) : null) : null);
}

function renderLink(l) {
  const key = l.href || l.raw;
  const box = h('div', { class: 'link-item' });
  const sigs = [...(l.signals || [])].filter(s => s.id !== 'ml_url').sort((a, b) => b.w - a.w).slice(0, 3);
  const badge = l.official ? h('span', { class: 'badge official' }, icon('circle-check'), `${T('official')} · ${L(l.official.name)}`)
    : l.risk >= 0.3 ? h('span', { class: 'badge unsafe' }, icon('triangle-alert'), T('unsafe')) : h('span', { class: 'badge' }, T('checkIt'));
  box.append(h('div', { class: 'host' }, icon('link'), h('span', {}, l.hostUnicode || l.host || l.raw), badge));
  for (const s of sigs) box.append(h('div', { class: 'sig' }, L(s)));
  // the on-device link model: how phishing-like the NAME is, and which parts of it made it so
  if (l.ml && !l.official) {
    const pct = Math.round(l.ml.p * 100);
    // red only when the model also found a brand being misused (its high-precision evidence); an odd name alone stays amber
    const tone = l.ml.p >= 0.8 && l.ml.brand ? 'bad' : l.ml.p >= 0.5 ? 'mid' : 'low';
    box.append(h('div', { class: `ml-line ${tone}`, title: T('mlHelp') },
      icon('brain'), h('span', { class: 'k' }, T('mlModel')),
      h('span', { class: 'meter', 'aria-hidden': 'true' }, h('i', { style: `width:${pct}%` })),
      h('b', {}, `${pct}%`),
      l.ml.why?.length && l.ml.p >= 0.5 ? h('span', { class: 'why' }, `${T('mlBecause')} ${l.ml.why.map(L).join(', ')}`) : null));
  }
  const xr = h('div', { class: 'xray-slot' });
  const btn = h('button', { class: 'ghost small', type: 'button', disabled: !state.health.xray, title: state.health.xray ? T('xrayHelp') : T('xrayUnavailable'),
    onclick: () => confirmXray(l, xr) }, icon('scan-search'), T('xray'));
  box.append(h('div', { class: 'row' }, btn, state.health.xray ? null : h('span', { class: 'tiny muted' }, T('xrayUnavailable'))));
  box.append(xr);
  if (state.xrays.has(key)) xr.replaceChildren(renderXray(state.xrays.get(key)));
  return box;
}

// ---------------- link X-ray ----------------
const PII_PARAM = /(e-?mail|phone|mobile|msisdn|name|user|uid|id|token|session|eid|card|acc(oun)?t?)/i;
function stripPersonal(href) {
  try {
    const u = new URL(/^[a-z]+:\/\//i.test(href) ? href : 'http://' + href);
    let removed = 0;
    for (const [k, v] of [...u.searchParams]) {
      if (PII_PARAM.test(k) || /@|\+?\d{9,}/.test(v)) { u.searchParams.delete(k); removed++; }
    }
    return { url: u.href, removed };
  } catch { return { url: href, removed: 0 }; }
}

function confirmXray(l, slot) {
  const original = l.href || l.raw;
  const stripped = stripPersonal(original);
  const pre = h('pre', {}, stripped.url);
  const cb = h('input', { type: 'checkbox', checked: true, onchange: e => { pre.textContent = e.target.checked ? stripped.url : original; } });
  openModal(h('div', {},
    h('h3', { class: 'modal-title' }, icon('scan-search'), T('xray')),
    h('p', { class: 'muted' }, T('xrayHelp')),
    pre,
    stripped.removed ? h('label', { class: 'toggle' }, cb, T('stripPII')) : null,
    h('div', { class: 'row actions' },
      h('button', { class: 'primary', type: 'button', onclick: () => { closeModal(); doXray(l, slot, pre.textContent); } }, icon('send'), T('sendLink')))));
}

async function doXray(l, slot, url) {
  const key = l.href || l.raw;
  slot.replaceChildren(h('div', { class: 'xray' }, h('span', { class: 'spinner' }), T('xraySending')));
  pet?.set('investigating', T('petXray'), 0);
  try {
    const res = await fetch('/api/xray', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url }) });
    const x = await res.json();
    state.xrays.set(key, x);
    slot.replaceChildren(renderXray(x));
    if (x.ok) {
      const top = x.signals?.[0];
      const m = { dangerous: 'stop', suspicious: 'caution', caution: 'caution', official: 'verified', no_signals: 'advising' }[x.verdict] || 'advising';
      const said = x.intent ? L(x.intent) : top ? L(top) : '';
      pet?.set(m, `${T('xv_' + x.verdict)}${said ? ': ' + said : ''}`, m === 'stop' ? 0 : undefined);
    } else pet?.set('advising', x.message || T('xrayUnavailable'));
    if (x.ok && x.signals?.length && state.report) {
      // fold page evidence into the message verdict (monotonic: only adds risk)
      const top = x.signals[0];
      const extra = x.signals.filter(s => s.w >= 0.5).map(s => ({ id: 'xray', key: `xray:${s.id}:${key}`, w: s.w,
        title: { en: `X-ray: ${s.en}`, ar: `الأشعة: ${s.ar}` }, detail: null }));
      if (extra.length && top) { state.report = rescore(state.report, extra); renderResult(); }
    }
  } catch {
    slot.replaceChildren(h('div', { class: 'xray muted' }, T('xrayUnavailable')));
  }
}

const XV_ICON = { dangerous: 'octagon-alert', suspicious: 'shield-alert', caution: 'triangle-alert', official: 'shield-check', no_signals: 'info' };
function renderXray(x) {
  if (!x.ok) return h('div', { class: 'xray' }, h('div', { class: 'xv caution' }, icon('scan-search'), x.message || x.error),
    x.static?.signals?.length ? x.static.signals.map(s => h('div', { class: 'sig tiny' }, L(s))) : null);
  const wants = x.intent ? h('div', { class: 'xwant' }, h('span', { class: 'k' }, icon('scan-search'), T('xrayWants')), L(x.intent)) : null;
  const sends = x.intent?.sendsTo ? h('div', { class: 'xsend' }, h('span', { class: 'k' }, icon('send'), T('xraySendsTo')), L(x.intent.sendsTo)) : null;
  const app = x.apk?.ok ? h('div', { class: `xapp${x.apk.trojanProfile ? ' bad' : ''}` },
    h('div', { class: 'k' }, icon(x.apk.trojanProfile ? 'bug' : 'smartphone'), T('xrayApp')),
    h('div', { class: 'app-name' }, `“${x.apk.label || x.apk.package || '?'}”`, h('span', { class: 'tiny muted' }, x.apk.package || '')),
    x.apk.trojanProfile ? h('div', { class: 'trojan' }, icon('octagon-alert'), T('xrayTrojan')) : null,
    x.apk.capabilities?.length ? h('ul', { class: 'powers' }, x.apk.capabilities.slice(0, 7).map(c => h('li', {}, icon('circle-x'), L(c)))) : h('div', { class: 'tiny muted' }, T('xrayAppNoPowers')),
    h('div', { class: 'tiny muted' }, `SHA-256 ${x.apk.sha256.slice(0, 16)}… · ${T('xrayAppStatic')}${x.intel?.bazaar?.known ? ' · MalwareBazaar: ' + (x.intel.bazaar.signature || 'known malware') : ''}`))
    : null;
  const facts = [];
  if (x.facts.asks.length) facts.push([icon('lock'), x.facts.asks.join(', ')]);
  if (x.facts.downloads.length) facts.push([icon('download'), `${x.facts.downloads.map(d => d.file).join(', ')} (blocked)`]);
  if (x.trap?.ran) facts.push([icon('zap'), `${T('xrayTrapRan')}${x.trap.caught.length ? '' : ': ' + T('xrayTrapNothing')}`]);
  if (x.facts.domainAgeDays != null) facts.push([icon('globe'), `${x.facts.domainAgeDays} days old`]);
  if (x.facts.tls) facts.push([icon('lock'), `${x.facts.tls.protocol || 'TLS'} · ${x.facts.tls.issuer}`]);
  facts.push([icon('radar'), `${x.facts.requests} requests · ${x.facts.thirdPartyHosts} other sites`]);
  // the page picture with a frosted verdict card laid over it (glass, like a photo caption)
  const shot = x.screenshot ? h('div', { class: `phone ${x.verdict}` },
    h('img', { src: x.screenshot, alt: T('xrayPicture') }),
    h('span', { class: 'stamp' }, icon('eye'), state.lang === 'ar' ? 'صورة فقط' : 'picture only'),
    h('div', { class: 'shot-overlay' },
      h('div', { class: 'so-top' }, h('span', { class: `xv ${x.verdict}` }, icon(XV_ICON[x.verdict] || 'info'), T('xv_' + x.verdict)), h('b', {}, `${Math.round(x.risk * 100)}%`)),
      h('div', { class: 'so-host' }, icon('globe'), x.finalHost || ''))) : h('div', { class: 'phone empty' }, icon('wifi-off'));
  return h('div', { class: 'xray' },
    h('div', { class: 'xray-grid' },
      shot,
      h('div', { class: 'xray-body' },
        x.title ? h('div', { class: 'tiny muted page-title' }, `“${x.title}”`) : null,
        wants, sends, app,
        h('ul', { class: 'sigs' }, x.signals.slice(0, 6).map(s => h('li', {}, L(s)))),
        h('div', { class: 'chain-title' }, T('xrayChain')),
        h('div', { class: 'chain' }, x.chain.map(c => h('div', {}, c))),
        h('div', { class: 'facts' }, facts.map(f => h('span', {}, ...f))),
        renderForensics(x),
        h('div', { class: 'sandbox-note' }, icon('shield-check'), `${T('xrayPicture')} ${T('xraySandbox')} · ${x.sandbox?.browser?.channel || ''} ${x.sandbox?.browser?.version || ''} · ${x.ms} ms`))));
}

// "Evidence for investigators": the forensic layer of the X-ray (copied logo, cloaking, kit print,
// campaign keys, who runs the domain and the server, where a takedown request goes)
const KEY_LABEL = { analytics: 'Analytics ID', pixel: 'Ad pixel', metrika: 'Metrika', telegram_bot: 'Telegram bot', telegram: 'Telegram', whatsapp: 'WhatsApp', wallet: 'Wallet', email: 'E-mail', phone: 'Phone' };
function renderForensics(x) {
  const f = x.forensics;
  if (!f) return null;
  const rows = [];
  const row = (ic, k, ...v) => rows.push(h('div', { class: 'fx-row' }, h('span', { class: 'fx-k' }, icon(ic), T(k)), h('div', { class: 'fx-v' }, ...v)));
  if (f.logos?.length) {
    const l = f.logos[0];
    row('image', 'fxLogo', h('b', {}, L(l.name)), ` · ${l.kind === 'favicon' ? T('fxTabIcon') : T('fxLogoPic')} · ${l.exact ? T('fxIdentical') : T('fxNear')} · ${T('fxRealOn')} ${l.domain}`);
  }
  const c = f.cloaking;
  if (c && c.verdict !== 'inconclusive') {
    const view = v => !v ? '?' : v.ok ? `${v.finalHost || ''}${v.secrets ? ` · ${v.secrets} ${T('fxSecretFields')}` : ''}` : `HTTP ${v.status || v.error || '?'}`;
    row(c.verdict === 'cloaked' ? 'eye-off' : 'eye', 'fxCloak',
      h('div', { class: c.verdict === 'cloaked' ? 'fx-bad' : '' }, c.verdict === 'cloaked' ? T('fxCloaked') : T('fxSameForAll')),
      h('div', { class: 'tiny muted' }, `${T('fxPhone')}: ${view(c.phone)} | ${T('fxComputer')}: ${view(c.computer)} | ${T('fxCrawler')}: ${view(c.crawler)}`));
  }
  if (x.campaign?.size > 1) row('waypoints', 'fxCampaignK', h('div', { class: 'fx-bad' }, `${T('fxCampaign')} ${x.campaign.size - 1} ${T('fxOtherSites')}`),
    h('div', { class: 'tiny muted' }, [...new Set((x.campaign.links || []).map(l => `${L(l)}: ${l.value}`))].slice(0, 3).join(' · ')));
  if (f.kit?.simhash) row('fingerprint', 'fxKit', h('code', {}, f.kit.simhash), ` · ${f.kit.tokens} ${T('fxElements')}${f.kit.fields ? ` · ${f.kit.fields} ${T('fxFields')}` : ''}`);
  const keys = Object.entries(f.keys || {}).flatMap(([k, vs]) => vs.map(v => h('span', { class: 'chip-key' }, `${KEY_LABEL[k] || k}: ${k === 'whatsapp' ? '+' + v : v}`)));
  if (keys.length) row('hash', 'fxKeys', h('div', { class: 'chips' }, keys.slice(0, 10)));
  const d = f.infra?.domain, s = f.infra?.host;
  if (d || s) row('server', 'fxInfra',
    d ? h('div', {}, `${T('fxRegistrar')}: ${d.registrar || '?'}${d.created ? ` · ${T('fxCreated')} ${d.created.slice(0, 10)}` : ''}${d.abuseEmail ? ` · ${d.abuseEmail}` : ''}`) : null,
    s ? h('div', {}, `${T('fxHost')}: ${s.asName || s.network || '?'}${s.asn ? ` (AS${s.asn})` : ''}${s.country ? ` · ${s.country}` : ''} · ${s.ip}`) : null,
    d?.nameservers?.length ? h('div', { class: 'tiny muted' }, `DNS: ${d.nameservers.join(', ')}`) : null);
  if (f.favicon) row('search', 'fxShodan', h('code', {}, `http.favicon.hash:${f.favicon.shodan}`));
  if (f.takedown?.length) row('gavel', 'fxTakedown', h('ul', { class: 'fx-take' }, f.takedown.slice(0, 6).map(t => h('li', {},
    h('b', {}, t.name), t.email ? ` · ${t.email}` : '', t.url ? [' · ', h('a', { href: t.url, target: '_blank', rel: 'noopener noreferrer' }, T('fxReportForm'))] : '', h('span', { class: 'tiny muted' }, ` (${t.why})`)))));
  if (!rows.length) return null;
  const caseLink = x.caseId ? h('a', { class: 'btn ghost small', href: `/api/dossier/${x.caseId}`, target: '_blank', rel: 'noopener' }, icon('file-text'), T('fxDossier')) : null;
  return h('details', { class: 'forensics' }, h('summary', {}, icon('gavel'), T('fxTitle')), ...rows, caseLink ? h('div', { class: 'row' }, caseLink) : null);
}

// ---------------- scam-script stages ----------------
function renderStages(st, compact = false) {
  const chips = STAGES.map((s, i) => h('span', { class: `stage${st.reached[s.id] ? ' on' : ''}${s.id === 'ask' && st.preAsk ? ' next' : ''}` },
    `${i + 1}. ${L(s.label)}`));
  return h('div', { class: compact ? 'card stages-card' : 'stages-wrap' },
    compact ? h('div', { class: 'tiny muted' }, T('stagesTitle')) : null,
    h('div', { class: 'stages' }, chips));
}

// ---------------- warn a family member ----------------
function warnFamily(r) {
  const who = r.claims.find(c => !c.generic) || r.claims[0];
  const ask = r.findings.find(f => f.action)?.action;
  const text = T('familyMsg', { who: who ? L(who.name) : T('someone'), ask: ask ? L(ACTIONS[ask].label) : T('askSomething') });
  if (navigator.share) navigator.share({ text }).catch(() => {});
  else window.open(`https://wa.me/?text=${encodeURIComponent(text)}`, '_blank', 'noopener');
}

// ---------------- OTP ----------------
function renderOtp(o) {
  return h('div', { class: 'card otp-card' },
    h('h3', { class: 'section-title' }, h('span', {}, icon('lock'), T('otpTitle'))),
    h('div', { class: 'otp-code' }, o.masked),
    h('div', { class: 'otp-unlocks' }, L(o.unlocks)),
    h('div', {}, h('b', {}, T('otpWho') + ': '), L(o.risk)),
    o.riskyMerchant ? h('div', { class: 'tell' }, icon('triangle-alert'), T('otpRisky')) : null,
    o.requested ? h('div', { class: 'tell' }, icon('octagon-alert'), T('otpRequested')) : null);
}

// ---------------- AI deep check ----------------
function openAi() {
  if (!state.health.ai) { openModal(h('div', {}, h('h3', { class: 'modal-title' }, icon('sparkles'), T('aiCheck')), h('p', {}, T('aiOff')))); return; }
  const red = redact(state.input.text);
  openModal(h('div', {},
    h('h3', { class: 'modal-title' }, icon('sparkles'), T('aiCheck')),
    h('p', { class: 'muted' }, T('aiConsent')),
    h('pre', {}, red.text),
    h('p', { class: 'tiny muted' }, T('aiRemoved', { n: red.removed })),
    h('div', { class: 'row actions' }, h('button', { class: 'primary', type: 'button', onclick: () => { closeModal(); doAi(red.text); } }, T('send')))));
}

async function doAi(text) {
  const box = h('div', { class: 'card' }, h('span', { class: 'spinner' }), T('aiWorking'));
  pet?.set('thinking', T('petThinking'), 0);
  $('result').prepend(box);
  try {
    const res = await fetch('/api/ai', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text, channel: state.input.channel }) });
    const ai = await res.json();
    box.remove();
    if (ai.error || ai.refused) { openModal(h('p', {}, ai.message || ai.error || 'AI declined this request.')); return; }
    const have = new Set(state.report.actions);
    const extra = [];
    for (const a of ai.requested_actions || []) if (!have.has(a) && ACTIONS[a]) {
      extra.push({ id: 'ai', key: `ai:action:${a}`, w: 0.6, title: { en: `Asks you to ${ACTIONS[a].label.en}.`, ar: `يطلب منك ${ACTIONS[a].label.ar}.` }, detail: null });
    }
    for (const tc of ai.tactics || []) if (!state.report.tactics.includes(tc) && TACTICS[tc]) {
      extra.push({ id: 'ai', key: `ai:tactic:${tc}`, w: 0.2, title: TACTICS[tc].label, detail: null });
    }
    if (ai.risk >= 0.5) extra.push({ id: 'ai', key: 'ai:overall', w: Math.min(0.7, ai.risk), title: { en: `${T('aiSays')}: ${ai.explanation_en}`, ar: `${t('ar', 'aiSays')}: ${ai.explanation_ar}` }, detail: null });
    state.report = rescore(state.report, extra);
    state.report.ai = ai;
    renderResult();
    petForReport(state.report);
    if (ai.risk < 0.5) $('result').prepend(h('div', { class: 'card' }, h('b', {}, icon('sparkles'), T('aiSays') + ': '), state.lang === 'ar' ? ai.explanation_ar : ai.explanation_en));
  } catch {
    box.replaceChildren(T('aiOff'));
    if (state.report) petForReport(state.report);
  }
}

// ---------------- police report ----------------
function buildReport() {
  const r = state.report;
  const red = redact(state.input.text, { keepPhones: true });
  const lines = [
    `Veto scam report, ${new Date().toLocaleString('en-GB', { timeZone: 'Asia/Dubai' })} (UAE time)`,
    `Channel: ${state.input.channel}${state.input.sender ? ` · From: ${state.input.sender}` : ''}`,
    `Verdict: ${r.headline.en} Risk ${Math.round(r.risk * 100)}%${r.playbook ? `, ${r.playbook.en.title}` : ''}`,
    r.claims.filter(c => !c.generic).length ? `Pretends to be: ${r.claims.filter(c => !c.generic).map(c => c.name.en).join(', ')}` : null,
    'Why:', ...r.findings.slice(0, 6).map(f => ` - ${f.title.en}`),
    r.links.length ? `Links: ${r.links.map(l => l.raw).join('  ')}` : null,
    r.phones.length ? `Phone numbers in message: ${r.phones.map(p => p.raw).join(', ')}` : null,
    'Message (card numbers, IDs, IBANs, e-mails and codes removed):', `"${red.text}"`,
    '', 'Sent by the recipient using Veto. Report channels: Abu Dhabi Police Aman 800 2626 / SMS 2828 / aman@adpolice.gov.ae · Dubai Police 901 / ecrime.ae'
  ].filter(x => x != null);
  return lines.join('\n');
}

function openReport() {
  const text = buildReport();
  const copyBtn = h('button', { class: 'ghost', type: 'button', onclick: async () => { try { await navigator.clipboard.writeText(text); copyBtn.textContent = T('copied'); } catch { /* ignore */ } } }, '📋 ' + T('copy'));
  const aman = REPORTING.find(x => x.id === 'aman');
  openModal(h('div', {},
    h('h3', { class: 'modal-title' }, icon('siren'), T('reportTitle')),
    h('pre', {}, text),
    h('div', { class: 'row actions wrap' },
      copyBtn,
      navigator.share ? h('button', { class: 'ghost', type: 'button', onclick: () => navigator.share({ title: 'Scam report', text }).catch(() => {}) }, icon('share-2'), T('share')) : null,
      h('a', { class: 'ghost', href: `tel:${aman.phone}` }, icon('phone'), T('callAman')),
      h('a', { class: 'ghost', href: `sms:${aman.sms}?body=${encodeURIComponent(text.slice(0, 600))}` }, icon('message-square-text'), T('smsAman')),
      h('a', { class: 'ghost', href: `mailto:${aman.email}?subject=${encodeURIComponent('Scam report (Veto)')}&body=${encodeURIComponent(text)}` }, icon('send'), T('emailAman')),
      h('a', { class: 'ghost', href: 'https://www.ecrime.ae', target: '_blank', rel: 'noopener noreferrer' }, icon('globe'), T('dxb')))));
}

// ---------------- modal / privacy ----------------
function openModal(content) { $('modalBody').replaceChildren(content); $('modal').showModal(); }
function closeModal() { $('modal').close(); }
function showPrivacy() {
  openModal(h('div', {}, h('h3', { class: 'modal-title' }, icon('lock'), T('privacyTitle')), h('p', {}, T('privacyHelp')),
    state.report ? h('p', { class: 'tiny muted' }, T('netProof', { n: performance.getEntriesByType('resource').filter(e => e.startTime >= (state.netAfter || 0) && !/\/api\//.test(e.name)).length })) : null));
}

// ---------------- live call guard ----------------
const call = { listening: false, rec: null, lines: [], interim: '', alerted: new Set(), demoTimer: null };
const SR = window.SpeechRecognition || window.webkitSpeechRecognition;

function renderCall() {
  const tr = $('transcript');
  const items = call.lines.map(l => h('div', { class: `bubble ${l.who}${l.flag ? ' flag' : ''}` }, h('span', { class: 'who' }, T(l.who === 'you' ? 'you' : 'caller')), l.text));
  if (call.interim) items.push(h('div', { class: 'bubble caller interim' }, call.interim));
  tr.replaceChildren(...(items.length ? items : [h('p', { class: 'muted tiny' }, T('callIdle'))]));
  tr.scrollTop = tr.scrollHeight;
}

function evaluateCall() {
  const callerText = call.lines.filter(l => l.who !== 'you').map(l => l.text).join('\n') + (call.interim ? '\n' + call.interim : '');
  if (!callerText.trim()) return;
  const r = fuse(analyze({ text: callerText, channel: 'call' }), state.session.recent.filter(x => x.source !== 'call'));
  remember(r, 'call');
  call.report = r;
  const st = scriptStages(r);
  $('stages').replaceChildren(renderStages(st));
  if (st.preAsk && !call.alerted.size && !call.preWarned) {
    call.preWarned = true;
    const who = r.claims.find(c => !c.generic);
    $('callAlert').hidden = false;
    $('callAlert').className = 'call-alert pre';
    $('callAlert').replaceChildren(...[h('h2', {}, icon('triangle-alert'), T('preAskTitle')), h('p', {}, L(PRE_ASK_WARNING)),
      who?.phones?.[0] ? h('p', {}, icon('phone'), `${L(who.name)}: ${who.phones[0].d}`) : null].filter(Boolean));
    pet?.set('caution', T('preAskTitle'), 0);
    try { navigator.vibrate?.([200, 100, 200]); } catch { /* ignore */ }
  }
  $('callMeter').style.width = `${Math.round(r.risk * 100)}%`;
  $('callMeter').style.background = r.risk >= 0.85 ? 'var(--scam)' : r.risk >= 0.6 ? 'var(--high)' : r.risk >= 0.3 ? 'var(--caution)' : 'var(--brand2)';
  $('callRiskPct').textContent = `${Math.round(r.risk * 100)}%`;
  const crit = r.findings.filter(f => f.w >= 0.85);
  const fresh = crit.filter(f => !call.alerted.has(f.key));
  if (fresh.length) {
    fresh.forEach(f => call.alerted.add(f.key));
    const last = call.lines.filter(l => l.who !== 'you').at(-1);
    if (last) last.flag = true;
    const f = fresh.find(x => x.id === 'fusion') || fresh[0];
    showCallAlert(r, f);
    try { navigator.vibrate?.([300, 120, 300, 120, 600]); } catch { /* ignore */ }
    beep();
    renderCall();
  }
}

function showCallAlert(r, f) {
  pet?.set('stop', `${T('hangUp')}, ${L(f.title)}`, 0);
  $('callAlert').hidden = false;
  $('callAlert').className = 'call-alert';
  $('callAlert').replaceChildren(...[
    h('h2', {}, icon('octagon-alert'), T('hangUp')),
    h('p', {}, h('b', {}, L(f.title))),
    f.detail ? h('p', {}, L(f.detail)) : null,
    r.next.find(n => n.icon === 'phone') ? h('p', {}, L(r.next.find(n => n.icon === 'phone'))) : null,
    f.cite ? h('div', { class: 'src' }, `${T('source')}: `, h('a', { href: f.cite.url, target: '_blank', rel: 'noopener noreferrer' }, f.cite.title)) : null,
    h('div', { class: 'row actions' }, h('button', { class: 'ghost small', type: 'button', onclick: () => warnFamily(r) }, icon('users'), T('warnFamily')))
  ].filter(Boolean));
}

// "I just got a code" during a call: fuse the real OTP with the caller's claims.
function openCodeCheck() {
  const ta = h('textarea', { rows: 4, dir: 'auto', placeholder: T('codePh'), style: 'width:100%;border:1px solid var(--line);border-radius:12px;padding:10px;font-size:15px' });
  openModal(h('div', {},
    h('h3', { class: 'modal-title' }, icon('lock'), T('gotCode')),
    h('p', { class: 'muted' }, T('gotCodeHelp')),
    ta,
    h('div', { class: 'row actions' }, h('button', { class: 'primary', type: 'button', onclick: () => {
      const text = ta.value.trim();
      if (!text) return;
      closeModal();
      const r = fuse(analyze({ text, channel: 'sms' }), state.session.recent);
      remember(r, 'otp');
      const fz = r.findings.find(x => x.id === 'fusion');
      if (fz) { call.alerted.add(fz.key); showCallAlert(r, fz); beep(); try { navigator.vibrate?.([300, 120, 600]); } catch { /* ignore */ } }
      else if (r.otp) {
        pet?.set('advising', `${L(r.otp.unlocks)}. ${T('neverShareCode')}`, 0);
        $('callAlert').hidden = false; $('callAlert').className = 'call-alert pre';
        $('callAlert').replaceChildren(h('h2', {}, icon('lock'), L(r.otp.unlocks)), h('p', {}, L(r.otp.risk)), h('p', {}, T('neverShareCode')));
      }
      evaluateCall();
    } }, T('checkCode')))));
  setTimeout(() => ta.focus(), 50);
}

function beep() {
  try {
    const ac = new (window.AudioContext || window.webkitAudioContext)();
    [0, 0.28, 0.56].forEach(at => {
      const o = ac.createOscillator(), g = ac.createGain();
      o.frequency.value = 880; o.connect(g); g.connect(ac.destination);
      g.gain.setValueAtTime(0.0001, ac.currentTime + at);
      g.gain.exponentialRampToValueAtTime(0.25, ac.currentTime + at + 0.02);
      g.gain.exponentialRampToValueAtTime(0.0001, ac.currentTime + at + 0.22);
      o.start(ac.currentTime + at); o.stop(ac.currentTime + at + 0.25);
    });
  } catch { /* no audio */ }
}

function resetCall() {
  call.lines = []; call.interim = ''; call.alerted.clear(); call.preWarned = false;
  $('callAlert').hidden = true;
  $('stages').replaceChildren(renderStages({ reached: {}, preAsk: false }));
  $('callMeter').style.width = '0%'; $('callRiskPct').textContent = '0%';
  renderCall();
}

function toggleListen() {
  if (call.listening) { call.rec?.stop(); return; }
  if (!SR) { $('callAlert').hidden = false; $('callAlert').replaceChildren(h('p', {}, T('noSpeech'))); return; }
  resetCall();
  const rec = new SR();
  rec.lang = state.lang === 'ar' ? 'ar-AE' : 'en-AE';
  rec.continuous = true;
  rec.interimResults = true;
  if ('processLocally' in rec) { try { rec.processLocally = true; } catch { /* not available */ } }
  rec.onresult = e => {
    call.interim = '';
    for (let i = e.resultIndex; i < e.results.length; i++) {
      const res = e.results[i];
      if (res.isFinal) call.lines.push({ who: 'caller', text: res[0].transcript.trim() });
      else call.interim += res[0].transcript;
    }
    renderCall(); evaluateCall();
  };
  rec.onend = () => { call.listening = false; $('listenBtn').classList.remove('listening'); renderStatic(); };
  rec.onerror = ev => { if (ev.error === 'not-allowed' || ev.error === 'service-not-allowed') { $('callAlert').hidden = false; $('callAlert').replaceChildren(h('p', {}, T('noSpeech'))); } };
  call.rec = rec;
  call.listening = true;
  pet?.set('listening', T('petListening'));
  rec.start();
  $('listenBtn').classList.add('listening');
  renderStatic();
}

function playDemoCall() {
  clearTimeout(call.demoTimer);
  speechSynthesis?.cancel?.();
  resetCall();
  const script = CALL_SCRIPTS[state.lang] || CALL_SCRIPTS.en;
  const speak = $('demoAudio').checked && 'speechSynthesis' in window;
  pet?.set('listening', T('petListening'));
  let i = 0;
  const next = () => {
    if (i >= script.length) return;
    const [who, text] = script[i++];
    call.lines.push({ who, text });
    renderCall(); evaluateCall();
    if (speak) {
      const u = new SpeechSynthesisUtterance(text);
      u.lang = state.lang === 'ar' ? 'ar-AE' : 'en-GB';
      u.rate = 1.05;
      u.onend = () => { call.demoTimer = setTimeout(next, 350); };
      speechSynthesis.speak(u);
    } else call.demoTimer = setTimeout(next, 1700);
  };
  next();
}

// ---------------- listing check (Google Maps, search results, flyers) ----------------
// Fake listings keep the institution's NAME and swap in the criminal's number or website. The check runs on
// the device against the official ledger (engine/ledger.js): nothing is sent anywhere.
const LISTING_EXAMPLES = [
  { label: { en: 'Maps: "Emirates NBD Customer Care 24/7" with a mobile number', ar: 'خرائط: «خدمة عملاء الإمارات دبي الوطني 24/7» برقم متحرك' }, name: 'Emirates NBD Customer Care 24/7', phone: '+971 52 318 4407', site: '' },
  { label: { en: 'Search ad: "ADCB card refund" with its own website', ar: 'إعلان بحث: «استرداد بطاقة ADCB» بموقع خاص' }, name: 'ADCB Card Refund Center', phone: '04 330 1288', site: 'https://adcb-refund-uae.com/claim' },
  { label: { en: 'Flyer: "Abu Dhabi Police fines" with a WhatsApp link', ar: 'منشور: «مخالفات شرطة أبوظبي» برابط واتساب' }, name: 'Abu Dhabi Police traffic fines', phone: '', site: 'https://wa.me/971501239876' },
  { label: { en: 'The real Emirates NBD listing', ar: 'الإدراج الحقيقي لبنك الإمارات دبي الوطني' }, name: 'Emirates NBD', phone: '600 54 0000', site: 'https://www.emiratesnbd.com/en' }
];
function runListing() {
  const r = checkListing({ name: $('lstName').value, phone: $('lstPhone').value.trim(), website: $('lstSite').value.trim() });
  const out = $('lstResult');
  if (!r.inst && !r.signals.length && !r.positives.length) { out.replaceChildren(h('div', { class: 'card muted' }, icon('info'), T('lstUnknown'))); return; }
  const tone = r.verdict === 'fake' ? 'scam' : r.verdict === 'suspicious' ? 'high' : r.verdict === 'official' ? 'clear' : 'caution';
  const ico = { fake: 'octagon-alert', suspicious: 'shield-alert', official: 'shield-check', unknown: 'info', guide: 'info' }[r.verdict];
  out.replaceChildren(h('div', { class: `listing-result ${r.verdict}` },
    h('div', { class: `verdict ${tone}` }, h('div', { class: 'icon' }, icon(ico)), h('h2', {}, T('lst_' + r.verdict)), r.inst ? h('p', {}, `${T('lstClaims')} ${L(r.inst.name)}`) : null),
    r.signals.length ? h('ul', { class: 'sigs' }, r.signals.map(s => h('li', {}, L(s)))) : null,
    r.positives.length ? h('ul', { class: 'sigs ok' }, r.positives.map(p => h('li', {}, icon('circle-check'), L(p)))) : null,
    r.official ? h('div', { class: 'official-box' }, h('div', { class: 'k' }, icon('badge-check'), `${T('lstOfficial')} ${L(r.inst.name)}`),
      r.official.phones.length ? h('div', {}, icon('phone'), r.official.phones.map(p => p.display).join(' · ')) : null,
      r.official.domains.length ? h('div', {}, icon('globe'), r.official.domains.join(' · ')) : null,
      h('div', { class: 'tiny muted' }, T('lstAdvice'))) : null));
}

// ---------------- "Test yourself": scam or not? ----------------
function startQuiz() {
  const items = [...QUIZ].sort(() => Math.random() - 0.5);
  let i = 0, score = 0;
  const bubble = q => h('div', { class: 'quiz-bubble' }, h('span', { class: 'tiny muted' }, q.channel === 'whatsapp' ? 'WhatsApp' : 'SMS'), h('p', { dir: 'auto' }, q.text));
  const step = () => {
    const q = items[i];
    openModal(h('div', { class: 'quiz' },
      h('div', { class: 'quiz-top' }, h('b', {}, T('quizTitle')), h('span', { class: 'tiny muted' }, `${i + 1} / ${items.length}`)),
      bubble(q),
      h('div', { class: 'row actions' },
        h('button', { class: 'primary danger', type: 'button', onclick: () => answer(true) }, icon('octagon-alert'), T('quizScam')),
        h('button', { class: 'ghost', type: 'button', onclick: () => answer(false) }, icon('circle-check'), T('quizSafe')))));
  };
  const answer = guess => {
    const q = items[i];
    const r = analyze({ text: q.text, channel: q.channel });
    const right = guess === q.scam;
    if (right) score++;
    const top = [...r.findings].sort((a, b) => b.w - a.w)[0];
    openModal(h('div', { class: 'quiz' },
      h('div', { class: `quiz-verdict ${right ? 'ok' : 'bad'}` }, icon(right ? 'circle-check' : 'circle-x'), right ? T('quizRight') : T('quizWrong')),
      bubble(q),
      h('p', {}, h('b', {}, q.scam ? T('quizWasScam') : T('quizWasSafe')), ' ', q.scam ? L(top ? top.title : r.headline) : T('quizSafeWhy')),
      h('div', { class: 'row actions' }, h('button', { class: 'primary', type: 'button', onclick: () => { i++; if (i < items.length) step(); else finish(); } },
        icon('chevron-right'), i + 1 < items.length ? T('quizNext') : T('quizDone')))));
  };
  const finish = () => openModal(h('div', { class: 'quiz' },
    h('h3', { class: 'modal-title' }, icon('trophy'), `${score} / ${items.length}`),
    h('p', {}, score === items.length ? T('quizPerfect') : T('quizScore')),
    h('p', { class: 'quiz-rule' }, T('quizRule')),
    h('div', { class: 'row actions' }, h('button', { class: 'primary', type: 'button', onclick: closeModal }, T('quizClose')))));
  step();
}

// ---------------- QR codes in pictures ("quishing") ----------------
async function scanQr(file) {
  if (!file) return;
  try {
    if (!('BarcodeDetector' in window)) throw new Error('nodetector');
    const bmp = await createImageBitmap(file);
    const codes = await new window.BarcodeDetector({ formats: ['qr_code'] }).detect(bmp);
    if (!codes.length) { openModal(h('div', {}, h('h3', { class: 'modal-title' }, icon('qr-code'), T('qrBtn')), h('p', {}, T('qrNone')))); return; }
    const v = codes.map(c => c.rawValue).join('\n');
    $('msg').value = `${T('qrPrefix')} ${v}`;
    state.channel = 'other';
    renderStatic();
    runCheck();
  } catch {
    openModal(h('div', {}, h('h3', { class: 'modal-title' }, icon('qr-code'), T('qrBtn')), h('p', {}, T('qrUnsupported'))));
  }
}

// ---------------- wiring ----------------
function setView(v) {
  $('viewCheck').hidden = v !== 'check';
  $('viewCall').hidden = v !== 'call';
  $('viewListing').hidden = v !== 'listing';
  $('tabCheck').setAttribute('aria-selected', String(v === 'check'));
  $('tabCall').setAttribute('aria-selected', String(v === 'call'));
  $('tabListing').setAttribute('aria-selected', String(v === 'listing'));
}

async function init() {
  pet = mountPet($('pet'), () => state.lang);
  renderStatic();
  $('langBtn').onclick = () => { state.lang = state.lang === 'ar' ? 'en' : 'ar'; store.set('veto.lang', state.lang); renderStatic(); };
  $('privacyBtn').onclick = showPrivacy;
  $('tabCheck').onclick = () => setView('check');
  $('tabCall').onclick = () => setView('call');
  $('tabListing').onclick = () => setView('listing');
  $('lstBtn').onclick = runListing;
  for (const id of ['lstName', 'lstPhone', 'lstSite']) $(id).addEventListener('keydown', e => { if (e.key === 'Enter') runListing(); });
  $('lstExample').onchange = e => {
    const x = LISTING_EXAMPLES[Number(e.target.value)];
    if (!x) return;
    $('lstName').value = x.name; $('lstPhone').value = x.phone; $('lstSite').value = x.site; e.target.value = '';
    runListing();
  };
  $('qrBtn').onclick = () => $('qrFile').click();
  $('quizBtn').onclick = startQuiz;
  $('qrFile').onchange = e => { scanQr(e.target.files[0]); e.target.value = ''; };
  $('checkBtn').onclick = runCheck;
  $('clearBtn').onclick = () => { $('msg').value = ''; $('sender').value = ''; fillContext({}); state.report = null; $('result').replaceChildren(); pet.hide(); $('msg').focus(); };
  $('msg').addEventListener('keydown', e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) runCheck(); });
  $('pasteBtn').onclick = async () => { try { $('msg').value = await navigator.clipboard.readText(); runCheck(); } catch { $('msg').focus(); } };
  $('exampleSel').onchange = e => {
    const ex = EXAMPLES.find(x => x.id === e.target.value);
    if (!ex) return;
    $('msg').value = ex.text; $('sender').value = ex.sender || ''; state.channel = ex.channel; e.target.value = '';
    fillContext(ex.context || {});
    renderStatic(); runCheck();
  };
  $('listenBtn').onclick = toggleListen;
  $('demoBtn').onclick = playDemoCall;
  $('codeBtn').onclick = openCodeCheck;
  $('stages').replaceChildren(renderStages({ reached: {}, preAsk: false }));

  // Android share-sheet / deep link: /share?text=...  or  /?text=...
  // iPhone Shortcut ("Check with Veto" in the share sheet): /#text=...  The part after # never leaves the
  // phone (browsers don't send it to the server), so the shared message is only checked on the device.
  const q = new URLSearchParams(location.search);
  const readShared = (withQuery = true) => {
    const hq = new URLSearchParams(location.hash.replace(/^#/, ''));
    const shared = [...(withQuery ? [q.get('title'), q.get('text'), q.get('url')] : []), hq.get('text')].filter(Boolean).join('\n');
    if (!shared) return;
    setView('check');
    $('msg').value = shared; runCheck(); history.replaceState(null, '', '/resident');
  };
  readShared();
  window.addEventListener('hashchange', () => { if (/^#text=/.test(location.hash)) readShared(false); }); // Safari tab already open
  if (q.get('view') === 'call') setView('call');

  try {
    const res = await fetch('/api/health');
    state.health = await res.json();
  } catch { state.health = { xray: false, ai: false }; }
  if (state.report) renderResult();

  if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost')) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }
}
init();
