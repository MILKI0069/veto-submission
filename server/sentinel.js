// Veto Sentinel: finds scam sites BEFORE the scam messages go out, and proves what they are.
//
//  1. Look-alike names. Every plausible misspelling of each official domain (missing, doubled, swapped or
//     neighbouring keys, look-alike letters, hyphens), the brand on other endings (.com, .top, .online …) and
//     "brand + word" names (emiratesnbd-verify, salik-refund …). Each is checked in DNS: registered or not.
//  2. Certificate logs. Names that just got an HTTPS certificate (data/radar.js, `npm run radar`).
//  3. Search and maps (optional API keys, server/connectors.js): results and business listings that use an
//     institution's name with a website or phone number the institution does not publish.
//  4. A light visit to every registered name: brand-owned (redirects to the real site), parked / for sale,
//     no website yet (dormant: watched, because it can switch on any day), or LIVE.
//  5. Live suspects are ranked (rulebook + ML link model + what the page shows) and go through the X-ray,
//     which records a case and links it into campaigns (server/cases.js).
// State lives in var/sentinel.json (private). Nothing here touches any user data.

import dns from 'node:dns';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fetchBytes } from './netguard.js';
import { analyzeUrl, splitDomain, officialFor } from '../engine/url.js';
import { mlUrlScore } from '../engine/urlml.js';
import { mlUrlScore2 } from '../engine/urlml2.js';
import { findInstitutions } from '../engine/extract.js';
import { matchForm } from '../engine/normalize.js';
import { checkListing } from '../engine/ledger.js';
import { INSTITUTIONS } from '../data/institutions.js';
import RADAR from '../data/radar.js';
import { nrdCandidates } from './nrd.js';
import { storeState } from './store.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIR = process.env.VETO_VAR || path.join(ROOT, 'var');
const FILE = path.join(DIR, 'sentinel.json');
const DESKTOP_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
export const PRIORITY = ['enbd', 'fab', 'adcb', 'mashreq', 'adib', 'dib', 'rakbank', 'ei', 'cbuae', 'adpolice', 'dxbpolice', 'uaepass', 'salik', 'rta', 'emiratespost', 'aramex', 'eand', 'du', 'dewa', 'tamm', 'mohre', 'gdrfa', 'icp'];

// ---------------------------------------------------------------------------------------------
// 1. look-alike names (dnstwist-style, tuned for how UAE scam domains are actually built)
const KEYBOARD = { q: 'wa', w: 'qeas', e: 'wrsd', r: 'etdf', t: 'ryfg', y: 'tugh', u: 'yihj', i: 'uojk', o: 'ipkl', p: 'ol', a: 'qwsz', s: 'awedxz', d: 'serfcx',
  f: 'drtgvc', g: 'ftyhbv', h: 'gyujnb', j: 'huikmn', k: 'jiolm', l: 'kop', z: 'asx', x: 'zsdc', c: 'xdfv', v: 'cfgb', b: 'vghn', n: 'bhjm', m: 'njk' };
const HOMO = { o: ['0'], l: ['1', 'i'], i: ['1', 'l'], e: ['3'], a: ['4'], s: ['5'], g: ['q'], m: ['rn', 'nn'], w: ['vv'], d: ['cl'], rn: ['m'], cl: ['d'], vv: ['w'], nn: ['m'] };
const WORDS = ['uae', 'ae', 'online', 'login', 'secure', 'verify', 'update', 'support', 'help', 'pay', 'rewards', 'points', 'refund', 'card', 'app',
  'portal', 'service', 'care', 'account', 'track', 'delivery', 'fines', 'gov', 'claim', 'gift', 'kyc'];
const OTHER_ENDINGS = ['com', 'net', 'org', 'co', 'ae', 'info', 'online', 'site', 'top', 'xyz', 'live', 'app', 'shop', 'store', 'support', 'services', 'click',
  'link', 'icu', 'cfd', 'sbs', 'vip', 'cc', 'me', 'io', 'pro', 'biz', 'life', 'help', 'center', 'website', 'cloud', 'today', 'work'];
const WORD_ENDINGS = ['com', 'online', 'top'];
const RESTRICTED = /(^|\.)(gov|mil|ac|sch)\.ae$|^abudhabi$/; // endings scammers cannot register

export function permutations(domain, extraLabels = []) {
  const d = domain.toLowerCase();
  const [label, ...rest] = d.split('.');
  const tld = rest.join('.');
  const out = new Map();
  const add = (l, t, how) => {
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l) || /--/.test(l)) return;
    const h = `${l}.${t}`;
    if (h !== d && !out.has(h)) out.set(h, how);
  };
  const editEndings = RESTRICTED.test(tld) ? ['com', 'ae'] : [tld];
  if (label.length >= 5) {
    for (const t of editEndings) {
      for (let i = 0; i < label.length; i++) {
        add(label.slice(0, i) + label.slice(i + 1), t, 'missing letter');
        add(label.slice(0, i) + label[i] + label.slice(i), t, 'doubled letter');
        if (i < label.length - 1) add(label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2), t, 'swapped letters');
        for (const k of KEYBOARD[label[i]] || '') add(label.slice(0, i) + k + label.slice(i + 1), t, 'neighbouring key');
        if ('aeiou'.includes(label[i])) for (const v of 'aeiou') if (v !== label[i]) add(label.slice(0, i) + v + label.slice(i + 1), t, 'vowel swap');
        if (i > 0) add(label.slice(0, i) + '-' + label.slice(i), t, 'hyphen');
        for (const [g, subs] of Object.entries(HOMO)) if (label.startsWith(g, i)) for (const s of subs) add(label.slice(0, i) + s + label.slice(i + g.length), t, 'look-alike letters');
      }
    }
  }
  for (const t of OTHER_ENDINGS) if (t !== tld) add(label, t, 'other ending');
  const bases = [...new Set([label, ...extraLabels.filter(x => x.length >= 4 && x !== label)])];
  for (const b of bases) for (const w of WORDS) for (const t of WORD_ENDINGS) {
    add(`${b}-${w}`, t, 'brand + word'); add(`${w}-${b}`, t, 'brand + word'); add(`${b}${w}`, t, 'brand + word');
  }
  return [...out].map(([host, how]) => ({ host, how }));
}

// ---------------------------------------------------------------------------------------------
// 2. DNS: registered or not (NXDOMAIN = free, ENODATA = registered without a web address)
const resolver = new dns.promises.Resolver({ timeout: 3000, tries: 2 });
export async function resolveName(host) {
  try { return { registered: true, ips: await resolver.resolve4(host) }; } catch (e) {
    if (e.code === 'ENODATA') return { registered: true, ips: [] };
    if (e.code === 'ENOTFOUND' || e.code === 'NXDOMAIN') return { registered: false };
    return { registered: null, error: e.code };
  }
}
async function pool(items, n, fn, onTick) {
  const q = items.slice();
  let done = 0;
  await Promise.all(Array.from({ length: Math.min(n, q.length) }, async () => {
    while (q.length) { const it = q.shift(); await fn(it); done++; if (onTick && done % 25 === 0) onTick(done); }
  }));
}

// ---------------------------------------------------------------------------------------------
// 3. a light visit (raw HTML, SSRF-guarded): what is there?
const PARKED = /domain (name )?(is |may be )?for sale|buy this domain|this domain (name )?(is|may be) (for sale|available)|make an offer|parked (free|domain|by)|sedoparking|parkingcrew|bodis\.com|afternic|dan\.com|hugedomains|domain has (been )?(registered|expired)|this (web )?page is parked|related searches|coming soon|under construction|default (web )?page|it works!|index of \//i;
const PARKING_HOSTS = /(^|\.)(sedo\.com|dan\.com|afternic\.com|hugedomains\.com|godaddy\.com|bodis\.com|parkingcrew\.net|above\.com|namecheap\.com|uniregistry\.com|squadhelp\.com|atom\.com|spaceship\.com|porkbun\.com)$/;
export async function visit(host) {
  let last = null;
  for (const scheme of ['https', 'http']) {
    const r = await fetchBytes(`${scheme}://${host}/`, { maxBytes: 500_000, timeout: 7000, userAgent: DESKTOP_UA }).catch(e => ({ ok: false, error: String(e.message || e) }));
    if (r.ok) {
      const html = r.bytes.toString('utf8');
      let finalHost = host;
      try { finalHost = new URL(r.finalUrl).hostname.toLowerCase(); } catch { /* keep */ }
      const title = ((/<title[^>]*>([^<]{0,160})/i.exec(html) || [])[1] || '').replace(/\s+/g, ' ').trim();
      const text = html.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').slice(0, 3000);
      return { ok: true, scheme, finalHost, title, size: html.length, parked: PARKED.test(`${title} ${text.slice(0, 1500)}`) || PARKING_HOSTS.test(finalHost),
        secrets: (html.match(/type\s*=\s*["']?password|name\s*=\s*["'](?:[^"']*[_-])?(?:pass(?:word)?|pin|otp|card(?:_?(?:number|no))?|cvv|cvc|iban)(?:[_-][^"']*)?["']/gi) || []).length,
        uae: /\b(uae|u\.a\.e|dubai|abu dhabi|sharjah|ajman|emirates|aed|dhs?)\b|الإمارات|دبي|أبوظبي|ابوظبي|درهم/i.test(`${title} ${text}`), text: text.slice(0, 600) };
    }
    last = r;
    if (/HTTP \d+/.test(r.error || '')) return { ok: false, status: Number(/HTTP (\d+)/.exec(r.error)[1]) };
  }
  return { ok: false, error: last?.error || 'unreachable' };
}

// ---------------------------------------------------------------------------------------------
// state
let state = null;
export function loadState() {
  if (state) return state;
  try { state = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch { state = { suspects: {}, sweeps: [] }; }
  return state;
}
export function saveState() {
  try { fs.mkdirSync(DIR, { recursive: true }); fs.writeFileSync(FILE, JSON.stringify(state)); } catch (e) { console.error('[veto] sentinel state:', e.message); }
  storeState('sentinel', state);
}
const now = () => new Date().toISOString();
function upsert(host, patch) {
  const s = loadState().suspects;
  const cur = s[host] || { host, firstSeen: now(), sources: [], history: [] };
  for (const src of patch.sources || []) if (!cur.sources.includes(src)) cur.sources.push(src);
  const { sources, ...rest } = patch;
  if (rest.status && rest.status !== cur.status) cur.history.push({ t: now(), status: rest.status });
  Object.assign(cur, rest, { lastChecked: now() });
  s[host] = cur;
  return cur;
}

const PROOF_TEXT = { asks_secrets: ['asks for card details or codes', 'تطلب بيانات البطاقة أو الرموز'], exfil: ['sends what you type to criminals', 'ترسل ما تكتبه إلى المحتالين'],
  copied_logo: ['wears the brand’s own icon', 'تستخدم أيقونة الجهة الحقيقية'], cloaking: ['hides from scanners (cloaking)', 'تختبئ من الفاحصات (تمويه)'], apk: ['pushes a dangerous app', 'تدفع تطبيقاً خطيراً'],
  download_attempt: ['tries to install an app', 'تحاول تثبيت تطبيق'], page_impersonation: ['poses as the institution', 'تنتحل صفة الجهة'] };

/** How alarming a suspect is (0..1), from everything Sentinel knows about it, with the reasons. */
export function scoreSuspect(x) {
  const inst = INSTITUTIONS.find(i => i.id === x.inst);
  const why = [];
  let p = 0;
  const add = (w, en, ar) => { p = 1 - (1 - p) * (1 - w); why.push({ en, ar, w }); };
  if (x.status === 'brand_owned') return { score: 0, why: [{ en: `Owned by ${inst?.name.en || 'the brand'} (sends visitors to the real site).`, ar: 'مملوك للجهة نفسها (يحوّل إلى الموقع الحقيقي).', w: 0 }] };
  if (x.how) add(x.sources.includes('ct') ? 0.35 : 0.25, `Imitates ${inst?.name.en || x.inst}: ${x.how}.`, `يقلّد ${inst?.name.ar || x.inst}: ${x.how}.`);
  if (x.sources.includes('nrd')) add(0.4, `Registered only days ago (${x.nrdDay || 'newly registered list'}).`, `سُجّل قبل أيام فقط (${x.nrdDay || 'قائمة النطاقات الجديدة'}).`);
  if (x.sources.includes('ct')) add(0.2, `Got an HTTPS certificate recently (${x.ctFirstSeen || 'certificate logs'}).`, `حصل على شهادة HTTPS مؤخراً (${x.ctFirstSeen || 'سجلات الشهادات'}).`);
  if (x.sources.includes('search')) add(0.35, 'Appears in search results for the institution.', 'يظهر في نتائج البحث عن الجهة.');
  if (x.sources.includes('maps')) add(0.45, 'Appears in a map listing that uses the institution’s name.', 'يظهر في إدراج على الخريطة يستخدم اسم الجهة.');
  if (x.ml2?.p >= x.ml2?.threshold) add(0.3, `URL model: ${Math.round(x.ml2.p * 100)}% phishing-like.`, `نموذج الروابط: احتيالي بنسبة ${Math.round(x.ml2.p * 100)}%.`);
  else if (x.ml?.p >= 0.8) add(x.ml.brand ? 0.3 : 0.15, `Link model: ${Math.round(x.ml.p * 100)}% phishing-style name.`, `نموذج الروابط: اسم تصيّد بنسبة ${Math.round(x.ml.p * 100)}%.`);
  if (x.status === 'live') add(0.25, 'The website is live.', 'الموقع يعمل.');
  if (x.status === 'parked') p *= 0.5;
  // a look-alike NAME on a live site that neither uses the brand nor talks to UAE residents is usually an unrelated
  // business that happens to share letters (rta.org, tamm.org …): it stays on the list, but low
  const relevant = x.web?.brandInPage && x.web?.uae;
  if (x.web?.secrets && relevant) add(0.35, `The page has ${x.web.secrets} secret field(s) (password, PIN, card …).`, `في الصفحة ${x.web.secrets} حقل سري (كلمة مرور، رقم سري، بطاقة …).`);
  if (relevant) add(0.3, `The page calls itself ${inst?.name.en || 'the brand'} and talks to UAE residents.`, `الصفحة تقدّم نفسها باسم ${inst?.name.ar || 'الجهة'} وتخاطب سكان الإمارات.`);
  else if (x.web?.brandInPage) add(0.1, `The page names ${inst?.name.en || 'the brand'}, without any UAE context.`, `الصفحة تذكر ${inst?.name.ar || 'الجهة'} دون سياق إماراتي.`);
  if (x.status === 'live' && !x.web?.brandInPage && !x.verdict) p *= 0.55;
  if (x.listing?.verdict === 'fake') add(0.6, x.listing.signals?.[0]?.en || 'Fake listing.', x.listing.signals?.[0]?.ar || 'إدراج مزيّف.');
  if (x.armed && (x.verdict === 'dangerous' || x.verdict === 'suspicious')) add(x.verdict === 'dangerous' ? 0.92 : 0.6, `X-ray: armed, the page ${(x.proof || []).map(p => PROOF_TEXT[p.replace(/^(exfil|apk)_.*/, '$1')]?.[0]).filter(Boolean).slice(0, 2).join(' and ') || 'acts like a phishing page'}.`,
    `الأشعة: مفعّل، الصفحة ${(x.proof || []).map(p => PROOF_TEXT[p.replace(/^(exfil|apk)_.*/, '$1')]?.[1]).filter(Boolean).slice(0, 2).join(' و') || 'تتصرف كصفحة تصيّد'}.`);
  else if (x.verdict === 'dangerous' || x.verdict === 'suspicious') add(0.3, 'X-ray: the name imitates the brand, but the page does nothing harmful yet. Keep watching: it can be armed any day.', 'الأشعة: الاسم يقلّد الجهة لكن الصفحة لا تفعل شيئاً ضاراً بعد. استمر بالمراقبة: قد تُفعّل في أي يوم.');
  return { score: +p.toFixed(3), why: why.sort((a, b) => b.w - a.w) };
}

// ---------------------------------------------------------------------------------------------
// the sweep (background job)
let job = null;
export const getJob = () => job;

export async function sweep({ insts = PRIORITY, kinds = ['lookalike', 'ct'], connectors = null, xray = null, xrayTop = 0, log = () => {} } = {}) {
  if (job && job.running) return job;
  job = { id: Date.now().toString(36), running: true, started: now(), phase: 'names', checked: 0, total: 0, registered: 0, live: 0, log: [] };
  const say = m => { job.log.push(`${new Date().toISOString().slice(11, 19)} ${m}`); if (job.log.length > 60) job.log.shift(); log(m); };
  try {
    const list = INSTITUTIONS.filter(i => insts.includes(i.id) && i.domains.length);
    const candidates = new Map();
    if (kinds.includes('lookalike')) {
      for (const inst of list) {
        for (const p of permutations(inst.domains[0], inst.tokens || [])) {
          if (officialFor(splitDomain(p.host).registrable)) continue; // another official domain
          if (!candidates.has(p.host)) candidates.set(p.host, { host: p.host, inst: inst.id, how: p.how, sources: ['lookalike'] });
        }
      }
    }
    if (kinds.includes('nrd')) {
      job.phase = 'newly registered domains';
      for (const c of await nrdCandidates({ days: 2, insts: list.map(i => i.id), log: say }).catch(e => { say('newly registered: ' + e.message); return []; })) {
        const cur = candidates.get(c.host);
        if (cur) { if (!cur.sources.includes('nrd')) cur.sources.push('nrd'); cur.nrdDay = c.nrdDay; } else candidates.set(c.host, c);
      }
    }
    if (kinds.includes('ct')) {
      for (const c of [...(RADAR.candidates || [])]) {
        if (!list.some(i => i.id === c.inst) && insts !== PRIORITY) continue;
        const host = c.registrable;
        const cur = candidates.get(host);
        if (cur) { cur.sources.push('ct'); cur.ctFirstSeen = c.firstSeen; } else candidates.set(host, { host, inst: c.inst, how: 'uses the brand name (certificate logs)', sources: ['ct'], ctFirstSeen: c.firstSeen, ctHosts: c.hosts });
      }
    }
    if (connectors) {
      job.phase = 'search & maps';
      for (const s of await connectors.suspects(list, say).catch(e => { say('connectors: ' + e.message); return []; })) {
        const cur = candidates.get(s.host);
        if (cur) { for (const x of s.sources) if (!cur.sources.includes(x)) cur.sources.push(x); Object.assign(cur, { listing: s.listing || cur.listing, query: s.query || cur.query }); }
        else candidates.set(s.host, s);
      }
    }
    job.total = candidates.size;
    say(`${candidates.size} names to check for ${list.length} institutions`);
    job.phase = 'dns';
    const registered = [];
    await pool([...candidates.values()], 48, async c => {
      const r = await resolveName(c.host);
      job.checked++;
      if (r.registered) { registered.push({ ...c, ips: r.ips }); job.registered++; }
      else if (r.registered === false && loadState().suspects[c.host]) upsert(c.host, { status: 'gone', sources: c.sources });
    });
    say(`${registered.length} of them are registered`);
    job.phase = 'visit';
    await pool(registered, 12, async c => {
      const inst = INSTITUTIONS.find(i => i.id === c.inst);
      const web = c.ips.length ? await visit(c.host) : { ok: false, error: 'no web address' };
      let status = 'no_web';
      if (web.ok) {
        const finalReg = splitDomain(web.finalHost).registrable;
        const off = officialFor(finalReg);
        if (off && off.id === c.inst) status = 'brand_owned';
        else if (off) status = 'redirects_official';
        else if (web.parked) status = 'parked';
        else status = 'live';
        const said = `${web.title} ${web.text}`.split(c.host).join(' ').split(web.finalHost).join(' ');
        web.brandInPage = !!findInstitutions(matchForm(said), said).find(x => x.inst.id === c.inst && !x.mention);
        if (finalReg !== splitDomain(c.host).registrable && status === 'live') web.redirectsTo = web.finalHost;
      } else if (web.status) status = 'error_page';
      if (status === 'live') job.live++;
      const a = analyzeUrl('https://' + c.host + '/');
      const ml = mlUrlScore(c.host);
      const ml2 = mlUrlScore2('https://' + c.host + '/');
      const prev = loadState().suspects[c.host];
      const rec = upsert(c.host, { inst: c.inst, instName: inst?.name || null, how: c.how, sources: c.sources, ips: c.ips.slice(0, 4), status,
        web: web.ok ? { title: web.title, secrets: web.secrets, brandInPage: web.brandInPage, uae: !!web.uae, finalHost: web.finalHost, size: web.size, redirectsTo: web.redirectsTo || null } : { error: web.error || `HTTP ${web.status}` },
        ml: ml ? { p: ml.p, brand: ml.brand } : null, ml2: ml2 ? { p: ml2.p, threshold: ml2.threshold } : null, rulebook: +a.risk.toFixed(2), ctFirstSeen: c.ctFirstSeen || prev?.ctFirstSeen || null,
        listing: c.listing || prev?.listing || null, query: c.query || prev?.query || null, nrdDay: c.nrdDay || prev?.nrdDay || null });
      if (prev && prev.status !== 'live' && status === 'live') rec.armedAt = now(); // switched on since the last sweep: act now
      Object.assign(rec, scoreSuspect(rec));
    });
    // dormant names we knew about but did not re-check this time keep their old state
    for (const s of Object.values(loadState().suspects)) if (!s.score && s.score !== 0) Object.assign(s, scoreSuspect(s));
    say(`${job.live} live, ${registered.length - job.live} parked / brand-owned / no website`);
    if (xray && xrayTop > 0) {
      job.phase = 'x-ray';
      const top = Object.values(loadState().suspects).filter(s => s.status === 'live' && !s.caseId).sort((a, b) => b.score - a.score).slice(0, xrayTop);
      for (const s of top) { say(`x-ray ${s.host}`); await xraySuspect(s.host, xray).catch(e => say(`x-ray failed: ${e.message}`)); }
    }
    loadState().sweeps.push({ t: job.started, insts: list.map(i => i.id), names: candidates.size, registered: registered.length, live: job.live });
    loadState().sweeps = loadState().sweeps.slice(-20);
    saveState();
    job.phase = 'done';
  } catch (e) {
    job.error = String(e.message || e);
    say('error: ' + job.error);
  } finally {
    job.running = false;
    job.finished = now();
  }
  return job;
}

/** X-ray one suspect now (xray = { run(url) -> result, record(result, opts) -> case }). */
export async function xraySuspect(host, xray) {
  const s = loadState().suspects[host] || upsert(host, { sources: ['manual'], status: 'live' });
  let r = await xray.run(`https://${host}/`);
  if (!r.ok && /resolve|chamber|net::/i.test(`${r.error} ${r.message}`)) r = await xray.run(`http://${host}/`);
  const inst = INSTITUTIONS.find(i => i.id === s.inst);
  const c = r.ok ? xray.record(r, { source: 'sentinel', extra: { imitates: inst ? { id: inst.id, name: inst.name } : null } }) : null;
  const rec = upsert(host, { verdict: r.ok ? r.verdict : 'unreachable', xrayRisk: r.ok ? r.risk : null, armed: !!r.armed, proof: r.proof || [], caseId: c?.id || null, xrayAt: now(),
    status: r.ok && r.official ? 'brand_owned' : s.status });
  Object.assign(rec, scoreSuspect(rec));
  saveState();
  return { suspect: rec, result: r, caseId: c?.id || null };
}

/** A listing from maps/search, checked against the ledger and added as a suspect when it lies. */
export function listingSuspect(listing, { source = 'maps', query = null } = {}) {
  const chk = checkListing(listing);
  if (!['fake', 'suspicious'].includes(chk.verdict)) return null;
  let host = null;
  try { host = listing.website ? new URL(/^https?:/i.test(listing.website) ? listing.website : 'http://' + listing.website).hostname.toLowerCase() : null; } catch { /* none */ }
  return { host: host || `listing:${(listing.phone || listing.name || '').replace(/\W+/g, '')}`, inst: chk.inst?.id, how: `${source} listing “${listing.name || ''}”`,
    sources: [source], listing: { name: listing.name, phone: listing.phone || null, website: listing.website || null, address: listing.address || null, mapsUri: listing.mapsUri || null, verdict: chk.verdict, signals: chk.signals.slice(0, 3) }, query };
}

/** Everything the police console shows. */
export function overview() {
  const s = loadState();
  const all = Object.values(s.suspects);
  const by = st => all.filter(x => x.status === st).length;
  return {
    sweeps: s.sweeps.slice(-5), counts: { total: all.length, live: by('live'), noWeb: by('no_web'), parked: by('parked'), brandOwned: by('brand_owned'), gone: by('gone'), xrayed: all.filter(x => x.caseId).length, dangerous: all.filter(x => x.verdict === 'dangerous').length },
    suspects: all.filter(x => x.status !== 'gone' && x.status !== 'brand_owned').sort((a, b) => (b.score || 0) - (a.score || 0)).slice(0, 2000),
    radar: { generatedAt: RADAR.generatedAt, candidates: (RADAR.candidates || []).length, shipped: (RADAR.domains || []).length }, job
  };
}
