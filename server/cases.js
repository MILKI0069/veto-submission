// The Veto case file: one compact record per suspicious SITE the X-ray or Sentinel examined. Never the user,
// never their message: only what the site is, what it imitates, what it asks for, where it sends stolen data,
// and the forensic keys that link sites into campaigns.
//
// Stored in var/ (private: not served by the web server, not in the repository):
//   var/cases.jsonl        one JSON record per line (latest record per site wins)
//   var/shots/<id>.jpg     the X-ray picture of dangerous / suspicious pages, for the takedown pack
//
// Campaign linking ("Scam DNA"): two sites belong to the same operation when they share something criminals
// reuse: the Telegram bot or account that receives the data, a WhatsApp number, a wallet, an analytics or ad
// pixel ID, the exact kit, a near-identical kit skeleton, the same server (not a shared CDN), or a bulk
// registration (same registrar, same day). Each link keeps its reason, so a human can check it.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { hamming64 } from './forensics.js';
import { LOGOS } from '../data/logos.js';
import { storeCase } from './store.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIR = process.env.VETO_VAR || path.join(ROOT, 'var');
const FILE = path.join(DIR, 'cases.jsonl');
const SHOTS = path.join(DIR, 'shots');
const OFFICIAL_ICON = new Set(LOGOS.map(l => l.sha256));
// big shared networks: many unrelated sites sit on the same IPs / name servers, so those are not links
const SHARED_NET = /cloudflare|akamai|fastly|amazon|google|microsoft|azure|incapsula|imperva|sucuri|vercel|netlify|github|ovh|hetzner|digitalocean|hostinger|namecheap|godaddy|wix|squarespace|shopify/i;
const SHARED_NS = /cloudflare\.com$|domaincontrol\.com$|registrar-servers\.com$|awsdns|azure-dns|googledomains\.com$|nsone\.net$|dnsowl\.com$|hostinger|namecheaphosting|bluehost|wixdns|parkingcrew|sedoparking|above\.com$|dan\.com$/i;

let cache = null;
function load() {
  if (cache) return cache;
  cache = new Map();
  try {
    for (const line of fs.readFileSync(FILE, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try { const r = JSON.parse(line); cache.set(r.id, r); } catch { /* skip a torn line */ }
    }
  } catch { /* no case file yet */ }
  return cache;
}

const caseId = finalUrl => {
  let key = finalUrl;
  try { const u = new URL(finalUrl); key = (u.hostname + u.pathname).toLowerCase(); } catch { /* raw */ }
  return crypto.createHash('sha256').update(key).digest('hex').slice(0, 12);
};
const stripQuery = u => { try { const x = new URL(u); return x.origin + x.pathname; } catch { return String(u).split(/[?#]/)[0]; } };

/** Store (or update) the case for an X-ray result. Returns the case record, or null for official / failed scans. */
export function recordCase(x, { source = 'xray', extra = {} } = {}) {
  if (!x || !x.ok || x.official) return null;
  const f = x.forensics || {};
  const id = caseId(x.finalUrl);
  const prev = load().get(id);
  const imitation = x.signals.find(s => s.id === 'page_impersonation' || s.id === 'copied_logo' || s.id === 'lookalike');
  const rec = {
    id, source: prev?.source || source, firstSeen: prev?.firstSeen || new Date().toISOString(), lastSeen: new Date().toISOString(),
    input: stripQuery(x.input), finalUrl: stripQuery(x.finalUrl), finalHost: x.finalHost, chain: (x.chain || []).map(stripQuery).slice(0, 8),
    browserStatus: x.browserStatus ?? null, redirectObservation: x.redirectObservation ?? null,
    registrable: regOf(x.finalHost), title: (x.title || '').slice(0, 140), verdict: x.verdict, risk: x.risk, armed: !!x.armed, proof: x.proof || [],
    imitates: f.logos?.[0] ? { id: f.logos[0].inst, name: f.logos[0].name } : extra.imitates || prev?.imitates || null,
    imitationText: imitation ? { en: imitation.en, ar: imitation.ar } : null,
    signals: x.signals.slice(0, 8).map(({ id: sid, w, en, ar }) => ({ id: sid, w, en, ar })),
    asks: x.facts?.asks || [], intent: x.intent ? { en: x.intent.en, ar: x.intent.ar, sendsTo: x.intent.sendsTo || null } : null,
    exfil: (x.trap?.caught || []).map(({ kind, host, bot, method }) => ({ kind, host, bot: bot || null, method })),
    apk: x.apk?.ok ? { package: x.apk.package, label: x.apk.label, sha256: x.apk.sha256, trojan: !!x.apk.trojanProfile } : null,
    keys: f.keys || {}, kit: f.kit || null, favicon: f.favicon || null, logos: f.logos || [],
    cloaking: f.cloaking ? { verdict: f.cloaking.verdict, who: f.cloaking.who } : null,
    infra: f.infra ? {
      registrar: f.infra.domain?.registrar || null, abuseEmail: f.infra.domain?.abuseEmail || null, created: f.infra.domain?.created || null,
      status: f.infra.domain?.status || [], nameservers: f.infra.domain?.nameservers || [],
      ip: f.infra.host?.ip || null, asn: f.infra.host?.asn || null, asName: f.infra.host?.asName || null, country: f.infra.host?.country || null, hostAbuse: f.infra.host?.abuseEmail || null
    } : null,
    takedown: f.takedown || [], tls: x.facts?.tls || null, domainAgeDays: x.facts?.domainAgeDays ?? null,
    ...extra
  };
  rec.hasShot = prev?.hasShot || false;
  let shotB64 = null;
  if (x.screenshot && (x.verdict === 'dangerous' || x.verdict === 'suspicious')) {
    try {
      fs.mkdirSync(SHOTS, { recursive: true });
      fs.writeFileSync(path.join(SHOTS, id + '.jpg'), Buffer.from(x.screenshot.split(',')[1], 'base64'));
      rec.hasShot = true;
      shotB64 = x.screenshot.split(',')[1];
    } catch { /* picture is optional */ }
  }
  load().set(id, rec);
  try { fs.mkdirSync(DIR, { recursive: true }); fs.appendFileSync(FILE, JSON.stringify(rec) + '\n'); } catch (e) { console.error('[veto] case file:', e.message); }
  storeCase(rec, shotB64);
  return rec;
}

/** Add or update a lightweight record (Sentinel suspects that were not X-rayed yet use their own list). */
export function getCase(id) { return load().get(id) || null; }
export function listCases() { return [...load().values()].sort((a, b) => b.lastSeen.localeCompare(a.lastSeen)); }
export function shotPath(id) { const p = path.join(SHOTS, String(id).replace(/[^a-f0-9]/g, '') + '.jpg'); return fs.existsSync(p) ? p : null; }
function regOf(host) {
  const l = String(host || '').toLowerCase().split('.');
  return l.length >= 3 && /^(co|com|net|org|gov|ac|edu|sch|mil)$/.test(l[l.length - 2]) && l[l.length - 1].length === 2 ? l.slice(-3).join('.') : l.slice(-2).join('.');
}

// ---------------------------------------------------------------------------------------------
// campaigns: union-find over shared criminal infrastructure
const STRONG_KEYS = ['telegram_bot', 'telegram', 'whatsapp', 'wallet', 'analytics', 'pixel', 'metrika', 'email', 'phone'];
const KEY_TEXT = {
  telegram_bot: ['the same Telegram bot receives the stolen data', 'بوت تيليجرام نفسه يستقبل البيانات المسروقة'],
  telegram: ['the same Telegram account', 'حساب تيليجرام نفسه'], whatsapp: ['the same WhatsApp number', 'رقم واتساب نفسه'],
  wallet: ['the same crypto wallet', 'المحفظة الرقمية نفسها'], analytics: ['the same analytics ID', 'معرّف التحليلات نفسه'],
  pixel: ['the same ad pixel', 'بكسل الإعلانات نفسه'], metrika: ['the same Metrika counter', 'عدّاد Metrika نفسه'],
  email: ['the same e-mail drop', 'بريد الاستلام نفسه'], phone: ['the same phone number', 'رقم الهاتف نفسه'],
  kit_exact: ['the identical phishing kit', 'أداة التصيّد نفسها تماماً'], kit_near: ['a near-identical kit skeleton', 'هيكل أداة شبه مطابق'],
  favicon: ['the same home-made tab icon', 'الأيقونة المصنوعة نفسها'], ip: ['the same server', 'الخادم نفسه'],
  ns: ['the same private name servers', 'خوادم الأسماء الخاصة نفسها'], bulk: ['registered at the same registrar on the same day', 'سُجّلا لدى الجهة نفسها في اليوم نفسه'],
  exfil: ['the same data-collection server', 'خادم جمع البيانات نفسه'], apk: ['the same malicious app file', 'ملف التطبيق الخبيث نفسه']
};

// How strong each shared trace is. Only high and medium links join sites into one campaign. A low link stays in the
// record and never merges sites: shared hosting, common icons and same-day registrations link innocent sites.
const CONFIDENCE = { telegram_bot: 'high', wallet: 'high', exfil: 'high', apk: 'high', email: 'medium', analytics: 'medium',
  pixel: 'medium', metrika: 'medium', telegram: 'medium', whatsapp: 'medium', phone: 'medium', kit_exact: 'medium', ns: 'medium',
  ip: 'low', favicon: 'low', bulk: 'low', kit_near: 'low' };
export function campaigns(records = listCases()) {
  const rs = records.filter(r => r.verdict !== 'official');
  const parent = rs.map((_, i) => i);
  const find = i => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  const edges = [];
  const link = (a, b, why, value) => {
    const confidence = CONFIDENCE[why] || 'low';
    edges.push({ a: rs[a].id, b: rs[b].id, why, value, confidence });
    if (confidence !== 'low') parent[find(a)] = find(b);
  };
  // exact keys through an index (linear), fuzzy kit prints pairwise (case files are small)
  const index = new Map();
  const put = (k, i, why, value) => { const arr = index.get(k); if (arr) { for (const j of arr.slice(0, 1)) link(i, j, why, value); arr.push(i); } else index.set(k, [i]); };
  rs.forEach((r, i) => {
    for (const k of STRONG_KEYS) for (const v of r.keys?.[k] || []) put(`${k}:${v}`, i, k, v);
    if (r.kit?.exact && (r.kit.fields || 0) >= 2) put(`kit:${r.kit.exact}`, i, 'kit_exact', r.kit.exact);
    if (r.favicon?.sha256 && !OFFICIAL_ICON.has(r.favicon.sha256)) put(`fav:${r.favicon.sha256}`, i, 'favicon', String(r.favicon.shodan));
    if (r.infra?.ip && !SHARED_NET.test(r.infra.asName || '')) put(`ip:${r.infra.ip}`, i, 'ip', r.infra.ip);
    const ns = (r.infra?.nameservers || []).filter(n => !SHARED_NS.test(n)).sort();
    if (ns.length >= 2) put(`ns:${ns.join(',')}`, i, 'ns', ns.join(', '));
    if (r.infra?.registrar && r.infra?.created) put(`bulk:${r.infra.registrar}:${r.infra.created.slice(0, 10)}`, i, 'bulk', `${r.infra.registrar} ${r.infra.created.slice(0, 10)}`);
    for (const e of r.exfil || []) if (e.host && !/telegram|discord|google|script\.google|formspree|getform/.test(e.host)) put(`exfil:${e.host}`, i, 'exfil', e.host);
    if (r.apk?.sha256) put(`apk:${r.apk.sha256}`, i, 'apk', r.apk.sha256.slice(0, 16));
  });
  for (let i = 0; i < rs.length; i++) for (let j = i + 1; j < rs.length; j++) {
    const a = rs[i].kit, b = rs[j].kit;
    if (a?.simhash && b?.simhash && a.tokens >= 60 && b.tokens >= 60 && a.exact !== b.exact) {
      const d = hamming64(a.simhash, b.simhash);
      if (d <= 5) link(i, j, 'kit_near', `${d} bits apart`);
    }
  }
  const groups = new Map();
  rs.forEach((r, i) => { const g = find(i); if (!groups.has(g)) groups.set(g, []); groups.get(g).push(r); });
  const out = [];
  for (const members of groups.values()) {
    if (members.length < 2) continue;
    const ids = new Set(members.map(m => m.id));
    const why = edges.filter(e => ids.has(e.a) && ids.has(e.b)).map(e => ({ why: e.why, value: e.value, confidence: e.confidence, en: KEY_TEXT[e.why][0], ar: KEY_TEXT[e.why][1], a: e.a, b: e.b }));
    const confidence = why.some(l => l.confidence === 'high') ? 'high' : 'medium';
    const brands = [...new Map(members.filter(m => m.imitates).map(m => [m.imitates.id, m.imitates])).values()];
    const firstSeen = members.map(m => m.firstSeen).sort()[0];
    const lastSeen = members.map(m => m.lastSeen).sort().pop();
    const cid = 'C-' + crypto.createHash('sha256').update([...ids].sort().join(',')).digest('hex').slice(0, 6).toUpperCase();
    out.push({ id: cid, confidence, size: members.length, members: members.map(m => ({ id: m.id, host: m.finalHost, verdict: m.verdict, risk: m.risk, imitates: m.imitates, firstSeen: m.firstSeen })),
      brands, firstSeen, lastSeen, links: why, dangerous: members.filter(m => m.verdict === 'dangerous').length });
  }
  return out.sort((a, b) => b.size - a.size || b.lastSeen.localeCompare(a.lastSeen));
}

/** The campaign a case belongs to (or null). */
export function campaignOf(id) {
  return campaigns().find(c => c.members.some(m => m.id === id)) || null;
}

/** For tests: start from an empty, in-memory case file. */
export function _resetForTests(records = []) { cache = new Map(records.map(r => [r.id, r])); }
