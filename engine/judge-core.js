// Veto URL Judge, offline core: one verdict, one score and plain reasons for one URL, with no network. Layers, each one
// explainable:
//   1. official allowlist     an official UAE institution's domain is never flagged
//   2. restricted registries  gov.ae / ac.ae / mil.ae (and .gov / .edu / .mil): only real institutions can register
//   3. rulebook               look-alike letters, brand glued to words, punycode, "@" tricks, raw IPs (engine/url.js)
//   4. full-URL model         engine/urlml2-core.js: host + path + query + popularity, trained on dated public data
//   5. popularity guard       a top-10k site (not a hosting platform) needs much stronger evidence to be flagged
// This file has no Node-only code: the server (server/judge.js, which adds the online layer) and the browser extension
// run the same function. ~1 ms per URL.

import { analyzeUrl, splitDomain, officialFor, USER_CONTENT_HOSTS } from './url.js';
import { mlUrlScore2, parseUrl, trancoRank, isPlatform } from './urlml2-core.js';
import { INSTITUTIONS } from '../data/institutions.js';
import HOSTING from '../data/hosting-providers.js';

// Registries that only real public bodies can use. gob/gouv/govt/mil country zones and Brazil's jus.br were added on
// 24 Nov: no phishing in the dated history before 4 Oct or in the validation split; edu.xx and ac.xx were NOT added
// because hacked university sites do host phishing (10 and 2 cases in that history).
export const RESTRICTED = /(^|\.)(gov|mil|ac|sch)\.ae$|(^|\.)(gov|mil|edu)$|(^|\.)(gov|gob|gouv|govt|mil)\.[a-z]{2}$|(^|\.)jus\.br$|(^|\.)(gc\.ca|gouv\.fr|gov\.uk|nhs\.uk|europa\.eu|un\.org|who\.int)$/;
export const sig = (id, w, en, ar) => ({ id, w, en, ar });
const logit = p => Math.log(Math.max(1e-6, p) / Math.max(1e-6, 1 - p));
const sigmoid = z => 1 / (1 + Math.exp(-z));
export const THRESHOLDS = { phishing: 0.5, suspicious: 0.3 };
// Offline floor for a short link with a code: 0.3 = suspicious (the default). The validation split has 21 short links
// with a code, all phishing, and no legitimate short link with a code, so the false-alarm cost of a phishing floor is
// unmeasured. Set VETO_SHORT_LINK_FLOOR=0.5 to report them as phishing. The online check follows the link and judges the destination.
const ENV = typeof process !== 'undefined' && process.env ? process.env : {};
const SHORT_LINK_FLOOR = Number(ENV.VETO_SHORT_LINK_FLOOR || 0.3);
const GENERIC_TOKENS = new Set(['centralbank', 'police', 'emirates', 'finance', 'post', 'customs', 'courts', 'tax', 'bank', 'gov']);

// Public file buckets: anyone can create one, so a bad file often sits on a respectable storage domain.
// Evidence is the bucket name, the path and the query: well-known names, lure words, and a victim's e-mail
// address inside the link (phishing kits pre-fill the victim's login from it). Storage hosts only.
export const STORAGE_HOST = /(^|\.)s3([.-][a-z0-9-]+)*\.amazonaws\.com$|(^|\.)backblazeb2\.com$|(^|\.)blob\.core\.windows\.net$|(^|\.)storage\.googleapis\.com$|(^|\.)r2\.dev$|(^|\.)digitaloceanspaces\.com$/;
const LURE = new Set(['review', 'waybill', 'invoice', 'payment', 'verify', 'verification', 'secure', 'login', 'signin', 'statement', 'voicemail', 'shared', 'document', 'documents', 'doc', 'docs', 'receipt', 'delivery', 'shipment', 'unlock', 'update']);
const STORAGE_BRAND = new Set(['hotmail', 'outlook', 'office', 'onedrive', 'sharepoint', 'docusign', 'adobe', 'dropbox', 'gmail', 'yahoo', 'paypal', 'dhl', 'fedex', 'ups', 'aramex', 'microsoft', 'google', 'apple', 'icloud', 'netflix', 'whatsapp', 'binance']);
let BRANDS = null;
function storageBrands() {
  if (!BRANDS) BRANDS = new Set([...STORAGE_BRAND, ...INSTITUTIONS.filter(i => !i.generic).flatMap(i => [...i.tokens, ...i.domains.map(d => d.split('.')[0])]).map(t => t.toLowerCase()).filter(t => /^[a-z]{4,}$/.test(t) && !GENERIC_TOKENS.has(t))]);
  return BRANDS;
}
const EMAIL = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i;
const UTF8 = new TextDecoder('utf-8');
// base64 or base64url to text, as leniently as Node's Buffer: either alphabet, padding optional, a dangling last
// character ignored, invalid UTF-8 replaced
function b64text(t) {
  let s = t.replace(/=+$/, '').replace(/-/g, '+').replace(/_/g, '/');
  if (s.length % 4 === 1) s = s.slice(0, -1);
  while (s.length % 4) s += '=';
  try {
    const b = atob(s);
    const out = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
    return UTF8.decode(out);
  } catch { return ''; }
}
function hasVictimEmail(u) {
  let s = `${u.search}${u.hash}`;
  for (let k = 0; k < 2; k++) { try { s = decodeURIComponent(s); } catch { break; } }
  if (EMAIL.test(s)) return true;
  for (const t of s.match(/[A-Za-z0-9+/_-]{12,}={0,2}/g) || []) {
    if (EMAIL.test(b64text(t))) return true;
  }
  return false;
}
function storageEvidence(u, host) {
  if (!STORAGE_HOST.test(host)) return { q: 0, kind: null, reasons: [] };
  const words = `${host} ${u.pathname} ${u.search} ${u.hash}`.toLowerCase().match(/[a-z]+/g) || [];
  const brands = [...new Set(words.filter(w => storageBrands().has(w)))];
  const lures = [...new Set(words.filter(w => LURE.has(w)))];
  const list = a => a.slice(0, 3).join(', ');
  let q = 0, kind = null, en = '', ar = '';
  if (hasVictimEmail(u)) {
    q = 0.9; kind = 'victim_email';
    en = "The link carries an e-mail address. Phishing kits use one to pre-fill the victim's login, and this file sits on a public storage bucket.";
    ar = 'الرابط يحمل عنوان بريد إلكتروني، وصفحات التصيّد تستعمله لملء بيانات دخول الضحية تلقائياً، والملف على حاوية تخزين عامة.';
  } else if (brands.length && lures.length) {
    q = 0.85; kind = 'brand_lure';
    en = `A public storage bucket (anyone can create one) combines a well-known name (${list(brands)}) with lure words (${list(lures)}).`;
    ar = `حاوية تخزين عامة (يمكن لأي شخص إنشاؤها) تجمع اسماً مشهوراً (${list(brands)}) مع كلمات إغراء (${list(lures)}).`;
  } else if (lures.length >= 2) {
    q = 0.4; kind = 'lures';
    en = `A public storage bucket whose name or path uses several lure words (${list(lures)}).`;
    ar = `حاوية تخزين عامة يستعمل اسمها أو مسارها عدة كلمات إغراء (${list(lures)}).`;
  } else if (brands.length) {
    q = 0.35; kind = 'brand';
    en = `A public storage bucket whose name or path contains a well-known name (${list(brands)}).`;
    ar = `حاوية تخزين عامة يظهر في اسمها أو مسارها اسم خدمة مشهورة (${list(brands)}).`;
  }
  return { q, kind, reasons: q ? [sig('storage', q, en, ar)] : [] };
}

/** Offline verdict for one URL (no network). */
export function judgeOffline(input, depth = 0) {
  const t0 = performance.now();
  const url = String(input || '').trim();
  const u = parseUrl(url);
  if (!u || !u.hostname || !u.hostname.includes('.')) return finish({ url, verdict: 'invalid', score: null, reasons: [sig('invalid', 0, 'Not a web address.', 'ليس عنواناً على الويب.')] }, t0);
  const host = u.hostname.toLowerCase().replace(/^www\d?\./, '');
  const reg = splitDomain(host).registrable;
  const off = USER_CONTENT_HOSTS.some(p => host === p || host.endsWith('.' + p)) ? null : officialFor(reg); // Google Sites etc. are anyone's pages
  const hop = (off || RESTRICTED.test(host)) && depth < 2 ? embeddedHop(u, host, reg, depth, t0) : null;
  if (hop) return hop;
  if (off) return finish({ url, host, verdict: 'legitimate', score: 0.01, reasons: [sig('official', 0, `Official ${off.name.en} website (${reg}).`, `موقع رسمي لـ${off.name.ar} (${reg}).`)], layers: { official: off.id } }, t0);
  if (RESTRICTED.test(host)) return finish({ url, host, verdict: 'legitimate', score: 0.03, reasons: [sig('restricted', 0, `A government or academic domain (${host.split('.').slice(-2).join('.')}): only real institutions can register these.`, 'نطاق حكومي أو أكاديمي: لا يسجّله إلا جهات حقيقية.')], layers: { restricted: true } }, t0);

  const a = analyzeUrl(u.href);
  const m = mlUrlScore2(u.href);
  const rank = trancoRank(reg);
  // A short link with a code (bit.ly/AbC12) hides its destination. Offline the judge cannot see where it leads, and
  // the shortener's own popularity says nothing about that destination, so it gets no popularity discount.
  const shortCode = a.shortener && (u.pathname.replace(/\/+$/, '').length > 1 || u.search.length > 1);
  // A subdomain on a popular domain that hands out subdomains to anyone (data/hosting-providers.js) is someone's
  // site, not the provider's: the provider's popularity does not vouch for it.
  const userSite = !!HOSTING[reg] && host !== reg && !STORAGE_HOST.test(host); // buckets have their own layer below
  // Some hosted HTML uses a long mixed letter/digit tenant label. On its own that
  // shape proves nothing, but the parent provider's traffic cannot validate the file.
  const tenant = host.split('.')[0];
  const mixedTenantPage = STORAGE_HOST.test(host) && /\.html?$/i.test(u.pathname)
    && /^[a-z0-9]{10,63}$/i.test(tenant) && /[a-z]/i.test(tenant) && /\d.*\d/.test(tenant);
  const platform = isPlatform(host, reg) || shortCode || userSite || mixedTenantPage;
  const reasons = [];
  // model, re-centred so that its validated threshold (false alarms <= 1 %) sits at 0.5
  const T = m?.threshold || 0.5;
  const s = m ? sigmoid(logit(m.p) - logit(T)) : 0;
  if (m && m.p >= T * 0.8) reasons.push(sig('ml_url2', s, `The URL model rates this address ${Math.round(m.p * 100)}% phishing-like${m.why.length ? ': ' + m.why.map(x => x.en).join(', ') : ''}.`,
    `نموذج الروابط يقدّر هذا العنوان احتيالياً بنسبة ${Math.round(m.p * 100)}%${m.why.length ? ': ' + m.why.map(x => x.ar).join('، ') : ''}.`));
  // rulebook signals: the strong ones count on their own, weak ones only next to a model that already leans phishing
  let r = 0;
  // brand words that are also ordinary words abroad ("centralbank.cy" is Cyprus's real central bank) only count as
  // impersonation when the model also leans phishing
  const genericBrand = a.brand && GENERIC_TOKENS.has(a.brand.token);
  for (const x of a.signals) {
    if (x.id === 'ml_url') continue; // the v1 name model is superseded here
    if (x.id === 'shortener' && shortCode) continue; // handled below, with its own floor
    // A brand name or near-miss in a domain that is itself among the 100,000 most visited sites (google.com.lb,
    // microsoftedgeinsider.com) is almost always the brand's own or a well-known site: it counts only next to the model.
    // Google's own country domains (google.com.lb, google.iq) are registered by Google itself.
    const popularOwnName = ((rank && rank <= 100000 && !platform) || /^google\.(com?\.)?[a-z]{2}$/.test(reg)) && ['brand_in_domain', 'lookalike_domain'].includes(x.id);
    const strong = (x.w >= 0.8 || ['lookalike', 'punycode_lookalike', 'at_trick', 'radar'].includes(x.id)) && !(x.id === 'brand_in_domain' && genericBrand) && !popularOwnName;
    if (!strong && s < 0.35) continue;
    r = 1 - (1 - r) * (1 - x.w * (strong ? 1 : 0.6));
    reasons.push(x);
  }
  // popularity guard: a top site that is not a hosting platform needs much stronger evidence
  let damp = 1;
  if (rank && rank <= 10000 && !platform) damp = 0.25;
  else if (rank && rank <= 100000 && !platform) damp = 0.6;
  if (damp < 1) reasons.push(sig('popular', 0, `Among the ${rank <= 10000 ? '10,000' : '100,000'} most visited sites in the world (Tranco rank ${rank.toLocaleString('en')}).`, `من أكثر المواقع زيارة في العالم (ترتيب Tranco ${rank}).`));
  const st = storageEvidence(u, host);
  reasons.push(...st.reasons);
  const raw = 1 - (1 - s * damp) * (1 - r * damp) * (1 - st.q);
  // A file on a public bucket is judged on its content: without a victim e-mail or a famous name with lure words,
  // the host alone cannot make it phishing (the model reads many bucket hostnames as phishing-like).
  const bucketCap = STORAGE_HOST.test(host) && st.kind !== 'victim_email' && st.kind !== 'brand_lure';
  if (bucketCap && raw >= THRESHOLDS.phishing) reasons.push(sig('storage_cap', 0, 'The address alone does not make a file on a public bucket phishing: no victim e-mail and no famous name with lure words was found in it.', 'عنوان الحاوية وحده لا يجعل الملف احتيالياً: لم يُعثر فيه على بريد ضحية، ولا على اسم مشهور مع كلمات إغراء.'));
  let score = bucketCap ? Math.min(raw, 0.49) : raw;
  if (mixedTenantPage && bucketCap && score >= THRESHOLDS.suspicious) {
    reasons.unshift(sig('storage', 0, 'This HTML file is on a tenant-controlled storage host. Check its destination and contents before clearing it.',
      'ملف HTML مستضاف لدى حساب مستقل على خدمة تخزين. تحقّق من الوجهة والمحتوى قبل استبعاده من المراجعة.'));
  }
  if (shortCode) {
    score = Math.max(score, SHORT_LINK_FLOOR);
    reasons.push(sig('short_link', SHORT_LINK_FLOOR, `A short link (${reg}) hides the real address, and scammers use short links to slip past filters. Offline, the judge cannot see where it leads, so it is treated as at least suspicious until the online check expands it.`,
      `الرابط المختصر (${reg}) يخفي العنوان الحقيقي، ويستخدمه المحتالون لتجاوز أدوات الحماية. لا يمكن معرفة وجهته دون اتصال، لذا يُعامل كرابط مشبوه على الأقل حتى يكشف الفحص المباشر وجهته.`));
  }
  return finish({ url, host, reg, verdict: score >= THRESHOLDS.phishing ? 'phishing' : score >= THRESHOLDS.suspicious ? 'suspicious' : 'legitimate', score: +score.toFixed(4),
    reasons: reasons.sort((x, y) => y.w - x.w).slice(0, 5), layers: { model: m ? m.p : null, rules: +r.toFixed(3), rank: rank || null, platform, storage: st.kind } }, t0);
}

// Open redirects on trusted sites: a link such as google.com/url?q=<address> or a bank's /redirect?url=<address>
// sends the visitor to the address inside it. Judge that address too; if it is bad, the link is bad.
const EMBEDDED = /https?:\/\/[^\s&"'<>]+/gi;
function embeddedTargets(u) {
  let s = `${u.search}${u.hash}`;
  for (let k = 0; k < 2; k++) { try { s = decodeURIComponent(s); } catch { break; } }
  const found = new Set();
  for (const m of s.matchAll(EMBEDDED)) { const t = m[0].replace(/[),.;]+$/, ''); if (t.length > 12) found.add(t); }
  return [...found].slice(0, 3);
}
function embeddedHop(u, host, reg, depth, t0) {
  const judged = embeddedTargets(u).map(t => judgeOffline(t, depth + 1)).filter(r => r.host);
  if (!judged.length) return null;
  const worst = judged.reduce((a, b) => (b.score > a.score ? b : a));
  if (worst.verdict === 'legitimate' || worst.verdict === 'invalid') return null;
  const en = worst.verdict === 'phishing' ? 'phishing' : 'suspicious';
  const ar = worst.verdict === 'phishing' ? 'احتيالي' : 'مشبوه';
  return finish({ url: u.href, host, reg, verdict: worst.verdict, score: worst.score,
    reasons: [sig('redirect', worst.score, `This link is on ${host} but passes you on to ${worst.host}, which is judged ${en}.`,
      `هذا الرابط على ${host} لكنه يحوّلك إلى ${worst.host}، ويُقيَّم بأنه ${ar}.`), ...(worst.reasons || [])].slice(0, 5),
    layers: { redirect_to: worst.host, inner: worst.layers } }, t0);
}

// Every reason says where it came from (provenance, as in the explainability criterion): a rule, the URL model,
// the allowlist, the popularity guard, the bucket layer, an online check, a threat feed, the input check, or the AI layer.
export const REASON_SOURCES = new Set(['rule', 'model', 'allowlist', 'popularity', 'bucket_layer', 'online_check', 'feed', 'input', 'ai']);
const SOURCE_OF = {
  ml_url2: 'model',
  official: 'allowlist', restricted: 'allowlist',
  popular: 'popularity',
  storage: 'bucket_layer', storage_cap: 'bucket_layer',
  feed: 'feed',
  lands_on: 'online_check', page_secrets: 'online_check', page_pretends: 'online_check',
  dead: 'online_check', gone: 'online_check', on_hold: 'online_check', old_domain: 'online_check', new_domain: 'online_check',
  invalid: 'input',
  ai: 'ai',
};
export function finish(res, t0) {
  res.ms = +(performance.now() - t0).toFixed(2);
  if (Array.isArray(res.reasons)) res.reasons = res.reasons.map(r => (r.src ? r : { ...r, src: SOURCE_OF[r.id] || 'rule' }));
  return res;
}
