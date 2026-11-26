// Veto server: serves the web app (which analyses messages ON THE DEVICE) and hosts the
// two optional server-side helpers: the Link X-ray chamber and the AI deep-check.
// It never receives message text unless the user presses "AI deep check" (and then only redacted text).
//
//   npm start            -> http://localhost:8787
//   PORT=9000 npm start
//   VETO_DEMO=0         -> disable the built-in demo scam pages (*.localhost)

import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { xray, xrayAvailable } from './xray.js';
import { aiConfigured, deepCheck, inspectScreenshot } from './ai.js';
import { intelConfigured, ipqsPhone } from './intel.js';
import { callerCheck } from '../engine/context.js';
import { recordCase, getCase, listCases, campaigns, campaignOf, shotPath } from './cases.js';
import { dossierHtml, stixBundle, shotDataUrl, evidenceBundle, reportTexts } from './dossier.js';
import { sweep, getJob, overview, xraySuspect, PRIORITY } from './sentinel.js';
import { helplineHunt, connectors, connectorsConfigured } from './connectors.js';
import { judgeOffline, judgeOnline, judgeList, parseList } from './judge.js';
import { INSTITUTIONS } from '../data/institutions.js';
import { storeRestore, storeStatus } from './store.js';
import { codeConfigured, checkCode, sessionCookie, clearCookie, hasSession, recordReview, auditLog, reviewOf } from './console.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = Number(process.env.PORT) || 8787;
const DEMO = process.env.VETO_DEMO !== '0';
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json',
  '.woff2': 'font/woff2', '.webmanifest': 'application/manifest+json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8' };
const STATIC = [['/engine/', 'engine'], ['/data/', 'data'], ['/', 'web']];

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'microphone=(self), camera=(), geolocation=()',
  'Content-Security-Policy': "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
};

const send = (res, code, body, type = 'application/json', extra = {}) => {
  res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store', ...SECURITY_HEADERS, ...extra });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
};

async function readJson(req, limit = 200_000) {
  let size = 0;
  const chunks = [];
  for await (const c of req) {
    size += c.length;
    if (size > limit) throw Object.assign(new Error('too large'), { code: 413 });
    chunks.push(c);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
}

// The police console (Sentinel, case file, campaigns) answers only on this machine, or with the console token.
const CONSOLE_TOKEN = process.env.VETO_CONSOLE_TOKEN || '';
const isLocal = req => ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress) && !req.headers['x-forwarded-for'];
const consoleOk = req => isLocal(req) || (!!CONSOLE_TOKEN && req.headers['x-veto-console'] === CONSOLE_TOKEN) || hasSession(req);
// behind a hosting proxy every request arrives from the proxy's address, so rate limits use the forwarded client address
const clientIp = req => (!isLocal(req) && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || 'x';
const policeAliases = new Set(['/resident', '/index.html', '/home.html', '/sentinel.html', '/share']);
const TRAINING_HOSTS = ['secure-verify-uae', 'parcel-redelivery', 'salik-fine-pay', 'bank-app-update', 'phone-cleaner'];
const brief = c => ({ id: c.id, host: c.finalHost, registrable: c.registrable, verdict: c.verdict, risk: c.risk, imitates: c.imitates, firstSeen: c.firstSeen, lastSeen: c.lastSeen,
  source: c.source, armed: !!c.armed, asks: c.asks, title: c.title, review: (r => r && { decision: r.decision, officer: r.officer, t: r.t })(reviewOf(c.id)), exfil: (c.exfil || []).map(e => e.kind), cloaked: c.cloaking?.verdict === 'cloaked', copiedLogo: !!c.logos?.length, hasShot: c.hasShot });

// very small per-IP rate limit for the server-side helpers
const hits = new Map();
function limited(ip, max = 20) {
  const now = Date.now();
  const h = (hits.get(ip) || []).filter(t => now - t < 60_000);
  h.push(now);
  hits.set(ip, h);
  return h.length > max;
}

// one shared hourly budget for the X-ray chamber, so a public page cannot be used to wear the server out
const XRAY_HOURLY = Number(process.env.VETO_XRAY_HOURLY) || 240;
let xrayRuns = [];
function xrayBudgetSpent() {
  const now = Date.now();
  xrayRuns = xrayRuns.filter(t => now - t < 3600_000);
  if (xrayRuns.length >= XRAY_HOURLY) return true;
  xrayRuns.push(now);
  return false;
}

async function serveStatic(req, res, pathname) {
  for (const [prefix, dir] of STATIC) {
    if (!pathname.startsWith(prefix)) continue;
    let rel = decodeURIComponent(pathname.slice(prefix.length)) || 'index.html';
    if (rel.endsWith('/')) rel += 'index.html';
    const base = path.join(ROOT, dir);
    const file = path.resolve(base, rel);
    if (!file.startsWith(base + path.sep) && file !== base) return send(res, 403, { error: 'forbidden' });
    try {
      const data = await fs.readFile(file);
      const type = MIME[path.extname(file).toLowerCase()] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-cache', ...SECURITY_HEADERS });
      return res.end(data);
    } catch {
      return send(res, 404, { error: 'not found' });
    }
  }
  return send(res, 404, { error: 'not found' });
}

// ---------- built-in demo scam pages (only on *.localhost, never on the real app host) ----------
async function serveDemo(req, res, sub, pathname) {
  const dir = path.join(ROOT, 'demo-sites');
  const head = { 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex' };
  if (/^\/go\b/.test(pathname)) { // a "short link" that bounces to the parcel page
    res.writeHead(302, { Location: `http://parcel-redelivery.localhost:${PORT}/track?id=AE${Date.now() % 100000}`, ...head });
    return res.end();
  }
  if (pathname.endsWith('.apk')) {
    // harmless demo app file: NO code, it only declares a banking-trojan permission set (tools/make-demo-apk.js)
    const name = (pathname.split('/').pop() || 'app.apk').replace(/[^\w.-]/g, '');
    let body;
    try { body = await fs.readFile(path.join(dir, 'files', /clean/i.test(name) ? 'demo-cleaner.apk' : 'demo-app.apk')); } catch { body = 'VETO.AI DEMO FILE - not a real app.'; }
    res.writeHead(200, { 'Content-Type': 'application/vnd.android.package-archive', 'Content-Disposition': `attachment; filename="${name}"`, ...head });
    return res.end(body);
  }
  // cloaking demo: the toll-fine trap is shown only to phones; computers and search crawlers are sent to a harmless blog
  if (/fine|toll|salik/.test(sub) && !/Mobile|Android|iPhone/i.test(req.headers['user-agent'] || '')) {
    res.writeHead(302, { Location: `http://travel-tips-blog.localhost:${PORT}/`, ...head });
    return res.end();
  }
  if (/blog/.test(sub)) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...head });
    return res.end('<!doctype html><meta charset="utf-8"><title>Weekend travel tips</title><body style="font-family:Arial;max-width:560px;margin:30px auto;color:#333"><h1>Weekend travel tips</h1><p>Five easy road trips from Dubai and Abu Dhabi, with the best stops for coffee and sunsets.</p><p>VETO.AI DEMO PAGE: the harmless face a cloaked scam site shows to computers and search engines.</p></body>');
  }
  const page = /fine|toll|salik/.test(sub) ? 'fine.html' : /clean|virus|boost|antivirus/.test(sub) ? 'scare.html' : /parcel|post|deliver|track|aramex|ship/.test(sub) ? 'parcel.html'
    : /app|apk|update-app|download/.test(sub) ? 'app.html' : 'verify.html';
  const html = await fs.readFile(path.join(dir, page));
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...head });
  return res.end(html);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const host = (req.headers.host || '').split(':')[0].toLowerCase();
  const ip = clientIp(req);
  try {
    if (DEMO && host.endsWith('.localhost') && host !== 'localhost') {
      return await serveDemo(req, res, host.replace(/\.localhost$/, ''), url.pathname);
    }
    if (url.pathname === '/healthz') return send(res, 200, 'ok', 'text/plain; charset=utf-8');
    // where the case file lives (files only, or files + database copy); no secrets, no case data
    if (url.pathname === '/api/store') { const s = storeStatus(); return send(res, 200, { mode: s.mode, restored: s.restored, pending: s.pending, healthy: !s.lastError }); }
    if (policeAliases.has(url.pathname.replace(/\/$/, ''))) { res.writeHead(302, { Location: '/police', ...SECURITY_HEADERS }); return res.end(); }
    // ---------- police console sign-in (hosted): access code in, signed session cookie out ----------
    if (url.pathname === '/api/console/session') {
      return send(res, 200, { ok: consoleOk(req), mode: isLocal(req) ? 'local' : consoleOk(req) ? 'code' : 'none', codeConfigured: codeConfigured() });
    }
    if (url.pathname === '/api/console/login' && req.method === 'POST') {
      if (limited('login:' + ip, 8)) return send(res, 429, { ok: false, error: 'rate' });
      const body = await readJson(req, 2_000);
      if (!checkCode(body.code)) return send(res, 401, { ok: false, error: codeConfigured() ? 'wrong' : 'not_configured' });
      return send(res, 200, { ok: true }, 'application/json', { 'Set-Cookie': sessionCookie(req) });
    }
    if (url.pathname === '/api/console/logout' && req.method === 'POST') return send(res, 200, { ok: true }, 'application/json', { 'Set-Cookie': clearCookie() });
    if (url.pathname === '/api/health') {
      const x = await xrayAvailable();
      return send(res, 200, { ok: true, xray: x.ok, xrayBrowser: x.ok ? `${x.channel} ${x.version}` : x.error, ai: aiConfigured(), intel: intelConfigured(), connectors: connectorsConfigured(), console: consoleOk(req), demo: DEMO, port: PORT });
    }
    // ---------- URL Judge: verdict + score + reasons for one URL or a whole list (hidden test sets, feeds) ----------
    const ONLINE_ONLY = 'Online checks fetch the link from this server, so they run only on the Veto server itself (localhost) or with the console token.';
    if (url.pathname === '/api/v1/judge' && req.method === 'GET') {
      const u = url.searchParams.get('url') || '';
      const online = url.searchParams.get('online') === '1';
      if (online && !consoleOk(req)) return send(res, 403, { error: 'console', message: ONLINE_ONLY });
      if (online && limited(ip, 60)) return send(res, 429, { error: 'rate' });
      return send(res, 200, online ? await judgeOnline(u) : judgeOffline(u));
    }
    if (url.pathname === '/api/v1/judge' && req.method === 'POST') {
      const body = await readJson(req, 3_000_000);
      const online = !!body.online;
      if (online && !consoleOk(req)) return send(res, 403, { error: 'console', message: ONLINE_ONLY });
      if (limited(ip, online ? 10 : 30)) return send(res, 429, { error: 'rate' });
      const rows = Array.isArray(body.urls)
        ? body.urls.map(x => (typeof x === 'string' ? { url: x, label: null } : { url: String(x.url || ''), label: x.label === 1 || x.label === 0 ? x.label : null }))
        : parseList(body.text || '');
      const cap = online ? 400 : 20000;
      if (rows.length > cap) return send(res, 413, { error: 'too many', message: 'Up to ' + cap + ' URLs per request ' + (online ? 'online' : 'offline') + '; use npm run judge for more.' });
      return send(res, 200, await judgeList(rows, { online, concurrency: 16 }));
    }
    if (url.pathname === '/api/number' && req.method === 'POST') {
      // caller check: only the number arrives here (never names, never messages); nothing is logged
      if (limited(ip, 30)) return send(res, 429, { ok: false, error: 'rate' });
      const body = await readJson(req, 2_000);
      const offline = callerCheck(String(body.number || ''), { inContacts: !!body.inContacts });
      const online = await ipqsPhone(body.number);
      const signals = [...offline.signals, ...(online?.signals || [])];
      const risk = +(1 - signals.reduce((p, s) => p * (1 - s.w), 1)).toFixed(3);
      return send(res, 200, { ok: true, ...offline, online, signals, risk,
        verdict: risk >= 0.7 ? 'danger' : risk >= 0.3 ? 'caution' : offline.verdict });
    }
    if (url.pathname === '/api/xray' && req.method === 'POST') {
      if (limited(ip)) return send(res, 429, { ok: false, error: 'rate', message: 'Too many X-rays, wait a minute.' });
      const { url: target } = await readJson(req, 10_000);
      if (!consoleOk(req) && xrayBudgetSpent()) return send(res, 429, { ok: false, error: 'rate', message: 'The X-ray chamber is busy, try again in a few minutes.' });
      const result = await xray(target, { demoHosts: DEMO, ai: aiConfigured() ? { inspectScreenshot } : null });
      // the scam SITE goes into the case file (address without query string + evidence); who asked is never stored
      const c = recordCase(result);
      if (c) {
        result.caseId = c.id;
        const camp = campaignOf(c.id);
        if (camp) result.campaign = { id: camp.id, size: camp.size, links: camp.links.slice(0, 6) };
      }
      return send(res, 200, result);
    }
    // Every representation of a stored case shares the police console's access policy.
    if ((url.pathname.startsWith('/api/case/') || url.pathname.startsWith('/api/dossier/')) && !consoleOk(req)) {
      return send(res, 403, { error: 'console', message: 'Sign in at /police to access stored case evidence.' });
    }
    const dm = /^\/api\/dossier\/([a-f0-9]{12})$/.exec(url.pathname);
    if (dm) {
      const rec = getCase(dm[1]);
      if (!rec) return send(res, 404, { error: 'no such case' });
      return send(res, 200, dossierHtml(rec, { campaign: campaignOf(rec.id), shot: shotDataUrl(shotPath(rec.id)), review: reviewOf(rec.id) }), 'text/html; charset=utf-8');
    }
    const zm = /^\/api\/case\/([a-f0-9]{12})\/evidence\.(zip|pdf)$/.exec(url.pathname);
    if (zm) {
      const rec = getCase(zm[1]);
      if (!rec) return send(res, 404, { error: 'no such case' });
      const b = await evidenceBundle(rec, { campaign: campaignOf(rec.id), shotFile: shotPath(rec.id), review: reviewOf(rec.id) });
      if (zm[2] === 'pdf') return b.pdf ? send(res, 200, b.pdf, 'application/pdf', { 'Content-Disposition': `inline; filename="veto-case-${rec.id}.pdf"` }) : send(res, 503, { error: 'pdf unavailable' });
      return send(res, 200, b.zip, 'application/zip', { 'Content-Disposition': `attachment; filename="veto-evidence-${rec.registrable || rec.id}-${rec.id}.zip"` });
    }
    // ---------- police console: one case in full, its picture, and the officer sign-off ----------
    const cm = /^\/api\/case\/([a-f0-9]{12})(\/shot\.jpg|\/review)?$/.exec(url.pathname);
    if (cm) {
      const rec = getCase(cm[1]);
      if (!rec) return send(res, 404, { error: 'no such case' });
      if (cm[2] === '/shot.jpg') {
        const file = shotPath(rec.id);
        return file ? send(res, 200, await fs.readFile(file), 'image/jpeg') : send(res, 404, { error: 'no picture' });
      }
      if (cm[2] === '/review') {
        if (req.method !== 'POST') return send(res, 405, { error: 'method' });
        const body = await readJson(req, 4_000);
        try { return send(res, 200, { ok: true, review: recordReview({ caseId: rec.id, host: rec.finalHost, decision: body.decision, officer: body.officer, note: body.note }) }); }
        catch (e) { if (e.code === 400) return send(res, 400, { ok: false, error: e.message }); throw e; }
      }
      return send(res, 200, { ok: true, case: rec, campaign: campaignOf(rec.id), review: reviewOf(rec.id), reports: reportTexts(rec) });
    }
    if (url.pathname === '/api/audit') {
      if (!consoleOk(req)) return send(res, 403, { error: 'console' });
      return send(res, 200, { ok: true, ...auditLog() });
    }
    const sm = /^\/api\/case\/([a-f0-9]{12})\/stix$/.exec(url.pathname);
    if (sm) {
      const rec = getCase(sm[1]);
      if (!rec) return send(res, 404, { error: 'no such case' });
      return send(res, 200, JSON.stringify(stixBundle(rec, { campaign: campaignOf(rec.id) }), null, 1), 'application/json', { 'Content-Disposition': `inline; filename="veto-case-${rec.id}.stix.json"` });
    }
    // ---------- police console: Sentinel ----------
    if (url.pathname.startsWith('/api/sentinel')) {
      if (!consoleOk(req)) return send(res, 403, { error: 'console', message: 'The police console answers only on the Veto server itself.' });
      const XR = { run: u => xray(u, { demoHosts: DEMO, ai: aiConfigured() ? { inspectScreenshot } : null }), record: (r, o) => recordCase(r, o) };
      if (url.pathname === '/api/sentinel' && req.method === 'GET') {
        return send(res, 200, { ok: true, ...overview(), campaigns: campaigns(), cases: listCases().slice(0, 150).map(brief), connectors: connectorsConfigured(),
          institutions: INSTITUTIONS.filter(i => i.domains.length && !i.generic).map(i => ({ id: i.id, name: i.name, type: i.type, priority: PRIORITY.includes(i.id) })) });
      }
      if (url.pathname === '/api/sentinel/helplines' && req.method === 'POST') {
        const body = await readJson(req, 1000);
        const inst = INSTITUTIONS.find(i => i.id === body.inst && !i.generic && i.domains.length);
        if (!inst) return send(res,400,{error:'Unknown institution'});
        return send(res,200,await helplineHunt(inst));
      }
      if (url.pathname === '/api/sentinel/job') return send(res, 200, { ok: true, job: getJob() });
      // training cases: X-ray Veto's own harmless demo scam pages, so a new officer can practise on a full case file
      if (url.pathname === '/api/sentinel/training' && req.method === 'POST') {
        if (!DEMO) return send(res, 409, { ok: false, error: 'demo_off' });
        const made = [];
        for (const sub of TRAINING_HOSTS) {
          const r = await XR.run(`http://${sub}.localhost:${PORT}/`).catch(() => null);
          const c = r?.ok ? recordCase(r, { source: 'training' }) : null;
          if (c) made.push(c.id);
        }
        return send(res, 200, { ok: true, cases: made });
      }
      if (url.pathname === '/api/sentinel/sweep' && req.method === 'POST') {
        const body = await readJson(req, 10_000);
        const insts = Array.isArray(body.insts) && body.insts.length ? body.insts.map(String).slice(0, 40) : PRIORITY;
        const kinds = Array.isArray(body.kinds) && body.kinds.length ? body.kinds : ['lookalike', 'nrd', 'ct', 'search', 'maps'];
        sweep({ insts, kinds, connectors: kinds.some(k => k === 'search' || k === 'maps') ? connectors : null, xray: XR, xrayTop: Math.min(10, Number(body.xrayTop) || 0) })
          .catch(e => console.error('[veto] sweep', e));
        return send(res, 202, { ok: true, job: getJob() });
      }
      if (url.pathname === '/api/sentinel/xray' && req.method === 'POST') {
        const body = await readJson(req, 5_000);
        const host = String(body.host || '').toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
        if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(host)) return send(res, 400, { error: 'bad host' });
        const r = await xraySuspect(host, XR);
        return send(res, 200, { ok: true, suspect: r.suspect, caseId: r.caseId, verdict: r.result.verdict || null, risk: r.result.risk ?? null, message: r.result.message || null });
      }
      return send(res, 404, { error: 'not found' });
    }
    if (url.pathname === '/api/ai' && req.method === 'POST') {
      if (!aiConfigured()) return send(res, 501, { error: 'ai_off', message: 'AI deep check is not configured on this server (set ANTHROPIC_API_KEY).' });
      if (limited(ip, 10)) return send(res, 429, { error: 'rate' });
      const body = await readJson(req, 50_000);
      const out = await deepCheck({ text: body.text, channel: body.channel });
      return send(res, 200, out);
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { error: 'method' });
    // an unknown API path answers with JSON 404, never with the app shell (a wrong endpoint must not look like success)
    if (url.pathname.startsWith('/api/')) return send(res, 404, { error: 'not found' });
    const policePage = ['/', '/police', '/police/'].includes(url.pathname);
    return await serveStatic(req, res, policePage ? '/police.html' : url.pathname);
  } catch (e) {
    const code = e.code === 413 ? 413 : e instanceof SyntaxError ? 400 : 500;
    if (code === 500) console.error('[veto]', e);
    return send(res, code, { error: code === 413 ? 'too large' : code === 400 ? 'bad request' : 'server error' });
  }
});

const store = await storeRestore();
server.listen(PORT, () => {
  console.log(`Veto running on http://localhost:${PORT}`);
  console.log(`  Case file: ${store.mode === 'database' ? (store.restored ? `database copy ON (restored ${store.restored.cases} cases, ${store.restored.signoffs} sign-offs, ${store.restored.pictures} pictures)` : 'database copy configured but unreachable, using local files') : 'local files only (set VETO_STORE_* to keep it across restarts)'}`);
  console.log(`  AI deep check: ${aiConfigured() ? 'ON (' + (process.env.VETO_AI_MODEL || 'claude-opus-5-5') + ')' : 'off (set ANTHROPIC_API_KEY to enable)'}`);
  const intel = intelConfigured();
  console.log(`  Reputation look-ups: URLhaus/MalwareBazaar ${intel.abusech ? 'ON' : 'off (set ABUSECH_KEY)'} · phone (IPQS) ${intel.ipqs ? 'ON' : 'off (set IPQS_KEY)'}`);
  if (DEMO) console.log(`  Demo scam pages: http://secure-verify-uae.localhost:${PORT}/  http://parcel-redelivery.localhost:${PORT}/  http://bank-app-update.localhost:${PORT}/  http://phone-cleaner.localhost:${PORT}/  http://go-short.localhost:${PORT}/go  http://salik-fine-pay.localhost:${PORT}/ (cloaked)`);
  xrayAvailable().then(x => console.log(`  Link X-ray chamber: ${x.ok ? `ready (${x.channel} ${x.version})` : 'unavailable, ' + x.error}`));
});
