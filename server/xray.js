// Link X-ray chamber, opens a suspicious link in a throw-away headless browser so the user
// never has to. Returns a picture of the page, what the page actually does, WHAT IT WANTS from you,
// WHERE it would send what you type, and whether the app it pushes is a trojan.
//
// Hardening in this MVP: fresh incognito context per link, downloads refused (files are fetched
// separately, size-capped, parsed, never run), every permission denied, service workers blocked,
// WebSockets mocked (nothing leaves), private-network requests blocked (SSRF guard on every request),
// a watcher script neutralises clipboard / notification / full-screen tricks, 15 s navigation budget,
// browser sandbox left ON. The canary trap types only FAKE values and blocks every request that
// carries them. Production: run each detonation in a disposable micro-VM (see docs/TECHNICAL.md).

import { chromium } from 'playwright-core';
import { checkHost, fetchBytes } from './netguard.js';
import { inspectApk, sha256 } from './apk.js';
import { urlhausUrl, bazaarHash } from './intel.js';
import { hashImages, sniffImage, sha256hex, shodanFaviconHash, matchLogos, brandSibling, cloakProbe, cloakSignal, kitPrint, campaignKeys, rdapDomain, ipInfo, takedownTargets } from './forensics.js';
import { WATCHER, classifyField, fillClass, newRun, canaryValues, carriesCanary, classifySink, scanCode, pageTricks, pageIntent } from './xray-intent.js';
import { analyzeUrl, splitDomain, officialFor } from '../engine/url.js';
import { findInstitutions } from '../engine/extract.js';
import { matchForm } from '../engine/normalize.js';
import { analyze } from '../engine/index.js';

const MOBILE_UA = 'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36';
const NAV_TIMEOUT = 15000;
const MAX_PARALLEL = 2;
const CRIMINAL_SINKS = ['telegram', 'discord', 'apps_script', 'form_service', 'cloud_db', 'tunnel'];
const BRAND_TYPES = new Set(['bank', 'gov', 'police', 'regulator', 'telecom', 'courier', 'airline']);

let browserPromise = null;
let browserInfo = null;
async function launch() {
  const order = process.env.XRAY_CHANNEL ? [process.env.XRAY_CHANNEL] : process.platform === 'win32' ? ['msedge', 'chrome', null] : [null, 'chrome', 'msedge'];
  let lastErr;
  for (const channel of order) {
    try {
      const b = await chromium.launch({
        channel: channel || undefined,
        headless: true,
        args: ['--disable-extensions', '--disable-background-networking', '--no-first-run', '--disable-sync', '--mute-audio',
          '--disable-features=Translate,AutofillServerCommunication,MediaRouter', '--disable-component-update']
      });
      browserInfo = { channel: channel || 'chromium', version: b.version() };
      return b;
    } catch (e) { lastErr = e; }
  }
  throw lastErr;
}
export function getBrowser() {
  if (!browserPromise) browserPromise = launch().catch(e => { browserPromise = null; throw e; });
  return browserPromise;
}
export async function xrayAvailable() {
  try { await getBrowser(); return { ok: true, ...browserInfo }; } catch (e) { return { ok: false, error: String(e.message || e).split('\n')[0] }; }
}

// tiny semaphore
let running = 0;
const queue = [];
async function slot() {
  if (running < MAX_PARALLEL) { running++; return; }
  await new Promise(r => queue.push(r));
  running++;
}
function release() { running--; const n = queue.shift(); if (n) n(); }

const cache = new Map(); // url -> {t, result}
const sig = (id, w, en, ar) => ({ id, w, en, ar });
const sleep = ms => new Promise(r => setTimeout(r, ms));

const FIELD_TEXT = {
  card: ['card number', 'رقم البطاقة'], cvv: ['CVV', 'رمز CVV'], expiry: ['card expiry', 'تاريخ انتهاء البطاقة'], otp: ['one-time code', 'رمز التحقق'],
  password: ['password', 'كلمة المرور'], pin: ['ATM PIN', 'الرقم السري'], eid: ['Emirates ID', 'رقم الهوية'], iban: ['IBAN', 'رقم الآيبان'],
  seed: ['wallet recovery phrase', 'العبارة السرية للمحفظة']
};
const TRICK_TEXT = {
  vibrate: ['vibration', 'الاهتزاز'], fullscreen: ['full-screen', 'ملء الشاشة'], backtrap: ['a back-button trap', 'منع زر الرجوع'],
  leavetrap: ['a “don’t leave” trap', 'منع المغادرة'], beep: ['alarm sounds', 'أصوات إنذار'], dialogs: ['repeated pop-ups', 'نوافذ منبثقة متكررة']
};

// Types FAKE values into the page's fields, presses its button and lets the route handler catch
// (and block) whatever the page tries to send.
async function springTrap(page, trap) {
  const vals = canaryValues(trap.run);
  trap.armed = true;
  let filled = 0, last = null, submitted = false;
  const handles = await page.$$('input, textarea').catch(() => []);
  for (const el of handles.slice(0, 30)) {
    const f = await el.evaluate(e => {
      const st = getComputedStyle(e), r = e.getBoundingClientRect();
      return {
        visible: e.type !== 'hidden' && st.display !== 'none' && st.visibility !== 'hidden' && r.width > 0 && r.height > 0 && !e.disabled && !e.readOnly,
        type: (e.type || 'text').toLowerCase(), name: e.name || '', id: e.id || '', ph: e.placeholder || '', ac: e.autocomplete || '',
        label: ((e.labels && e.labels[0] && e.labels[0].innerText) || e.getAttribute('aria-label') || '').slice(0, 80)
      };
    }).catch(() => null);
    if (!f || !f.visible || /^(submit|button|reset|checkbox|radio|file|image|range|color|hidden|date|month|week|time)$/.test(f.type)) continue;
    let v = vals[fillClass(f)] ?? vals.text;
    if (f.type === 'number') v = v.replace(/\D/g, '') || '1234';
    try { await el.fill(v, { timeout: 1200 }); filled++; last = el; } catch { /* field refused */ }
  }
  if (!filled) return { filled, submitted };
  const btn = await page.$('form button[type=submit], form input[type=submit], button[type=submit], input[type=submit], form button:not([type=button]):not([type=reset])').catch(() => null);
  if (btn) submitted = await btn.click({ timeout: 1500 }).then(() => true, () => false);
  if (!submitted) {
    submitted = await page.locator('button, [role=button], a.btn, input[type=button]')
      .filter({ hasText: /continue|next|submit|verify|confirm|pay|log ?in|sign ?in|track|proceed|متابعة|تأكيد|تحقق|ادفع|دخول|التالي/i })
      .first().click({ timeout: 1500 }).then(() => true, () => false);
  }
  if (!submitted && last) submitted = await last.press('Enter', { timeout: 800 }).then(() => true, () => false);
  const t0 = Date.now();
  while (Date.now() - t0 < 3000 && !trap.caught.length) await sleep(200);
  if (trap.caught.length) await sleep(500); // let parallel sends show up too
  return { filled, submitted };
}

export async function xray(rawUrl, { demoHosts = false, ai = null } = {}) {
  const t0 = Date.now();
  let url = String(rawUrl || '').trim();
  if (!/^[a-z][a-z0-9+.\-]*:\/\//i.test(url)) url = 'http://' + url;
  let u;
  try { u = new URL(url); } catch { return { ok: false, error: 'bad_url', message: 'That does not look like a web address.' }; }
  if (!['http:', 'https:'].includes(u.protocol)) return { ok: false, error: 'scheme', message: 'Only web links (http/https) can be X-rayed.' };
  const hit = cache.get(u.href);
  if (hit && Date.now() - hit.t < 10 * 60 * 1000) return { ...hit.result, cached: true };

  const pre = await checkHost(u.hostname, { demoHosts });
  if (!pre.ok) {
    return { ok: false, input: u.href, error: 'blocked', message: pre.reason === 'domain does not resolve'
      ? 'This website does not exist (anymore). Scam sites are often taken down within days, treat the message as suspicious.'
      : `Veto will not open this link: it ${pre.reason}.`, reason: pre.reason, static: analyzeUrl(u.href), ms: Date.now() - t0 };
  }

  await slot();
  let context;
  try {
    const browser = await getBrowser();
    context = await browser.newContext({
      acceptDownloads: false, viewport: { width: 390, height: 780 }, deviceScaleFactor: 1, isMobile: true, hasTouch: true,
      userAgent: MOBILE_UA, locale: 'en-AE', timezoneId: 'Asia/Dubai', serviceWorkers: 'block', permissions: [],
      ignoreHTTPSErrors: true, javaScriptEnabled: true, bypassCSP: false
    });
    await context.addInitScript(WATCHER);
    const requests = [], blocked = [], downloads = [], dialogs = [], popups = [], navs = [], sockets = [];
    const trap = { armed: false, run: newRun(), caught: [], otherPosts: 0 };
    const hostChecks = new Map();
    await context.route('**/*', async route => {
      const req = route.request();
      let ru;
      try { ru = new URL(req.url()); } catch { return route.abort(); }
      if (ru.protocol === 'data:' || ru.protocol === 'blob:') return route.continue();
      if (!['http:', 'https:'].includes(ru.protocol)) return route.abort();
      if (trap.armed) {
        let body = '';
        try { body = req.postData() || ''; } catch { /* binary */ }
        if (carriesCanary(req.url(), trap.run) || carriesCanary(body, trap.run)) {
          trap.caught.push({ url: req.url(), method: req.method() });
          return route.abort('blockedbyclient'); // the fake data never leaves the chamber
        }
        if (!/^(GET|HEAD|OPTIONS)$/i.test(req.method())) { trap.otherPosts++; return route.abort('blockedbyclient'); }
      }
      let chk = hostChecks.get(ru.hostname);
      if (!chk) { chk = checkHost(ru.hostname, { demoHosts }); hostChecks.set(ru.hostname, chk); }
      const c = await chk;
      if (!c.ok) { blocked.push(ru.hostname); return route.abort('blockedbyclient'); }
      if (['media', 'font'].includes(req.resourceType())) return route.abort();
      requests.push({ host: ru.hostname, type: req.resourceType() });
      return route.continue();
    });
    // WebSockets (live phishing panels) are mocked: the page thinks it is connected, nothing leaves.
    await context.routeWebSocket(/.*/, ws => {
      sockets.push(ws.url());
      ws.onMessage(m => {
        if (trap.armed && carriesCanary(typeof m === 'string' ? m : Buffer.from(m).toString('latin1'), trap.run)) trap.caught.push({ url: ws.url(), method: 'WS' });
      });
    }).catch(() => {});
    const page = await context.newPage();
    const code = [];
    let codeSize = 0;
    const codeJobs = [];
    const imgs = [], imgJobs = [];
    page.on('download', d => downloads.push({ url: d.url(), file: d.suggestedFilename() }));
    page.on('dialog', d => { dialogs.push({ type: d.type(), message: d.message().slice(0, 160) }); d.dismiss().catch(() => {}); });
    page.on('popup', p => { popups.push(p.url()); p.close().catch(() => {}); });
    page.on('framenavigated', f => { if (f === page.mainFrame()) navs.push(f.url()); });
    page.on('response', r => {
      try {
        const h = r.headers();
        const cd = h['content-disposition'] || '';
        const ct = h['content-type'] || '';
        if (r.request().isNavigationRequest() && (/attachment/i.test(cd) || /android\.package-archive|x-msdownload|x-msdos-program|octet-stream/i.test(ct))) {
          const file = (/filename\*?=(?:UTF-8'')?"?([^";]+)/i.exec(cd) || [])[1] || r.url().split('/').pop();
          if (!downloads.some(d => d.url === r.url())) downloads.push({ url: r.url(), file });
        }
        if (r.request().resourceType() === 'image' && r.status() === 200 && imgJobs.length < 24) {
          const iu = r.url();
          imgJobs.push(r.body().then(b => { if (b.length && b.length < 600_000) imgs.push({ url: iu, bytes: b, type: sniffImage(b, ct) }); }, () => {}));
        }
        if (r.request().resourceType() === 'script' && codeSize < 1_500_000) {
          codeJobs.push(r.text().then(t => { codeSize += Math.min(t.length, 400_000); code.push(t.slice(0, 400_000)); }, () => {}));
        }
      } catch { /* ignore */ }
    });

    let resp = null, navError = null;
    try {
      resp = await page.goto(u.href, { waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT });
    } catch (e) {
      navError = String(e.message || e).split('\n')[0];
    }
    if (!navError || /Download is starting/i.test(navError)) {
      await page.waitForLoadState('networkidle', { timeout: 3500 }).catch(() => {});
      await page.waitForTimeout(400);
    }

    const chain = [];
    let rq = resp?.request();
    while (rq) { chain.unshift(rq.url()); rq = rq.redirectedFrom(); }
    for (const n of navs) if (n && n !== 'about:blank' && !chain.includes(n)) chain.push(n);
    if (!chain.length) chain.push(u.href);
    const finalUrl = page.url() && page.url() !== 'about:blank' && !page.url().startsWith('chrome-error:') ? page.url() : chain[chain.length - 1];

    const browserStatus = resp?.status() ?? null;
    let redirectObservation = null;
    if (browserStatus === 403 || !resp) {
      const probe = await fetchBytes(u.href, { demoHosts, headersOnly: true, timeout: 5000 }).catch(() => null);
      redirectObservation = { status: probe?.status ?? null, destination: probe?.destination ?? null };
    }

    let facts = { inputs: [], forms: [], text: '', title: '', obf: false, iframes: 0, metaRefresh: '', links: [], imgs: '', inline: '', events: [], icons: [], logoImgs: [], html: '', skel: null };
    try {
      facts = await page.evaluate(() => {
        const q = s => Array.from(document.querySelectorAll(s));
        const vis = el => { const st = getComputedStyle(el); return el.type !== 'hidden' && st.display !== 'none' && st.visibility !== 'hidden'; };
        const inputs = q('input, select, textarea').filter(vis).slice(0, 60).map(el => ({
          type: (el.type || el.tagName || '').toLowerCase(), name: el.name || '', id: el.id || '', ph: el.placeholder || '',
          ac: el.autocomplete || '', ml: el.maxLength > 0 ? el.maxLength : null,
          label: ((el.labels && el.labels[0] && el.labels[0].innerText) || el.getAttribute('aria-label') || '').slice(0, 80)
        }));
        const forms = q('form').slice(0, 10).map(f => ({ action: f.action || '', method: (f.getAttribute('method') || 'get').toLowerCase() }));
        const scripts = q('script').map(s => (s.src ? '' : s.textContent || '')).join('\n');
        return {
          inputs, forms,
          text: (document.body ? document.body.innerText : '').replace(/\s+/g, ' ').slice(0, 4000),
          title: (document.title || '').slice(0, 200),
          obf: scripts.length > 2000 && /eval\(|atob\(|unescape\(|fromCharCode|\\x[0-9a-f]{2}/i.test(scripts),
          iframes: q('iframe').length,
          metaRefresh: (document.querySelector('meta[http-equiv="refresh" i]') || {}).content || '',
          links: q('a[href]').slice(0, 150).map(a => a.href),
          imgs: q('img').slice(0, 40).map(i => `${i.alt || ''} ${(i.currentSrc || i.src || '').split('/').pop().split('?')[0]}`).join(' ').slice(0, 1500),
          inline: scripts.slice(0, 300000),
          events: (window.__veto && window.__veto.ev) || [],
          icons: q('link[rel~="icon" i], link[rel="shortcut icon" i], link[rel~="apple-touch-icon" i]').map(l => l.href).filter(Boolean).slice(0, 4),
          logoImgs: q('img').filter(i => /logo|brand/i.test(`${i.currentSrc || i.src} ${i.alt} ${i.className} ${i.id} ${i.parentElement ? i.parentElement.className : ''}`)).slice(0, 4).map(i => i.currentSrc || i.src),
          html: document.documentElement.outerHTML.slice(0, 300000),
          skel: (() => {
            const norm = s => String(s || '').toLowerCase().replace(/[0-9a-f]{8,}/g, 'h').replace(/\d+/g, '0').slice(0, 32);
            const tags = [];
            for (const el of (document.body ? Array.from(document.body.querySelectorAll('*')) : []).slice(0, 1500)) {
              const t = el.tagName.toLowerCase();
              if (t !== 'svg' && el.closest('svg')) continue;
              const cls = Array.from(el.classList).map(norm).filter(Boolean).sort().slice(0, 3).join('.');
              tags.push(cls ? t + '.' + cls : t);
            }
            const base = u => { try { return new URL(u, location.href).pathname.split('/').pop().toLowerCase().replace(/[.-][0-9a-f]{6,}(?=\.)/g, '').slice(0, 40); } catch { return ''; } };
            return {
              tags: tags.join(' '),
              fields: q('input, select, textarea, button').slice(0, 60).map(e => [e.tagName.toLowerCase(), (e.type || '').toLowerCase(), norm(e.name), norm(e.id), norm(e.placeholder).slice(0, 16)].join(':')),
              assets: [...new Set([...q('script[src]').map(x => x.src), ...q('link[rel=stylesheet]').map(x => x.href)].map(base).filter(Boolean))].slice(0, 30),
              forms: q('form').slice(0, 6).map(f => { let p = ''; try { p = new URL(f.action, location.href).pathname.toLowerCase(); } catch { /* none */ } return `${(f.getAttribute('method') || 'get').toLowerCase()} ${p}`; })
            };
          })()
        };
      });
    } catch { /* page may have navigated away / download */ }

    let screenshot = null;
    try {
      const buf = await page.screenshot({ type: 'jpeg', quality: 62, fullPage: false, timeout: 5000 });
      screenshot = 'data:image/jpeg;base64,' + buf.toString('base64');
    } catch { /* no page to capture */ }

    let tls = null;
    try {
      const sd = resp ? await resp.securityDetails() : null;
      if (sd && sd.issuer) tls = { issuer: sd.issuer, protocol: sd.protocol, validFrom: sd.validFrom ? new Date(sd.validFrom * 1000).toISOString() : null };
    } catch { /* ignore */ }

    // ---------- verdict ----------
    const fin = analyzeUrl(finalUrl);
    const first = analyzeUrl(u.href);
    const S = [];
    const finalReg = splitDomain(fin.host).registrable;
    const official = officialFor(finalReg);
    for (const s of [...first.signals, ...fin.signals]) if (!S.some(x => x.id === s.id)) S.push(s);
    if (official) S.length = 0; // landing on an official site: static link signals no longer apply

    const asks = new Set();
    for (const f of facts.inputs) for (const c of classifyField(f)) asks.add(c);

    // forensics that run in parallel with the trap: cloaking (phone vs computer vs crawler), who runs the
    // domain and the server, the tab icon. Skipped for official sites.
    const finalIps = (await (hostChecks.get(fin.host) || Promise.resolve(pre)).catch(() => pre))?.ips || pre.ips || [];
    const cloakP = official || navError ? Promise.resolve(null) : cloakProbe(finalUrl, { demoHosts }).catch(() => null);
    const infraP = official ? Promise.resolve(null) : Promise.all([rdapDomain(finalReg), ipInfo(finalIps[0])]).then(([domain, host]) => ({ domain, host }), () => null);
    const iconUrl = (facts.icons || [])[0] || (() => { try { return new URL('/favicon.ico', finalUrl).href; } catch { return null; } })();

    // ---------- canary trap (only on non-official pages that ask for secrets) ----------
    let trapInfo = { ran: false };
    if (!official && asks.size && !(navError && !/Download is starting/i.test(navError))) {
      const r = await springTrap(page, trap).catch(() => ({ filled: 0, submitted: false }));
      trapInfo = { ran: true, filled: r.filled, submitted: r.submitted };
    }
    let events = facts.events || [];
    try {
      const more = await page.evaluate(() => (window.__veto && window.__veto.ev) || []);
      for (const e of more) if (!events.some(x => x.t === e.t && x.d === e.d)) events = events.concat(e);
    } catch { /* navigated */ }
    await Promise.race([Promise.allSettled(codeJobs), sleep(1500)]);

    const seen = new Set();
    for (let i = downloads.length - 1; i >= 0; i--) { if (seen.has(downloads[i].url)) downloads.splice(i, 1); else seen.add(downloads[i].url); }
    // Who does the page claim to be? The site's own address is removed first (parked pages print their domain,
    // which is not a claim), and a passing mention ("pay at Carrefour") does not count.
    let brandText = `${facts.title} ${facts.text.slice(0, 1500)} ${facts.imgs || ''}`;
    for (const hw of new Set([fin.host, u.hostname, finalReg].filter(Boolean))) brandText = brandText.split(hw).join(' ');
    const brands = findInstitutions(matchForm(brandText), brandText).filter(c => !c.inst.generic && !c.mention);
    const pretends = brands.find(b => !b.inst.domains.includes(finalReg) && !brandSibling(b.inst, finalReg));
    if (!official && asks.size) {
      const list = [...asks].filter(a => FIELD_TEXT[a]);
      const w = asks.has('pin') || asks.has('seed') ? 0.88 : asks.has('cvv') && asks.has('card') ? 0.78 : asks.has('otp') ? 0.62 : asks.has('card') ? 0.6 : asks.has('password') ? 0.45 : 0.3;
      if (list.length) S.push(sig('asks_secrets', w, `The page asks you to type: ${list.map(a => FIELD_TEXT[a][0]).join(', ')}.${asks.has('pin') ? ' No website ever needs your ATM PIN.' : ''}`,
        `الصفحة تطلب منك كتابة: ${list.map(a => FIELD_TEXT[a][1]).join('، ')}.${asks.has('pin') ? ' لا يحتاج أي موقع إلى رقمك السري.' : ''}`));
    }

    // where did the fake data go?
    const exfil = [];
    for (const c of trap.caught) {
      const s = classifySink(c.url, finalReg);
      if (s && !exfil.some(e => e.kind === s.kind && e.host === s.host)) exfil.push({ ...s, method: c.method });
    }
    const crim = exfil.find(e => CRIMINAL_SINKS.includes(e.kind));
    if (crim) {
      S.push(sig('exfil_' + crim.kind, 0.96, `Veto typed FAKE details into the page. It immediately tried to send them to ${crim.en}${crim.bot ? ` (${crim.bot})` : ''}. Veto blocked the send.`,
        `كتب فيتو بيانات مزيّفة في الصفحة، فحاولت فوراً إرسالها إلى ${crim.ar}. منع فيتو الإرسال.`));
    } else if (exfil.length && !official) {
      const w = pretends || asks.has('card') || asks.has('otp') ? 0.65 : 0.35;
      S.push(sig('exfil_server', w, `Veto typed FAKE details. The page sent them to ${exfil[0].en} (blocked).`, `كتب فيتو بيانات مزيّفة، فأرسلتها الصفحة إلى ${exfil[0].ar} (تم المنع).`));
    }
    const codeSinks = official ? [] : scanCode(`${facts.inline || ''}\n${code.join('\n')}`);
    if (codeSinks.length && !crim) {
      S.push(sig('exfil_code', 0.85, `The page’s code contains ${codeSinks[0].en} (${codeSinks[0].evidence}), phishing kits use this to deliver stolen data to criminals.`,
        `شيفرة الصفحة تحتوي على ${codeSinks[0].ar}، تستخدمها أدوات التصيّد لتسليم البيانات المسروقة للمحتالين.`));
    }

    // tricks the page played (watcher script)
    const tricks = pageTricks({ events, text: facts.text, links: facts.links || [], dialogs: dialogs.length });
    if (!official) {
      if (tricks.clipboardCommand) S.push(sig('clipboard_command', 0.92, `The page secretly copied a command to your clipboard (“${tricks.clipboardCommand.slice(0, 60)}…”). Pasting it would install malware.`, 'نسخت الصفحة أمراً خفياً إلى الحافظة. لصقه سيثبّت برنامجاً خبيثاً.'));
      if (tricks.scare) {
        const how = tricks.scareTricks.map(t => TRICK_TEXT[t]).filter(Boolean);
        S.push(sig('fake_virus_alert', 0.82, `FAKE virus warning: websites cannot scan your phone. Real phones never show “virus detected” pages${how.length ? `. This one uses ${how.map(x => x[0]).join(', ')} to panic you` : ''}.`,
          `تحذير فيروس مزيّف: المواقع لا تستطيع فحص هاتفك${how.length ? `، وتستخدم هذه الصفحة ${how.map(x => x[1]).join('، ')} لإثارة ذعرك` : ''}.`));
      } else if (tricks.scareTricks.length >= 2) {
        S.push(sig('pressure_tricks', 0.35, `The page uses ${tricks.scareTricks.map(t => TRICK_TEXT[t][0]).join(', ')} to stop you thinking.`, `تستخدم الصفحة ${tricks.scareTricks.map(t => TRICK_TEXT[t][1]).join('، ')} لمنعك من التفكير.`));
      }
      if (tricks.remote) S.push(sig('remote_access', 0.6, `The page pushes ${tricks.remote}, a remote-control app scammers use to watch your screen and your bank codes.`, `الصفحة تروّج لتطبيق ${tricks.remote}، يستخدمه المحتالون لمشاهدة شاشتك ورموز البنك.`));
      if (tricks.wallet) S.push(sig('wallet_drain', 0.55, 'The page wants to connect to a crypto wallet, wallet “drainer” pages empty it in one click.', 'الصفحة تريد ربط محفظة رقمية، صفحات «التفريغ» تفرغها بنقرة واحدة.'));
      if (tricks.push) S.push(sig('push_bait', 0.4, 'The page tells you to press “Allow”. That lets it send you fake alerts later.', 'الصفحة تطلب منك الضغط على «سماح»، ليرسل لك تنبيهات مزيّفة لاحقاً.'));
      if (tricks.chat.length) S.push(sig('move_to_chat', 0.25, 'The page moves you into a private WhatsApp / Telegram chat.', 'الصفحة تنقلك إلى محادثة خاصة على واتساب أو تيليجرام.'));
    }

    // the page's own words, read by the Veto rulebook (same engine as for messages)
    if (!official && facts.text && facts.text.length > 40) {
      try {
        const r = analyze({ text: facts.text.slice(0, 2500), channel: 'web' });
        const asksOrPressure = r.findings.filter(f => /^(policy|action|tactic)/.test(f.key || f.id));
        if ((r.verdict === 'scam' || r.verdict === 'high') && asksOrPressure.length) {
          const top = [...asksOrPressure].sort((a, b) => b.w - a.w)[0];
          if (top) S.push(sig('page_words', r.verdict === 'scam' ? 0.5 : 0.3, `The page’s own words match scam rules: ${top.title.en}`, `كلمات الصفحة تطابق قواعد الاحتيال: ${top.title.ar}`));
        }
      } catch { /* engine is best-effort here */ }
    }
    // copy-paste fakes load the real brand's logo / scripts straight from the real site
    if (!official) {
      const borrowed = [...new Set(requests.map(r => r.host))].map(h => officialFor(splitDomain(h).registrable)).find(i => i && BRAND_TYPES.has(i.type));
      if (borrowed) S.push(sig('borrowed_assets', 0.6, `The page loads pictures or code straight from ${borrowed.name.en}’s real website, a copy-paste fake.`, `الصفحة تحمّل صوراً أو شيفرة مباشرة من موقع ${borrowed.name.ar} الحقيقي، نسخة مزيّفة.`));
    }

    // ---------- the file it pushes: is it a virus? ----------
    // (a download the page started itself, or an app file its big button links to)
    let apk = null, bazaar = null;
    const offeredLink = !downloads.length && !official ? (facts.links || []).find(l => /^https?:.*\.apk([?#]|$)/i.test(l)) : null;
    const pushed = downloads[0] || (offeredLink && { url: offeredLink, file: decodeURIComponent(offeredLink.split(/[?#]/)[0].split('/').pop()), offered: true });
    if (pushed) {
      const d = pushed;
      const got = await fetchBytes(d.url, { demoHosts, maxBytes: 60 << 20, userAgent: MOBILE_UA });
      if (got.ok) {
        const zip = got.bytes.length > 4 && got.bytes.readUInt32LE(0) === 0x04034b50;
        apk = zip ? inspectApk(got.bytes) : { ok: false, sha256: sha256(got.bytes), size: got.bytes.length, error: 'not an Android app file' };
        bazaar = await bazaarHash(apk.sha256);
      } else apk = { ok: false, error: got.error };
      if (apk.ok && apk.capabilities.length) {
        const caps = apk.capabilities.slice(0, 5);
        S.push(sig(apk.trojanProfile ? 'apk_trojan' : 'apk_powers', apk.trojanProfile ? 0.97 : Math.min(0.9, Math.max(0.5, apk.risk)),
          `${apk.trojanProfile ? 'The app it pushes has the toolkit of a BANKING TROJAN. ' : ''}If installed, “${apk.label || d.file}” could: ${caps.map(c => c.en).join('; ')}.`,
          `${apk.trojanProfile ? 'التطبيق المدفوع يحمل أدوات حصان طروادة مصرفي. ' : ''}إذا ثبّته، يستطيع «${apk.label || d.file}»: ${caps.map(c => c.ar).join('؛ ')}.`));
      } else if (d.offered) {
        S.push(sig('apk_link', 0.6, `The page’s button downloads an app file (“${d.file}”) from outside the app store. Never install apps from links.`, `زر الصفحة ينزّل ملف تطبيق («${d.file}») من خارج متجر التطبيقات. لا تثبّت تطبيقات من الروابط أبداً.`));
      } else {
        S.push(sig('download_attempt', 0.9, `The page tried to download “${d.file}” onto your device. Veto blocked it. Never install apps from links.`, `حاولت الصفحة تنزيل «${d.file}» على جهازك وقد منعه فيتو. لا تثبّت تطبيقات من الروابط أبداً.`));
      }
      if (bazaar?.known) S.push(sig('known_malware', 0.99, `This exact file is a known malware sample${bazaar.signature ? ` (${bazaar.signature})` : ''}, MalwareBazaar.`, `هذا الملف عيّنة برمجيات خبيثة معروفة${bazaar.signature ? ` (${bazaar.signature})` : ''}, MalwareBazaar.`));
    }

    const pageHost = fin.host;
    const extForm = facts.forms.map(f => { try { return new URL(f.action).hostname; } catch { return ''; } })
      .find(h => h && h !== pageHost && splitDomain(h).registrable !== finalReg);
    if (extForm && !official) S.push(sig('third_party_form', 0.5, `Whatever you type is sent to a different website (${extForm}).`, `ما تكتبه يُرسل إلى موقع آخر (${extForm}).`));
    if (facts.obf && !official) S.push(sig('obfuscated_js', 0.3, 'The page hides its code (obfuscated scripts), common in phishing kits.', 'الصفحة تُخفي شيفرتها البرمجية، أمر شائع في أدوات التصيّد.'));
    if (dialogs.length) S.push(sig('dialogs', 0.3, `The page throws pop-up alerts at you (“${dialogs[0].message.slice(0, 60)}”).`, 'الصفحة تعرض نوافذ تنبيه منبثقة للضغط عليك.'));
    const hops = new Set(chain.map(c => { try { return splitDomain(new URL(c).hostname).registrable; } catch { return c; } }));
    if (hops.size >= 2 && !official) S.push(sig('redirects', hops.size >= 3 ? 0.35 : 0.2, `The link bounced through ${hops.size} different websites before landing.`, `مرّ الرابط عبر ${hops.size} مواقع مختلفة قبل الوصول.`));
    const [infra, cloak, urlhaus] = await Promise.all([infraP, cloakP, official ? null : urlhausUrl(u.href)]);
    const age = infra?.domain?.ageDays ?? null;
    if (age !== null) {
      if (age < 7) S.push(sig('new_domain', 0.6, `This website was registered only ${age} day(s) ago.`, `سُجّل هذا الموقع قبل ${age} يوم فقط.`));
      else if (age < 30) S.push(sig('new_domain', 0.45, `This website is only ${age} days old.`, `عمر هذا الموقع ${age} يوماً فقط.`));
      else if (age < 180) S.push(sig('young_domain', 0.15, `This website is less than 6 months old (${age} days).`, `عمر هذا الموقع أقل من 6 أشهر (${age} يوماً).`));
    }
    if (urlhaus?.listed) S.push(sig('urlhaus', 0.95, `URLhaus lists this link as malware${urlhaus.threat ? ` (${urlhaus.threat.replace(/_/g, ' ')})` : ''}.`, 'قاعدة URLhaus تصنّف هذا الرابط كرابط برمجيات خبيثة.'));
    if (navError && !/Download is starting/i.test(navError) && !screenshot) {
      S.push(sig('unreachable', 0.2, 'The site did not load, scam sites are often taken down quickly, or only show themselves to some visitors.', 'لم يُفتح الموقع، مواقع الاحتيال تُحذف بسرعة أو تظهر لبعض الزوار فقط.'));
    }

    // ---------- forensics: copied logo, cloaking, kit fingerprint, campaign keys ----------
    let forensics = null;
    if (!official) {
      await Promise.race([Promise.allSettled(imgJobs), sleep(1500)]);
      const iconSeen = imgs.find(i => i.url === iconUrl);
      if (iconUrl && !iconSeen) {
        const got = await fetchBytes(iconUrl, { demoHosts, maxBytes: 600_000, timeout: 5000, userAgent: MOBILE_UA }).catch(() => ({ ok: false }));
        if (got.ok) imgs.push({ url: iconUrl, bytes: got.bytes, type: sniffImage(got.bytes, got.contentType) });
      }
      const logoSet = new Set(facts.logoImgs || []);
      const iconSet = new Set([iconUrl, ...(facts.icons || [])]);
      const rank = { favicon: 0, logo: 1, image: 2 };
      const pick = imgs.filter(i => i.type).map(i => ({ ...i, kind: iconSet.has(i.url) || /favicon/i.test(i.url) ? 'favicon' : logoSet.has(i.url) || /logo|brand/i.test(i.url) ? 'logo' : 'image' }))
        .sort((a, b) => rank[a.kind] - rank[b.kind]).slice(0, 12);
      let ph = [];
      try { ph = await hashImages(await getBrowser(), pick); } catch { /* hashing is best-effort */ }
      const hashed = pick.map((p, k) => ({ url: p.url, kind: p.kind, sha256: sha256hex(p.bytes), ph: ph[k] || null }));
      const logos = matchLogos(hashed, finalReg);
      const fav = pick.find(p => p.kind === 'favicon');
      const kit = kitPrint(facts.skel);
      const keys = campaignKeys({ html: `${facts.html || ''}\n${(facts.inline || '').slice(0, 200000)}\n${code.join('\n').slice(0, 400000)}`, text: facts.text, links: facts.links || [] });
      forensics = { logos, favicon: fav ? { url: fav.url, sha256: sha256hex(fav.bytes), shodan: shodanFaviconHash(fav.bytes) } : null, cloaking: cloak, kit, keys, infra,
        takedown: takedownTargets({ infra, keys, url: finalUrl }) };
      const lm = logos[0];
      if (lm) {
        const strong = lm.kind === 'favicon' || asks.size > 0 || !!pretends;
        const what = lm.kind === 'favicon' ? ['tab icon', 'أيقونة'] : ['logo', 'شعار'];
        S.push(sig('copied_logo', strong ? 0.88 : 0.45,
          `The page wears ${lm.name.en}’s own ${what[0]} (${lm.exact ? 'the identical file' : 'a near-identical copy'}), but it is not on ${lm.domain}.`,
          `الصفحة تستخدم ${what[1]} ${lm.name.ar} الحقيقي (${lm.exact ? 'الملف نفسه' : 'نسخة شبه مطابقة'})، لكنها ليست على ${lm.domain}.`));
      }
      const cs = cloakSignal(cloak);
      // app links that send phones to the app store and computers to the website are not cloaking
      const toStore = cloak?.phone?.finalHost && /(^|\.)(play\.google\.com|apps\.apple\.com)$/.test(cloak.phone.finalHost);
      if (cs && !toStore) { if (!(asks.size || pretends || lm)) cs.w = 0.4; S.push(cs); }
    }

    // impersonation is strong evidence only when the page acts on it (asks for secrets, sends data, wears the
    // brand's own icon, pushes an app). A page that merely names an institution (a personal site called "Adib",
    // a US community bank called "Central Bank") is not a scam by that alone.
    if (pretends && !official) {
      const acts = asks.size > 0 || exfil.length > 0 || codeSinks.length > 0 || !!pushed || !!forensics?.logos?.length || !!facts.forms?.length && /login|sign in|verify|تحقق|دخول/i.test(facts.text);
      S.push(sig('page_impersonation', acts ? 0.92 : 0.35, acts
        ? `The page presents itself as ${pretends.inst.name.en}, but it is hosted on ${fin.hostUnicode || fin.host}, not an official ${pretends.inst.name.en} site (${pretends.inst.domains.join(', ')}).`
        : `The page mentions ${pretends.inst.name.en} but is not an official ${pretends.inst.name.en} site, and it asks for nothing. It may be unrelated, or a trap that is not armed yet.`,
      acts ? `الصفحة تقدّم نفسها على أنها ${pretends.inst.name.ar} لكنها مستضافة على ${fin.hostUnicode || fin.host}، وليست موقعاً رسمياً (${pretends.inst.domains.join('، ')}).`
        : `الصفحة تذكر ${pretends.inst.name.ar} لكنها ليست موقعاً رسمياً ولا تطلب شيئاً. قد لا تكون ذات صلة، أو فخاً لم يُفعّل بعد.`));
    }

    // optional AI vision check (monotonic: can only add a signal)
    let aiNote = null;
    if (ai && screenshot && !official) {
      try {
        aiNote = await ai.inspectScreenshot({ screenshot, finalHost: fin.host, title: facts.title, asks: [...asks] });
        if (aiNote?.impersonates && aiNote.risk > 0.5) {
          const b = findInstitutions(matchForm(aiNote.impersonates), aiNote.impersonates).find(c => !c.inst.generic);
          if (!b || !b.inst.domains.includes(finalReg)) {
            S.push(sig('ai_visual', Math.min(0.85, aiNote.risk), `AI vision: the page looks like ${aiNote.impersonates}${aiNote.purpose ? ` (${aiNote.purpose})` : ''} but is not on its official website.`,
              `رؤية الذكاء الاصطناعي: الصفحة تشبه ${aiNote.impersonates} لكنها ليست على الموقع الرسمي.`));
          }
        }
      } catch (e) { aiNote = { error: String(e.message || e) }; }
    }

    const intent = official ? null : pageIntent({ asks, apk: apk?.ok ? apk : null, downloads: pushed ? [pushed] : [], tricks, exfil, codeSinks });
    const risk = 1 - S.reduce((p, s) => p * (1 - s.w), 1);
    // "armed": the page DOES something harmful (asks for secrets, sends data, wears the brand's icon, cloaks,
    // pushes an app …), as opposed to a name that only imitates a brand. Investigators triage on this.
    const BEHAVIOR = /^(asks_secrets|exfil_|copied_logo|cloaking|apk_|download_attempt|clipboard_command|fake_virus_alert|remote_access|wallet_drain|known_malware|urlhaus|ai_visual)/; // a contact form posting elsewhere alone is not proof (small sites use form services)
    const proof = official ? [] : S.filter(s => BEHAVIOR.test(s.id) || (s.id === 'page_impersonation' && s.w >= 0.9)).map(s => s.id);
    // the X-ray SAW the page: when it does nothing harmful, the name alone can make it "suspicious", not "dangerous"
    const shownRisk = !official && !proof.length ? Math.min(risk, 0.84) : risk;
    const verdict = official && !downloads.length ? 'official' : !proof.length && risk >= 0.85 ? 'suspicious' : risk >= 0.85 ? 'dangerous' : risk >= 0.55 ? 'suspicious' : risk >= 0.25 ? 'caution' : 'no_signals';
    const result = {
      ok: true, input: u.href, finalUrl, finalHost: fin.hostUnicode || fin.host, official: official ? { id: official.id, name: official.name } : null,
      browserStatus, redirectObservation, chain, title: facts.title, screenshot, verdict, risk: +shownRisk.toFixed(3), signals: S.sort((a, b) => b.w - a.w), armed: proof.length > 0, proof,
      intent,
      trap: { ...trapInfo, caught: exfil.map(({ kind, host, en, ar, bot, method }) => ({ kind, host, en, ar, bot, method })), blockedPosts: trap.otherPosts },
      codeSinks,
      apk: apk ? { ...apk, permissions: apk.permissions?.slice(0, 40) } : null,
      intel: { urlhaus, bazaar },
      tricks: { ...tricks, events: events.slice(0, 20).map(e => e.t) },
      facts: { asks: [...asks], downloads, dialogs: dialogs.length, popups: popups.length, requests: requests.length, sockets: sockets.length,
        thirdPartyHosts: [...new Set(requests.map(r => r.host))].filter(h => h !== pageHost).length, blocked: [...new Set(blocked)],
        domainAgeDays: age, tls, navError: navError && !/Download is starting/i.test(navError) ? navError : null },
      ai: aiNote,
      forensics,
      sandbox: { browser: browserInfo, downloads: 'blocked (file inspected, never run)', permissions: 'denied', serviceWorkers: 'blocked', websockets: 'mocked',
        privateNetwork: 'blocked', canary: trapInfo.ran ? 'fake values only, every send blocked' : 'not needed', storage: 'discarded after scan', viewport: 'Android phone' },
      ms: Date.now() - t0
    };
    cache.set(u.href, { t: Date.now(), result });
    return result;
  } catch (e) {
    return { ok: false, input: u.href, error: 'chamber', message: 'The X-ray chamber could not open this link: ' + String(e.message || e).split('\n')[0], ms: Date.now() - t0 };
  } finally {
    if (context) await context.close().catch(() => {});
    release();
  }
}
