// The Veto takedown pack: everything a police analyst, a registrar or a hosting company needs to act on a scam
// site, on one printable page, plus a STIX 2.1 bundle for CERT / MISP tooling. Built from the case file only
// (server/cases.js): the site, never the person who reported it. Nothing is sent anywhere: the pack holds
// ready-to-send texts that a human reviews and sends.

import crypto from 'node:crypto';
import fs from 'node:fs';
import { makeZip } from './zip.js';
import { INSTITUTIONS } from '../data/institutions.js';

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const ASK = { card: 'card numbers', cvv: 'card security codes (CVV)', expiry: 'card expiry dates', otp: 'one-time codes', password: 'passwords', pin: 'ATM PINs',
  eid: 'Emirates ID numbers', iban: 'IBANs', seed: 'crypto wallet recovery phrases' };

function brandOf(rec) {
  const id = rec.imitates?.id;
  const inst = id ? INSTITUTIONS.find(i => i.id === id) : null;
  return inst ? { name: inst.name.en, domains: inst.domains.join(', ') } : { name: rec.imitates?.name?.en || 'a UAE institution', domains: '' };
}

/** Plain-text reports a human can paste into an abuse form or e-mail. */
export function reportTexts(rec) {
  const b = brandOf(rec);
  const asks = rec.asks?.length ? rec.asks.map(a => ASK[a] || a).join(', ') : 'personal and payment details';
  const exfil = rec.exfil?.length ? rec.exfil.map(e => `${e.kind.replace(/_/g, ' ')}${e.host ? ' (' + e.host + ')' : ''}${e.bot ? ', bot ' + e.bot : ''}`).join('; ') : 'not observed';
  const server = rec.infra?.ip ? `${rec.infra.ip}${rec.infra.asName ? ` (${rec.infra.asName}${rec.infra.asn ? ', AS' + rec.infra.asn : ''}${rec.infra.country ? ', ' + rec.infra.country : ''})` : ''}` : 'unknown';
  const evidence = [
    `URL: ${rec.finalUrl}`,
    rec.chain?.length > 1 ? `Redirect chain: ${rec.chain.join(' -> ')}` : null,
    `First seen by Veto: ${rec.firstSeen} (UTC)`,
    `What the page asks for: ${asks}`,
    `Where it sends what is typed: ${exfil}`,
    `Server: ${server}`,
    rec.infra?.created ? `Domain registered: ${rec.infra.created.slice(0, 10)}` : null,
    rec.tls?.issuer ? `TLS certificate issuer: ${rec.tls.issuer}` : null
  ].filter(Boolean).map(x => '- ' + x).join('\n');
  const domain = rec.registrable || rec.finalHost;
  const head = `The site ${domain} impersonates ${b.name}${b.domains ? ` (official: ${b.domains})` : ''} to steal ${asks} from people in the United Arab Emirates.`;
  const method = 'Evidence was collected automatically in an isolated browser (Veto X-ray). Only fake values were typed into the page; its attempts to send them were blocked.';
  return {
    registrar: `Subject: Phishing domain impersonating ${b.name}: ${domain}\n\nHello abuse team${rec.infra?.registrar ? ' of ' + rec.infra.registrar : ''},\n\n${head}\n\n${evidence}\n\n${method}\n\nPlease suspend the domain under your abuse policy (ICANN Registrar Accreditation Agreement, section 3.18). Thank you.`,
    host: `Subject: Phishing content on your network: ${rec.finalUrl}\n\nHello abuse team${rec.infra?.asName ? ' of ' + rec.infra.asName : ''},\n\n${head}\n\n${evidence}\n\n${method}\n\nPlease take the content offline. Thank you.`,
    telegram: rec.exfil?.some(e => /telegram/.test(e.kind)) || rec.keys?.telegram_bot?.length
      ? `Subject: Bot receiving stolen bank data (${(rec.keys?.telegram_bot || []).map(x => 'bot id ' + x).join(', ') || 'see evidence'})\n\nThe phishing page ${rec.finalUrl} sends what victims type (${asks}) to a Telegram bot. ${method}\n\n${evidence}\n\nPlease ban the bot and its owner account.` : null
  };
}

const row = (k, v) => v ? `<tr><th>${esc(k)}</th><td>${v}</td></tr>` : '';
const code = v => `<code>${esc(v)}</code>`;

const REVIEW_TEXT = { approved: 'Approved for takedown requests', rejected: 'Rejected: no action', needs_info: 'Needs more information' };
export function dossierHtml(rec, { campaign = null, shot = null, review = null } = {}) {
  const signoff = review
    ? `<p class="signoff ${esc(review.decision)}"><b>Officer sign-off: ${esc(REVIEW_TEXT[review.decision] || review.decision)}</b> · ${esc(review.officer)} · ${esc(review.t.slice(0, 16).replace('T', ' '))} UTC${review.note ? ` · “${esc(review.note)}”` : ''}<br><span class="muted">Audit entry ${review.n} · SHA-256 ${esc(review.hash)}</span></p>`
    : '<p class="signoff pending"><b>Officer sign-off: pending.</b> No takedown request may be sent from this pack until an officer has reviewed and approved it.</p>';
  const b = brandOf(rec);
  const t = reportTexts(rec);
  const sigs = (rec.signals || []).map(s => `<li><b>${Math.round(s.w * 100)}%</b> ${esc(s.en)}<div class="ar" dir="rtl" lang="ar">${esc(s.ar)}</div></li>`).join('');
  const keys = Object.entries(rec.keys || {}).map(([k, vs]) => `${esc(k.replace(/_/g, ' '))}: ${vs.map(code).join(' ')}`).join('<br>');
  const targets = (rec.takedown || []).map(x => `<li><b>${esc(x.name)}</b>${x.email ? ` · ${code(x.email)}` : ''}${x.url ? ` · <a href="${esc(x.url)}" rel="noopener noreferrer">${esc(x.url.length > 70 ? x.url.slice(0, 70) + '…' : x.url)}</a>` : ''} <span class="muted">${esc(x.why)}</span></li>`).join('');
  const camp = campaign ? `<section><h2>Linked sites: campaign ${esc(campaign.id)} (${campaign.size} sites, ${esc(campaign.confidence)} confidence)</h2>
    <p class="muted">Sites are linked only by things criminals reuse. Each link says why, so it can be checked.</p>
    <table class="list"><tr><th>Site</th><th>Verdict</th><th>Imitates</th><th>First seen</th></tr>${campaign.members.map(m => `<tr><td>${code(m.host)}</td><td>${esc(m.verdict)}</td><td>${esc(m.imitates?.name?.en || '')}</td><td>${esc((m.firstSeen || '').slice(0, 10))}</td></tr>`).join('')}</table>
    <ul>${[...new Map(campaign.links.map(l => [l.why + '|' + l.value, l])).values()].slice(0, 12).map(l => `<li>${esc(l.en)}: ${code(l.value)} (${esc(l.confidence)} confidence)</li>`).join('')}</ul></section>` : '';
  const textBox = (title, txt) => txt ? `<h3>${esc(title)}</h3><textarea readonly rows="12">${esc(txt)}</textarea>` : '';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Veto takedown pack · ${esc(rec.registrable || rec.finalHost)}</title>
<style>
.signoff{border-radius:10px;padding:10px 12px;margin:10px 0;font-size:13.5px;border:1px solid #fedf89;background:#fffaeb;color:#7a2e0e}.signoff.approved{border-color:#abefc6;background:#ecfdf3;color:#05603a}.signoff.rejected{border-color:#d0d5dd;background:#f2f4f7;color:#344054}.signoff .muted{font-size:11.5px;word-break:break-all}
:root{--ink:#0d1b2e;--muted:#4a5a72;--line:#d3ddeb;--bad:#a3201a;--bad-bg:#fef3f2;--blue:#1849a9}
body{font:14px/1.5 "Segoe UI",system-ui,sans-serif;color:var(--ink);background:#f3f6fb;margin:0;padding:24px}
main{max-width:920px;margin:0 auto;background:#fff;border:1px solid var(--line);border-radius:18px;padding:28px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:26px 0 8px;border-bottom:1px solid var(--line);padding-bottom:6px}h3{font-size:14px;margin:16px 0 6px}
.muted{color:var(--muted)}.verdict{display:inline-block;padding:3px 10px;border-radius:999px;background:var(--bad);color:#fff;font-weight:600}
.grid{display:grid;grid-template-columns:1fr 280px;gap:22px}@media(max-width:760px){.grid{grid-template-columns:1fr}}
img.shot{width:100%;border:1px solid var(--line);border-radius:14px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;vertical-align:top;padding:6px 8px;border-bottom:1px solid var(--line)}th{width:190px;color:var(--muted);font-weight:600}
table.list th{width:auto}code{font:12.5px Consolas,monospace;background:#f3f6fb;border:1px solid var(--line);border-radius:5px;padding:0 4px;overflow-wrap:anywhere}
ul{padding-left:20px}li{margin:4px 0}.ar{color:var(--muted);font-size:13px}
textarea{width:100%;font:12.5px Consolas,monospace;border:1px solid var(--line);border-radius:10px;padding:10px;background:#fbfcfe;color:var(--ink)}
.note{background:var(--bad-bg);border:1px solid #fecdca;border-radius:12px;padding:10px 14px;color:#7a1d14}
@media print{body{background:#fff;padding:0}main{border:0}textarea{border:1px solid #999}}
</style></head><body><main>
<p class="muted">Veto.ai takedown pack · case ${esc(rec.id)} · generated ${esc(new Date().toISOString().slice(0, 16).replace('T', ' '))} UTC</p>
<h1>${esc(rec.registrable || rec.finalHost)} <span class="verdict">${esc(rec.verdict)} · ${Math.round((rec.risk || 0) * 100)}%</span></h1>
${signoff}
<p>Impersonates <b>${esc(b.name)}</b>${b.domains ? ` (official: ${esc(b.domains)})` : ''}. ${rec.intent ? esc(rec.intent.en) : ''}</p>
<div class="grid"><div>
<h2>Evidence</h2><table>
${row('Final URL', code(rec.finalUrl))}
${row('Link as received', rec.input !== rec.finalUrl ? code(rec.input) : '')}
${row('Redirect chain', rec.chain?.length > 1 ? rec.chain.map(code).join(' → ') : '')}
${row('Page title', esc(rec.title))}
${row('Asks for', esc((rec.asks || []).map(a => ASK[a] || a).join(', ')))}
${row('Sends data to', (rec.exfil || []).map(e => `${esc(e.kind.replace(/_/g, ' '))} ${e.host ? code(e.host) : ''}${e.bot ? ' ' + code(e.bot) : ''}`).join('<br>'))}
${row('App it pushes', rec.apk ? `${esc(rec.apk.label || '')} ${code(rec.apk.package || '')} SHA-256 ${code(rec.apk.sha256)}${rec.apk.trojan ? ' <b>banking-trojan profile</b>' : ''}` : '')}
${row('Copied brand pictures', (rec.logos || []).map(l => `${esc(l.name?.en)} ${esc(l.kind)} (${l.exact ? 'identical file' : 'near-identical'})`).join('<br>'))}
${row('Cloaking', rec.cloaking?.verdict === 'cloaked' ? rec.cloaking.who.map(w => `${esc(w.who)}: ${esc(w.how)}${w.to ? ' → ' + code(w.to) : ''}${w.status ? ' HTTP ' + esc(w.status) : ''}`).join('<br>') : esc(rec.cloaking?.verdict || ''))}
${row('Registrar', rec.infra?.registrar ? `${esc(rec.infra.registrar)}${rec.infra.abuseEmail ? ' · abuse ' + code(rec.infra.abuseEmail) : ''}` : '')}
${row('Registered', esc(rec.infra?.created?.slice(0, 10) || (rec.domainAgeDays != null ? rec.domainAgeDays + ' days ago' : '')))}
${row('Domain status', esc((rec.infra?.status || []).join(', ')))}
${row('Name servers', (rec.infra?.nameservers || []).map(code).join(' '))}
${row('Server', rec.infra?.ip ? `${code(rec.infra.ip)} ${esc(rec.infra.asName || '')}${rec.infra.asn ? ' AS' + esc(rec.infra.asn) : ''} ${esc(rec.infra.country || '')}${rec.infra.hostAbuse ? ' · abuse ' + code(rec.infra.hostAbuse) : ''}` : '')}
${row('TLS', rec.tls ? `${esc(rec.tls.protocol || '')} · ${esc(rec.tls.issuer || '')}` : '')}
${row('Kit fingerprint', rec.kit?.simhash ? `SimHash ${code(rec.kit.simhash)} · exact ${code(rec.kit.exact)} · ${esc(rec.kit.tokens)} elements` : '')}
${row('Favicon hash (Shodan)', rec.favicon ? code('http.favicon.hash:' + rec.favicon.shodan) : '')}
${row('Campaign keys', keys)}
</table></div>
<div>${shot ? `<img class="shot" alt="X-ray picture of the page" src="${shot}">` : '<p class="muted">No picture stored.</p>'}</div></div>
<h2>Why Veto flagged it</h2><ul>${sigs}</ul>
${camp}
<h2>Where takedown requests go</h2><ul>${targets}</ul>
<h2>Ready-to-send reports</h2>
<p class="note">Review before sending. Veto never sends these itself.</p>
${textBox('To the registrar', t.registrar)}${textBox('To the hosting network', t.host)}${textBox('To Telegram (abuse@telegram.org)', t.telegram)}
<h2>Method</h2><p class="muted">Collected by the Veto X-ray chamber: a throw-away browser posing as an Android phone (downloads refused and inspected, permissions denied, private network blocked). Only fake values were typed; every send was blocked. Copied pictures are matched against fingerprints of the institutions' own icons; cloaking is tested by fetching the page as a phone, a computer and a search crawler. Treat findings as strong indicators to verify, not as a court finding.</p>
<p class="muted">Downloads: <a href="/api/case/${esc(rec.id)}/evidence.zip">evidence bundle (ZIP: PDF, picture, STIX, case data, SHA-256 manifest)</a> · <a href="/api/case/${esc(rec.id)}/evidence.pdf">PDF</a> · <a href="/api/case/${esc(rec.id)}/stix">STIX 2.1</a> (for aeCERT / MISP / OpenCTI).</p>
</main></body></html>`;
}

/** STIX 2.1 bundle: indicators for the URL, domain and IP, an observed-data record, and the campaign. */
export function stixBundle(rec, { campaign = null } = {}) {
  const ts = new Date().toISOString();
  const uid = (type, seed) => `${type}--${uuidFrom(seed)}`;
  const identity = { type: 'identity', spec_version: '2.1', id: uid('identity', 'veto.ai'), created: '2026-11-01T00:00:00.000Z', modified: '2026-11-01T00:00:00.000Z', name: 'Veto.ai', identity_class: 'system' };
  const q = s => String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  const ind = (pattern, name, seed) => ({ type: 'indicator', spec_version: '2.1', id: uid('indicator', seed), created: ts, modified: ts, created_by_ref: identity.id,
    name, pattern, pattern_type: 'stix', valid_from: rec.firstSeen, indicator_types: ['malicious-activity'], labels: ['phishing'],
    description: `Phishing impersonating ${brandOf(rec).name}. Verdict ${rec.verdict} (${Math.round((rec.risk || 0) * 100)}%).` });
  const objects = [identity,
    ind(`[url:value = '${q(rec.finalUrl)}']`, `Phishing URL ${rec.finalHost}`, 'url:' + rec.finalUrl),
    ind(`[domain-name:value = '${q(rec.registrable)}']`, `Phishing domain ${rec.registrable}`, 'domain:' + rec.registrable)];
  if (rec.infra?.ip) objects.push(ind(`[ipv4-addr:value = '${q(rec.infra.ip)}']`, `Server of ${rec.registrable}`, 'ip:' + rec.infra.ip));
  if (rec.apk?.sha256) objects.push(ind(`[file:hashes.'SHA-256' = '${q(rec.apk.sha256)}']`, `App pushed by ${rec.registrable}`, 'apk:' + rec.apk.sha256));
  if (campaign) {
    const c = { type: 'campaign', spec_version: '2.1', id: uid('campaign', campaign.id), created: ts, modified: ts, created_by_ref: identity.id, name: `Veto ${campaign.id}`,
      description: `${campaign.size} linked phishing sites (${campaign.confidence} confidence). Links: ${[...new Set(campaign.links.map(l => l.en))].join('; ')}.`, first_seen: campaign.firstSeen };
    objects.push(c);
    for (const o of objects.filter(o => o.type === 'indicator')) objects.push({ type: 'relationship', spec_version: '2.1', id: uid('relationship', o.id + c.id), created: ts, modified: ts, relationship_type: 'indicates', source_ref: o.id, target_ref: c.id });
  }
  return { type: 'bundle', id: `bundle--${crypto.randomUUID()}`, objects };
}
// deterministic UUID-v4-shaped ids, so re-exports of the same case keep the same object ids
function uuidFrom(seed) {
  const h = crypto.createHash('sha256').update(String(seed)).digest('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${((parseInt(h[16], 16) & 3) | 8).toString(16)}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

export function shotDataUrl(file) {
  try { return file ? 'data:image/jpeg;base64,' + fs.readFileSync(file).toString('base64') : null; } catch { return null; }
}

/** Evidence bundle for police and takedown: the pack as PDF (rendered by the X-ray's own browser) and HTML, the page
 *  picture, the STIX 2.1 file, the case record, and a manifest with the SHA-256 of every file and the UTC time, so
 *  anyone can check later that nothing was changed. */
export async function evidenceBundle(rec, { campaign = null, shotFile = null, review = null } = {}) {
  const shot = shotFile && fs.existsSync(shotFile) ? fs.readFileSync(shotFile) : null;
  const html = dossierHtml(rec, { campaign, review, shot: shot ? 'data:image/jpeg;base64,' + shot.toString('base64') : null });
  let pdf = null;
  try {
    const { getBrowser } = await import('./xray.js');
    const ctx = await (await getBrowser()).newContext({ javaScriptEnabled: false });
    try {
      await ctx.route('**/*', r => r.abort());
      const page = await ctx.newPage();
      await page.setContent(html, { waitUntil: 'load' });
      pdf = await page.pdf({ format: 'A4', printBackground: true, margin: { top: '12mm', bottom: '12mm', left: '10mm', right: '10mm' } });
    } finally { await ctx.close().catch(() => {}); }
  } catch { /* no browser: the bundle still has the HTML */ }
  const files = [
    { name: 'takedown-pack.html', data: html },
    ...(pdf ? [{ name: 'takedown-pack.pdf', data: pdf }] : []),
    ...(shot ? [{ name: 'page-screenshot.jpg', data: shot }] : []),
    { name: 'case.json', data: JSON.stringify(rec, null, 1) },
    { name: 'stix-2.1.json', data: JSON.stringify(stixBundle(rec, { campaign }), null, 1) },
    ...(campaign ? [{ name: 'campaign.json', data: JSON.stringify(campaign, null, 1) }] : []),
    { name: 'officer-signoff.json', data: JSON.stringify(review || { decision: 'pending', note: 'No officer has reviewed this case yet.' }, null, 1) }
  ];
  const now = new Date();
  const crypto = await import('node:crypto');
  const manifest = [`Veto.ai evidence bundle · case ${rec.id} · ${rec.finalUrl}`, `created ${now.toISOString()} (UTC) · first seen ${rec.firstSeen} · last seen ${rec.lastSeen}`, '',
    ...files.map(f => `${crypto.createHash('sha256').update(Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data)).digest('hex')}  ${f.name}`), '',
    'Collected automatically by the Veto X-ray chamber (only fake values were typed; every send was blocked). Verify before acting.'].join('\n');
  return { zip: makeZip([...files, { name: 'MANIFEST-SHA256.txt', data: manifest }], now), pdf };
}
