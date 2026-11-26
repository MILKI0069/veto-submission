// The web app: the front door, the resident app and the police dashboard, served as a HOSTED site would be
// (every request carries x-forwarded-for, so nothing is treated as local). Also the regressions the audit asked for.
// No outside network: the demo pages are off and the connector calls are faked.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyze } from '../engine/index.js';
import { judgeOffline } from '../server/judge.js';
import { EXAMPLES } from '../web/examples.js';
import { huntPlan, serperSearch, serperPlaces, connectorsConfigured } from '../server/connectors.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CODE = 'pilot-access-code';
const FWD = { 'x-forwarded-for': '203.0.113.9', 'x-forwarded-proto': 'https' };
let child = null, base = '';

const freePort = () => new Promise((resolve, reject) => {
  const s = net.createServer();
  s.on('error', reject);
  s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
});

before(async () => {
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ['server/server.js'], {
    cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, PORT: String(port), VETO_DEMO: '0', VETO_CONSOLE_TOKEN: CODE, VETO_VAR: fs.mkdtempSync(path.join(os.tmpdir(), 'veto-webapp-')) },
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('the server did not start within 20 s')), 20000);
    child.stdout.on('data', d => { if (String(d).includes('running on')) { clearTimeout(timer); resolve(); } });
    child.on('exit', code => { clearTimeout(timer); reject(new Error(`the server exited early with code ${code}`)); });
  });
});
after(() => { if (child) child.kill('SIGKILL'); });

const get = (p, headers = {}) => fetch(base + p, { headers: { ...FWD, ...headers }, redirect: 'manual' });
const post = (p, body, headers = {}) => fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json', ...FWD, ...headers }, body: JSON.stringify(body) });

test('officers reach one dashboard through current and legacy addresses', async () => {
  for (const [p, mark] of [['/', 'police.js'], ['/police/', 'police.js'], ['/police', 'police.js']]) {
    const r = await get(p);
    assert.equal(r.status, 200, p);
    assert.match(await r.text(), new RegExp(mark.replace('.', '\\.')), p);
  }
  assert.equal((await get('/healthz')).status, 200);
  for (const legacy of ['/resident/', '/sentinel.html', '/home.html', '/index.html', '/share']) {
    const old = await get(legacy);
    assert.equal(old.status, 302);
    assert.equal(old.headers.get('location'), '/police');
  }
  assert.equal((await get('/missing-route')).status, 404);
});

test('a hosted visitor without a session cannot read police data', async () => {
  const s = await (await get('/api/console/session')).json();
  assert.deepEqual({ ok: s.ok, mode: s.mode, codeConfigured: s.codeConfigured }, { ok: false, mode: 'none', codeConfigured: true });
  for (const p of ['/api/sentinel', '/api/audit', '/api/case/0123456789ab', '/api/sentinel/job']) assert.equal((await get(p)).status, 403, p);
  assert.equal((await post('/api/case/0123456789ab/review', { decision: 'approved', officer: 'Lt. Test' })).status, 403);
});

test('the access code opens a session, a wrong code does not, and signing out ends it', async () => {
  assert.equal((await post('/api/console/login', { code: 'wrong-code-000' })).status, 401);
  const ok = await post('/api/console/login', { code: CODE });
  assert.equal(ok.status, 200);
  const set = ok.headers.get('set-cookie');
  assert.match(set, /HttpOnly/);
  assert.match(set, /Secure/);
  const cookie = set.split(';')[0];
  const s = await (await get('/api/console/session', { cookie })).json();
  assert.equal(s.ok, true);
  assert.equal(s.mode, 'code');
  const board = await get('/api/sentinel', { cookie });
  assert.equal(board.status, 200);
  const j = await board.json();
  assert.ok(Array.isArray(j.cases) && Array.isArray(j.campaigns) && j.institutions.length > 10);
  const audit = await (await get('/api/audit', { cookie })).json();
  assert.equal(audit.intact, true);
  assert.equal((await get('/api/case/0123456789ab', { cookie })).status, 404);
  const out = await post('/api/console/logout', {}, { cookie });
  assert.match(out.headers.get('set-cookie'), /Max-Age=0/);
});

test('too many sign-in attempts from one address are slowed down', async () => {
  let limited = false;
  for (let i = 0; i < 12 && !limited; i++) limited = (await post('/api/console/login', { code: 'guess-' + i }, { 'x-forwarded-for': '198.51.100.7' })).status === 429;
  assert.equal(limited, true);
});

test('audit: a fake Dubai Police fine from a UK number with a short link is a scam, in English and in Arabic', () => {
  const en = analyze({ channel: 'sms', sender: '+447911123456', text: 'Dubai Police: You have an unpaid traffic fine of AED 300. Pay within 24 hours to avoid legal action: https://cutt.ly/dxb-fine' });
  const ar = analyze({ channel: 'sms', sender: '+447911123456', text: 'شرطة دبي: لديك مخالفة مرورية غير مدفوعة بقيمة 300 درهم. ادفع خلال 24 ساعة لتجنب الإجراءات القانونية: https://cutt.ly/dxb-fine' });
  assert.equal(en.verdict, 'scam');
  assert.equal(ar.verdict, 'scam');
});

test('audit: the Arabic examples on the front door give the verdict they promise', () => {
  const byId = Object.fromEntries(EXAMPLES.map(e => [e.id, e]));
  for (const id of ['tamm_ar', 'fab_otp_ar', 'police_fine']) {
    const e = byId[id];
    assert.ok(e, id);
    assert.equal(analyze({ channel: e.channel, sender: e.sender, text: e.text, context: e.context }).verdict, 'scam', id);
  }
  const real = analyze({ channel: 'sms', sender: 'EmiratesNBD', text: 'Your Emirates NBD statement is ready. View it in the app or at https://www.emiratesnbd.com' });
  assert.notEqual(real.verdict, 'scam');
});

test('audit: 30 real UAE bank and government sign-in addresses are not flagged', () => {
  const urls = fs.readFileSync(path.join(ROOT, 'tests/uae-logins.txt'), 'utf8').split('\n').map(s => s.trim()).filter(Boolean);
  assert.equal(urls.length, 30);
  for (const u of urls) assert.equal(judgeOffline(u).verdict, 'legitimate', u);
});

test('Serper.dev answers are mapped to results and listings, and count as a search and Maps source', async () => {
  const realFetch = globalThis.fetch;
  process.env.SERPER_API_KEY = 'test-key';
  try {
    const seen = [];
    globalThis.fetch = async (url, opt) => {
      seen.push({ url: String(url), key: opt.headers['x-api-key'], body: JSON.parse(opt.body) });
      return { ok: true, status: 200, json: async () => (String(url).endsWith('/places')
        ? { places: [{ title: 'FAB Customer Care', phoneNumber: '+971 50 000 0000', website: 'https://fab-help.example', address: 'Abu Dhabi', cid: '42' }] }
        : { organic: [{ position: 1, title: 'FAB', link: 'https://www.bankfab.com/', snippet: 'Official' }] }) };
    };
    assert.deepEqual(connectorsConfigured(), { search: true, maps: true, ads: false });
    const plan = huntPlan([{ id: 'fab', name: { en: 'FAB', ar: 'FAB' } }]);
    assert.equal(plan.search, 'Serper');
    assert.equal(plan.maps, 'Serper');
    assert.equal(plan.serpApiSearches, 0);
    const res = await serperSearch('FAB customer care number');
    assert.deepEqual(res[0], { rank: 1, ad: false, title: 'FAB', url: 'https://www.bankfab.com/', description: 'Official' });
    const places = await serperPlaces('FAB customer service');
    assert.equal(places[0].phone, '+971 50 000 0000');
    assert.equal(places[0].website, 'https://fab-help.example');
    assert.equal(seen[0].url, 'https://google.serper.dev/search');
    assert.equal(seen[0].key, 'test-key');
    assert.equal(seen[0].body.gl, 'ae');
  } finally { globalThis.fetch = realFetch; delete process.env.SERPER_API_KEY; }
});
