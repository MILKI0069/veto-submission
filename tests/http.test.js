// The HTTP layer. The real server is started as a child process on a free port, with the demo pages off, and each
// endpoint is checked for status, shape and behaviour on bad input. The judge is used offline only: no network.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
let child = null;
let base = '';

const freePort = () => new Promise((resolve, reject) => {
  const s = net.createServer();
  s.on('error', reject);
  s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
});

before(async () => {
  const port = await freePort();
  base = `http://127.0.0.1:${port}`;
  child = spawn(process.execPath, ['server/server.js'], {
    cwd: ROOT, env: { ...process.env, PORT: String(port), VETO_DEMO: '0' }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('the server did not start within 20 s')), 20000);
    child.stdout.on('data', d => { if (String(d).includes('running on')) { clearTimeout(timer); resolve(); } });
    child.on('exit', code => { clearTimeout(timer); reject(new Error(`the server exited early with code ${code}`)); });
  });
});

after(() => { if (child) child.kill('SIGKILL'); });

const get = p => fetch(base + p);
const post = (p, body, raw) => fetch(base + p, {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: raw ?? JSON.stringify(body),
});

test('health reports the server and its optional layers', async () => {
  const r = await get('/api/health');
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.equal(j.ok, true);
  assert.equal(typeof j.ai, 'boolean');
  assert.equal(typeof j.xray, 'boolean');
});

test('judge GET: one allowlisted institution is not called phishing, and the answer has the full shape', async () => {
  const r = await get('/api/v1/judge?url=' + encodeURIComponent('https://www.emiratesnbd.com/'));
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.ok(['phishing', 'suspicious', 'legitimate', 'invalid'].includes(j.verdict), `unexpected verdict ${j.verdict}`);
  assert.equal(typeof j.score, 'number');
  assert.ok(j.score >= 0 && j.score <= 1);
  assert.ok(Array.isArray(j.reasons));
  assert.notEqual(j.verdict, 'phishing');
});

test('judge GET: text that is not a web address is reported as invalid, not as a crash', async () => {
  const r = await get('/api/v1/judge?url=' + encodeURIComponent('not a url at all'));
  assert.equal(r.status, 200);
  assert.equal((await r.json()).verdict, 'invalid');
});

test('judge POST: a list gives one result per URL, in order, and no metrics without labels', async () => {
  const r = await post('/api/v1/judge', { urls: ['https://www.emiratesnbd.com/', 'not a url', 'https://example.org/'] });
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.equal(j.results.length, 3);
  assert.equal(j.results[1].verdict, 'invalid');
  assert.equal(j.metrics, null);
});

test('judge POST: labelled rows give metrics, and an invalid labelled row is counted', async () => {
  const r = await post('/api/v1/judge', { urls: [{ url: 'https://www.emiratesnbd.com/', label: 0 }, { url: 'not a url', label: 1 }] });
  const j = await r.json();
  assert.equal(j.metrics.strict.n, 2);
  assert.equal(j.metrics.invalid, 1);
});

test('judge POST: more than the offline cap (20,000 URLs) is refused with 413', async () => {
  const urls = Array.from({ length: 20001 }, (_, i) => `https://site${i}.example.org/`);
  const r = await post('/api/v1/judge', { urls });
  assert.equal(r.status, 413);
});

test('judge POST: broken JSON is refused, and the server keeps answering afterwards', async () => {
  const r = await post('/api/v1/judge', null, '{not json');
  assert.ok(r.status >= 400, `expected an error status, got ${r.status}`);
  const h = await get('/api/health');
  assert.equal(h.status, 200);
});

test('an unknown API path returns a JSON 404, never the app shell', async () => {
  const r = await get('/api/no-such-endpoint-' + Date.now());
  assert.equal(r.status, 404);
  assert.match(r.headers.get('content-type') || '', /application\/json/);
  const text = await r.text();
  assert.ok(!/<html/i.test(text), 'an API 404 must not return HTML');
  assert.ok(!/at .*\.js:\d+/.test(text), 'the 404 body must not contain a stack trace');
});

test('an unknown dashboard route returns 404', async () => {
  const r = await get('/share-' + Date.now());
  assert.equal(r.status, 404);
});

test('a missing file with an extension returns 404', async () => {
  const r = await get('/no-such-file-' + Date.now() + '.js');
  assert.equal(r.status, 404);
});

test('stored case files and exports require officer access before lookup', async () => {
  const id = '000000000000';
  const routes = ['/api/dossier/' + id, ...['', '/shot.jpg', '/stix', '/evidence.pdf', '/evidence.zip', '/review'].map(suffix => '/api/case/' + id + suffix)];
  for (const route of routes) {
    const response = await fetch(base + route, { headers: { 'x-forwarded-for': '192.0.2.1' } });
    assert.equal(response.status, 403, route);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal((await response.json()).error, 'console');
    assert.equal((await get(route)).status, 404, route);
  }
});
