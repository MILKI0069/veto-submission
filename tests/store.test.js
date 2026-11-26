// The durable copy of var/: writes are mirrored to the database and var/ is rebuilt from it at start-up.
// The database is faked here (global fetch), so the test needs no network.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'veto-store-'));
process.env.VETO_VAR = dir;
const KEYS = ['VETO_STORE_URL', 'VETO_STORE_KEY', 'VETO_STORE_SECRET'];
const on = () => { process.env.VETO_STORE_URL = 'https://db.example/'; process.env.VETO_STORE_KEY = 'pub'; process.env.VETO_STORE_SECRET = 's3cret-value'; };
const off = () => { for (const k of KEYS) delete process.env[k]; };
const realFetch = globalThis.fetch;
const { storeConfigured, storeStatus, storeCase, storeAudit, storeFlush, storeRestore } = await import('../server/store.js');

test.afterEach(() => { globalThis.fetch = realFetch; off(); });

test('without settings the store is off and sends nothing', async () => {
  off();
  let calls = 0; globalThis.fetch = async () => { calls++; return new Response('null'); };
  assert.equal(storeConfigured(), false);
  storeCase({ id: 'abc' }); storeAudit({ n: 1 });
  await storeFlush();
  assert.equal(calls, 0);
  assert.equal((await storeRestore()).mode, 'files');
});

test('writes are sent in order with the secret, and a failed call is retried', async () => {
  on();
  const seen = []; let failOnce = true;
  globalThis.fetch = async (url, opt) => {
    if (failOnce) { failOnce = false; return new Response('busy', { status: 503 }); }
    seen.push({ url: String(url), body: JSON.parse(opt.body), key: opt.headers.apikey });
    return new Response(null, { status: 204 });
  };
  storeCase({ id: 'aaa111', verdict: 'dangerous' }, 'QUJD');
  storeAudit({ n: 1, decision: 'approved' });
  await storeFlush();
  assert.deepEqual(seen.map(s => s.url), ['https://db.example/rest/v1/rpc/veto_put_case', 'https://db.example/rest/v1/rpc/veto_append_audit']);
  assert.equal(seen[0].body.p_secret, 's3cret-value');
  assert.equal(seen[0].body.p_shot, 'QUJD');
  assert.equal(seen[0].key, 'pub');
  assert.equal(seen[1].body.p_entry.n, 1);
  assert.equal(storeStatus().pending, 0);
});

test('start-up rebuilds the case file, the sign-off log, the hunt state and the pictures', async () => {
  on();
  globalThis.fetch = async (url, opt) => {
    const b = JSON.parse(opt.body);
    if (String(url).endsWith('/veto_load')) return Response.json({ cases: [{ id: 'aaa111', lastSeen: '2026-01-01' }, { id: 'bbb222', lastSeen: '2026-01-02' }], audit: [{ n: 1, decision: 'approved' }], state: { sentinel: { suspects: { 'x.test': {} }, sweeps: [] } }, shots: ['aaa111', '../evil'] });
    if (String(url).endsWith('/veto_shot')) return Response.json(b.p_id === 'aaa111' ? 'QUJD' : null);
    return new Response('nope', { status: 404 });
  };
  const s = await storeRestore();
  assert.deepEqual({ ...s.restored, at: 0 }, { cases: 2, signoffs: 1, pictures: 1, at: 0 });
  assert.equal(fs.readFileSync(path.join(dir, 'cases.jsonl'), 'utf8').trim().split('\n').length, 2);
  assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'audit.jsonl'), 'utf8')).n, 1);
  assert.ok(JSON.parse(fs.readFileSync(path.join(dir, 'sentinel.json'), 'utf8')).suspects['x.test']);
  assert.equal(fs.readFileSync(path.join(dir, 'shots', 'aaa111.jpg'), 'utf8'), 'ABC');
  assert.deepEqual(fs.readdirSync(path.join(dir, 'shots')), ['aaa111.jpg']);
});

test('an unreachable database never stops the server: it falls back to local files', async () => {
  on();
  globalThis.fetch = async () => { throw new Error('network down'); };
  const s = await storeRestore();
  assert.equal(s.mode, 'database');
  assert.match(s.lastError, /network down/);
});
