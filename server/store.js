// Durable copy of the private var/ folder, for hosts whose disk is wiped on every restart.
//
// The case file, the X-ray pictures, the officer sign-off log and the hunt state are written to var/ as before.
// When a database is configured, every write is also sent to it, and at start-up var/ is rebuilt from it, so a
// restart loses nothing. Without the three settings below this module does nothing and Veto runs on files only.
//
//   VETO_STORE_URL     the project address, e.g. https://abcd.supabase.co
//   VETO_STORE_KEY     the project's publishable key
//   VETO_STORE_SECRET  the store secret; the database keeps only its SHA-256 and refuses every call without it
//
// The tables sit in a schema the public API does not expose. The only way in is five functions (db/store.sql),
// each of which checks the secret first. Sign-off entries can be inserted once and never changed.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIR = process.env.VETO_VAR || path.join(ROOT, 'var');
const cfg = () => ({ url: (process.env.VETO_STORE_URL || '').replace(/\/+$/, ''), key: process.env.VETO_STORE_KEY || '', secret: process.env.VETO_STORE_SECRET || '' });

export const storeConfigured = () => { const c = cfg(); return !!(c.url && c.key && c.secret); };
const status = { mode: 'files', restored: null, lastError: null, pending: 0 };
export const storeStatus = () => ({ ...status, mode: storeConfigured() ? 'database' : 'files' });

async function rpc(fn, args = {}) {
  const c = cfg();
  const r = await fetch(`${c.url}/rest/v1/rpc/${fn}`, {
    method: 'POST',
    headers: { apikey: c.key, Authorization: 'Bearer ' + c.key, 'Content-Type': 'application/json' },
    body: JSON.stringify({ p_secret: c.secret, ...args }),
    signal: AbortSignal.timeout(20000)
  });
  if (!r.ok) throw new Error(`${fn}: HTTP ${r.status} ${(await r.text()).slice(0, 160)}`);
  const t = await r.text();
  return t ? JSON.parse(t) : null;
}

// writes go out one at a time, in order, each tried up to three times
let chain = Promise.resolve();
function push(fn, args) {
  if (!storeConfigured()) return;
  status.pending++;
  chain = chain.then(async () => {
    for (let i = 0; i < 3; i++) {
      try { await rpc(fn, args); status.lastError = null; break; } catch (e) {
        status.lastError = e.message;
        if (i === 2 || /HTTP 4\d\d/.test(e.message)) { console.error('[veto] store:', e.message); break; }
        await new Promise(res => setTimeout(res, 800 * (i + 1)));
      }
    }
    status.pending--;
  });
}
/** Wait until every queued write has gone out (tests, shutdown). */
export const storeFlush = () => chain;

export const storeCase = (rec, shotB64 = null) => push('veto_put_case', { p_rec: rec, p_shot: shotB64 });
export const storeAudit = entry => push('veto_append_audit', { p_entry: entry });

// the hunt state changes many times during a sweep: send the latest version at most every few seconds
let stateTimer = null, latestState = null;
export function storeState(key, value) {
  if (!storeConfigured()) return;
  latestState = { key, value: JSON.parse(JSON.stringify(value)) };
  if (stateTimer) return;
  stateTimer = setTimeout(() => { stateTimer = null; push('veto_put_state', { p_key: latestState.key, p_value: latestState.value }); }, 4000);
  stateTimer.unref?.();
}

/** Rebuild var/ from the database. Call once, before anything reads the files. Never throws. */
export async function storeRestore() {
  if (!storeConfigured()) return storeStatus();
  try {
    const d = await rpc('veto_load');
    fs.mkdirSync(path.join(DIR, 'shots'), { recursive: true });
    if (d.cases.length) fs.writeFileSync(path.join(DIR, 'cases.jsonl'), d.cases.map(r => JSON.stringify(r)).join('\n') + '\n');
    if (d.audit.length) fs.writeFileSync(path.join(DIR, 'audit.jsonl'), d.audit.map(e => JSON.stringify(e)).join('\n') + '\n');
    if (d.state.sentinel) fs.writeFileSync(path.join(DIR, 'sentinel.json'), JSON.stringify(d.state.sentinel));
    let shots = 0;
    for (const id of d.shots) {
      if (!/^[a-f0-9]{6,64}$/.test(id)) continue;
      try { const b64 = await rpc('veto_shot', { p_id: id }); if (b64) { fs.writeFileSync(path.join(DIR, 'shots', id + '.jpg'), Buffer.from(b64, 'base64')); shots++; } } catch (e) { status.lastError = e.message; }
    }
    status.restored = { cases: d.cases.length, signoffs: d.audit.length, pictures: shots, at: new Date().toISOString() };
  } catch (e) {
    status.lastError = e.message;
    console.error('[veto] store restore failed, continuing on local files:', e.message);
  }
  return storeStatus();
}
