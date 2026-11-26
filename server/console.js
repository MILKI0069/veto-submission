// Police console access and the officer sign-off log.
//
// Access: on the Veto server itself (localhost) the console is open, as before. When Veto is hosted, an officer
// signs in with the access code (VETO_CONSOLE_TOKEN) and gets a short-lived, signed, HttpOnly session cookie.
// This is a pilot gate, not the final design: a police deployment would sit behind the force's own single sign-on.
//
// Sign-off: Veto never sends a takedown request by itself. An officer records a decision on each case, and every
// decision is appended to var/audit.jsonl as a hash chain: each entry carries the SHA-256 of the entry before it,
// so a changed or removed line breaks the chain and shows.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { storeAudit } from './store.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIR = process.env.VETO_VAR || path.join(ROOT, 'var');
const AUDIT = path.join(DIR, 'audit.jsonl');
const TOKEN = () => process.env.VETO_CONSOLE_TOKEN || '';
const SESSION_HOURS = 12;
const COOKIE = 'veto_console';

const key = () => crypto.createHash('sha256').update('veto-console-session:' + TOKEN()).digest();
const sign = exp => crypto.createHmac('sha256', key()).update(String(exp)).digest('hex');
const safeEqual = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

export const codeConfigured = () => TOKEN().length >= 8;

/** Does the access code match? Constant-time, and never true when no code is set. */
export function checkCode(code) {
  // spaces around the code and letter case are forgiven: codes get pasted from chats and typed on phones
  const norm = v => String(v || '').trim().toLowerCase();
  return codeConfigured() && safeEqual(crypto.createHash('sha256').update(norm(code)).digest('hex'), crypto.createHash('sha256').update(norm(TOKEN())).digest('hex'));
}

export function sessionCookie(req) {
  const exp = Date.now() + SESSION_HOURS * 3600_000;
  const secure = (req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https';
  return `${COOKIE}=${exp}.${sign(exp)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_HOURS * 3600}${secure ? '; Secure' : ''}`;
}
export const clearCookie = () => `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`;

export function hasSession(req) {
  if (!codeConfigured()) return false;
  const m = new RegExp(`(?:^|;\\s*)${COOKIE}=(\\d{10,16})\\.([a-f0-9]{64})`).exec(req.headers.cookie || '');
  return !!m && Number(m[1]) > Date.now() && safeEqual(m[2], sign(m[1]));
}

// ---------------------------------------------------------------------------------------------
// officer sign-off: an append-only, hash-chained log
export const DECISIONS = ['approved', 'rejected', 'needs_info'];
const GENESIS = '0'.repeat(64);
const hashOf = e => crypto.createHash('sha256').update(JSON.stringify([e.n, e.t, e.caseId, e.host, e.decision, e.officer, e.note, e.prev])).digest('hex');

let cache = null;
function load() {
  if (cache) return cache;
  cache = [];
  try {
    for (const line of fs.readFileSync(AUDIT, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try { cache.push(JSON.parse(line)); } catch { cache.push({ torn: true }); }
    }
  } catch { /* no log yet */ }
  return cache;
}

/** Append an officer decision. Returns the new entry. */
export function recordReview({ caseId, host, decision, officer, note }) {
  if (!DECISIONS.includes(decision)) throw Object.assign(new Error('bad decision'), { code: 400 });
  const name = String(officer || '').trim().slice(0, 80);
  if (name.length < 2) throw Object.assign(new Error('officer name required'), { code: 400 });
  const log = load();
  const prev = log.length ? log[log.length - 1].hash || GENESIS : GENESIS;
  const e = { n: log.length + 1, t: new Date().toISOString(), caseId: String(caseId), host: String(host || ''), decision, officer: name, note: String(note || '').trim().slice(0, 500), prev };
  e.hash = hashOf(e);
  log.push(e);
  try { fs.mkdirSync(DIR, { recursive: true }); fs.appendFileSync(AUDIT, JSON.stringify(e) + '\n'); } catch (err) { console.error('[veto] audit log:', err.message); }
  storeAudit(e);
  return e;
}

/** The whole log, newest first, with a check that the chain is intact. */
export function auditLog() {
  const log = load();
  let prev = GENESIS, intact = true, brokenAt = null;
  for (const e of log) {
    if (e.torn || e.prev !== prev || e.hash !== hashOf(e)) { intact = false; brokenAt = e.n || null; break; }
    prev = e.hash;
  }
  return { entries: [...log].reverse(), count: log.length, intact, brokenAt, head: log.length ? log[log.length - 1].hash : null };
}

/** The latest decision on a case, or null while it still waits for an officer. */
export function reviewOf(caseId) {
  const log = load();
  for (let i = log.length - 1; i >= 0; i--) if (log[i].caseId === caseId) return log[i];
  return null;
}

export function _resetForTests() { cache = []; }
