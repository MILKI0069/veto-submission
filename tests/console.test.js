// Police console access and the officer sign-off log (server/console.js). No network, a temporary folder for the log.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'veto-console-'));
process.env.VETO_VAR = dir;
process.env.VETO_CONSOLE_TOKEN = 'officer-code-123';
const c = await import('../server/console.js');
const reqWith = cookie => ({ headers: { cookie } });

test('the access code is checked exactly, and nothing passes when no code is set', () => {
  assert.equal(c.checkCode('officer-code-123'), true);
  assert.equal(c.checkCode('officer-code-124'), false);
  assert.equal(c.checkCode(''), false);
  assert.equal(c.checkCode(undefined), false);
  process.env.VETO_CONSOLE_TOKEN = '';
  assert.equal(c.codeConfigured(), false);
  assert.equal(c.checkCode(''), false);
  process.env.VETO_CONSOLE_TOKEN = 'short';
  assert.equal(c.checkCode('short'), false, 'a code under 8 characters is not accepted as configured');
  process.env.VETO_CONSOLE_TOKEN = 'officer-code-123';
});

test('a session cookie is HttpOnly, signed, and refused when changed or expired', () => {
  const set = c.sessionCookie({ headers: { 'x-forwarded-proto': 'https' } });
  assert.match(set, /HttpOnly/);
  assert.match(set, /SameSite=Strict/);
  assert.match(set, /Secure/);
  const pair = set.split(';')[0];
  assert.equal(c.hasSession(reqWith(pair)), true);
  assert.equal(c.hasSession(reqWith('')), false);
  const [name, val] = pair.split('=');
  const [exp, sig] = val.split('.');
  assert.equal(c.hasSession(reqWith(`${name}=${Number(exp) + 1000}.${sig}`)), false, 'a later expiry needs a new signature');
  assert.equal(c.hasSession(reqWith(`${name}=${exp}.${'0'.repeat(64)}`)), false);
  assert.equal(c.hasSession(reqWith(`${name}=1000000000000.${sig}`)), false, 'an expired session is refused');
  process.env.VETO_CONSOLE_TOKEN = 'another-code-456';
  assert.equal(c.hasSession(reqWith(pair)), false, 'changing the access code ends every session');
  process.env.VETO_CONSOLE_TOKEN = 'officer-code-123';
});

test('officer decisions form a hash chain, and a changed entry is detected', () => {
  c._resetForTests();
  const a = c.recordReview({ caseId: 'aaaaaaaaaaaa', host: 'bad.example', decision: 'needs_info', officer: 'Lt. Test', note: 'check registrar' });
  const b = c.recordReview({ caseId: 'aaaaaaaaaaaa', host: 'bad.example', decision: 'approved', officer: 'Lt. Test' });
  assert.equal(a.n, 1);
  assert.equal(b.prev, a.hash);
  assert.equal(c.reviewOf('aaaaaaaaaaaa').decision, 'approved', 'the latest decision wins');
  assert.equal(c.reviewOf('bbbbbbbbbbbb'), null);
  let log = c.auditLog();
  assert.equal(log.count, 2);
  assert.equal(log.intact, true);
  assert.equal(log.entries[0].n, 2, 'newest first');
  assert.equal(log.head, b.hash);
  const lines = fs.readFileSync(path.join(dir, 'audit.jsonl'), 'utf8').trim().split('\n');
  assert.equal(lines.length, 2);
  a.decision = 'rejected';
  log = c.auditLog();
  assert.equal(log.intact, false);
  assert.equal(log.brokenAt, 1);
});

test('a decision needs a known value and an officer name', () => {
  c._resetForTests();
  assert.throws(() => c.recordReview({ caseId: 'x', decision: 'maybe', officer: 'Lt. Test' }), /bad decision/);
  assert.throws(() => c.recordReview({ caseId: 'x', decision: 'approved', officer: ' ' }), /officer name required/);
  assert.equal(c.auditLog().count, 0);
});

test('the access code forgives surrounding spaces and letter case', () => {
  process.env.VETO_CONSOLE_TOKEN = 'ADP-Officer-123';
  assert.equal(c.checkCode(' adp-officer-123 \n'), true);
  assert.equal(c.checkCode('ADP-Officer-124'), false);
  process.env.VETO_CONSOLE_TOKEN = 'officer-code-123';
});
