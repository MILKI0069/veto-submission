// SSRF guard for the X-ray chamber: the chamber must never be tricked into opening
// internal addresses (router admin pages, cloud metadata, the Veto server itself).

import dns from 'node:dns/promises';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';

export function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || (a === 198 && (b === 18 || b === 19)) ||
      (a === 192 && b === 0) || a >= 224;
  }
  if (net.isIPv6(ip)) {
    const x = ip.toLowerCase();
    if (x.startsWith('::ffff:')) return isPrivateIp(x.slice(7));
    return x === '::1' || x === '::' || x.startsWith('fc') || x.startsWith('fd') || x.startsWith('fe8') || x.startsWith('fe9') ||
      x.startsWith('fea') || x.startsWith('feb') || x.startsWith('ff');
  }
  return true;
}

const LOCAL_NAMES = /(^localhost$|\.localhost$|\.local$|\.internal$|\.lan$|\.home$|\.corp$|^metadata\b)/i;

/**
 * @returns {Promise<{ok: boolean, reason?: string, demo?: boolean}>}
 */
export async function checkHost(hostname, { demoHosts = false } = {}) {
  const h = String(hostname).toLowerCase().replace(/^\[|\]$/g, '');
  if (demoHosts && /^[a-z0-9-]+\.localhost$/.test(h)) return { ok: true, demo: true };
  if (LOCAL_NAMES.test(h)) return { ok: false, reason: 'is a local network address' };
  let ips;
  try {
    ips = net.isIP(h) ? [h] : (await dns.lookup(h, { all: true, verbatim: true })).map(a => a.address);
  } catch {
    return { ok: false, reason: 'domain does not resolve' };
  }
  if (!ips.length) return { ok: false, reason: 'domain does not resolve' };
  if (ips.some(isPrivateIp)) return { ok: false, reason: 'points to a private / internal address' };
  return { ok: true, ips };
}

/**
 * Download a file (e.g. An APK the page tried to push) for static inspection, through the same SSRF
 * guard, re-checked on every redirect, pinned to the checked IP (no DNS-rebinding window), size-capped.
 * The bytes are only parsed, never executed or saved.
 */
export async function fetchBytes(url, { demoHosts = false, maxBytes = 40 << 20, timeout = 15000, hops = 5, headersOnly = false, userAgent = 'Mozilla/5.0 (Linux; Android 14)' } = {}) {
  let cur;
  try { cur = new URL(url); } catch { return { ok: false, error: 'bad url' }; }
  for (let i = 0; i <= hops; i++) {
    if (!['http:', 'https:'].includes(cur.protocol)) return { ok: false, error: 'not a web link' };
    const chk = await checkHost(cur.hostname, { demoHosts });
    if (!chk.ok) return { ok: false, error: chk.reason };
    const ip = chk.demo ? '127.0.0.1' : chk.ips[0];
    const family = net.isIPv6(ip) ? 6 : 4;
    const res = await new Promise(resolve => {
      const mod = cur.protocol === 'https:' ? https : http;
      const req = mod.request(cur, {
        method: 'GET', timeout, rejectUnauthorized: headersOnly, // bytes are inspected, never trusted
        headers: { 'user-agent': userAgent, accept: '*/*' },
        lookup: (_h, opts, cb) => (opts && opts.all ? cb(null, [{ address: ip, family }]) : cb(null, ip, family))
      }, r => {
        if (headersOnly) {
          const status = r.statusCode;
          let destination = null;
          if ([301, 302, 303, 307, 308].includes(status) && r.headers.location) {
            try {
              const target = new URL(r.headers.location, cur);
              if (['http:', 'https:'].includes(target.protocol)) destination = target.origin + target.pathname;
            } catch { /* Invalid Location. */ }
          }
          resolve({ status, destination });
          r.destroy();
          return;
        }
        if (r.statusCode >= 300 && r.statusCode < 400 && r.headers.location) { r.resume(); return resolve({ redirect: r.headers.location }); }
        if (r.statusCode !== 200) { r.resume(); return resolve({ error: `HTTP ${r.statusCode}` }); }
        const declared = Number(r.headers['content-length'] || 0);
        if (declared > maxBytes) { r.destroy(); return resolve({ error: 'file too large to inspect', size: declared }); }
        const chunks = []; let size = 0;
        r.on('data', c => { size += c.length; if (size > maxBytes) { r.destroy(); resolve({ error: 'file too large to inspect', size }); } else chunks.push(c); });
        r.on('end', () => resolve({ bytes: Buffer.concat(chunks), contentType: r.headers['content-type'] || '', disposition: r.headers['content-disposition'] || '' }));
        r.on('error', e => resolve({ error: String(e.message || e) }));
      });
      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.on('error', e => resolve({ error: String(e.message || e) }));
      req.end();
    });
    if (res.redirect) { try { cur = new URL(res.redirect, cur); continue; } catch { return { ok: false, error: 'bad redirect' }; } }
    if (res.error) return { ok: false, error: res.error, size: res.size };
    return { ok: true, finalUrl: cur.href, ...res };
  }
  return { ok: false, error: 'too many redirects' };
}
