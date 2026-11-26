// The URL Judge (offline layers), list parsing and metrics, the evidence ZIP writer.
import test from 'node:test';
import assert from 'node:assert/strict';
import { judgeOffline, parseList, metrics } from '../server/judge.js';
import { makeZip, crc32 } from '../server/zip.js';
import { featurizeUrl, isPlatform, refang } from '../engine/urlml2.js';
import { INSTITUTIONS } from '../data/institutions.js';
import { splitDomain } from '../engine/url.js';

test('official UAE sites and restricted government domains are never flagged', () => {
  for (const d of INSTITUTIONS.flatMap(i => i.domains).slice(0, 80)) assert.equal(judgeOffline(`https://www.${d}/en/login`).verdict, 'legitimate', d);
  assert.equal(judgeOffline('https://www.moi.gov.ae/en/services').verdict, 'legitimate');
  assert.equal(judgeOffline('https://zu.ac.ae/main/en/').verdict, 'legitimate');
});

test('classic phishing addresses are flagged with reasons in both languages', () => {
  for (const u of ['http://emiratesnbd-secure-verify.top/login.php?email=a@b.com', 'https://uaepass-login-update.online/auth/verify', 'http://adcb.com-account-security.xyz/signin']) {
    const r = judgeOffline(u);
    assert.notEqual(r.verdict, 'legitimate', u);
    assert.ok(r.reasons.length && r.reasons[0].en && r.reasons[0].ar, u);
  }
});

test('invalid input is reported, not guessed', () => {
  assert.equal(judgeOffline('not a url at all').verdict, 'invalid');
  assert.equal(judgeOffline('').verdict, 'invalid');
});

test('lists: plain lines or CSV with labels, and metrics', () => {
  const a = parseList('https://a.example/x\nhttps://b.example/y');
  assert.equal(a.length, 2); assert.equal(a[0].label, null);
  const b = parseList('url,label\nhttps://a.example/x,phishing\nhttps://b.example/y,0\n"https://c.example/z",legitimate');
  assert.deepEqual(b.map(r => r.label), [1, 0, 0]);
  const m = metrics([{ verdict: 'phishing', label: 1 }, { verdict: 'legitimate', label: 0 }, { verdict: 'suspicious', label: 1 }, { verdict: 'phishing', label: 0 }]);
  assert.equal(m.strict.tp, 1); assert.equal(m.strict.fp, 1); assert.equal(m.strict.fn, 1);
  assert.equal(m.cautious.tp, 2);
});

test('hosting platforms are recognised, so popularity never vouches for a stranger\'s page', () => {
  assert.ok(isPlatform('sites.google.com', 'google.com'));
  assert.ok(isPlatform('evil-bank.web.app', 'web.app'));
  assert.ok(!isPlatform('www.emiratesnbd.com', 'emiratesnbd.com'));
  const f = featurizeUrl('https://sites.google.com/view/x', true);
  assert.ok([...f.keys.values()].some(k => /^pop:.*:platform$/.test(k)));
});

test('evidence ZIP: valid archive with correct CRC-32', () => {
  assert.equal(crc32(Buffer.from('hello')).toString(16), '3610a686');
  const z = makeZip([{ name: 'a.txt', data: 'hello' }, { name: 'MANIFEST-SHA256.txt', data: 'x' }]);
  assert.equal(z.readUInt32LE(0), 0x04034b50, 'local header');
  assert.equal(z.readUInt32LE(z.length - 22), 0x06054b50, 'end of central directory');
  assert.equal(z.readUInt16LE(z.length - 22 + 10), 2, 'two entries');
});

test('an open redirect on a trusted site is judged by where it sends the visitor', () => {
  const bad = 'http://emiratesnbd-secure-verify.top/login.php?email=a@b.com';
  const r = judgeOffline('https://www.google.com/url?q=' + encodeURIComponent(bad));
  assert.notEqual(r.verdict, 'legitimate');
  assert.equal(r.layers.redirect_to, 'emiratesnbd-secure-verify.top');
  assert.equal(r.reasons[0].id, 'redirect');
  assert.notEqual(judgeOffline('https://www.adcb.com/redirect?url=' + encodeURIComponent('https://uaepass-login-update.online/auth/verify')).verdict, 'legitimate');
});

test('a trusted redirect to an official page stays legitimate', () => {
  assert.equal(judgeOffline('https://www.google.com/url?q=' + encodeURIComponent('https://www.emiratesnbd.com/en/')).verdict, 'legitimate');
});

test('a trailing dot on the host does not change the verdict', () => {
  assert.notEqual(judgeOffline('https://metamzklogi.gitbook.io/').verdict, 'legitimate');
  assert.equal(judgeOffline('https://metamzklogi.gitbook.io./').verdict, judgeOffline('https://metamzklogi.gitbook.io/').verdict);
});

test('public file buckets: a victim e-mail in the link, a famous name with lure words, and two lure words are judged', () => {
  const victim = Buffer.from('victim.example@mail.example').toString('base64');
  assert.notEqual(judgeOffline(`https://portal-files.s3.us-east-1.amazonaws.com/login.html?u=${victim}`).verdict, 'legitimate');
  assert.equal(judgeOffline('https://dhl-waybill-delivery.s3.us-east-2.amazonaws.com/track/index.html').verdict, 'phishing');
  assert.notEqual(judgeOffline('https://shared-review-document.s3.us-east-2.amazonaws.com/pdf/document.html').verdict, 'legitimate');
});

test('ordinary bucket content stays legitimate', () => {
  assert.equal(judgeOffline('https://company-assets.s3.eu-west-1.amazonaws.com/images/logo.png').verdict, 'legitimate');
  assert.notEqual(judgeOffline('https://reports-2025.s3.amazonaws.com/annual.html').verdict, 'phishing'); // the host alone is capped at suspicious
});

test('defanged and wrapped links get the same verdict as the plain link', () => {
  const plain = 'https://uaepass-login-update.online/auth/verify';
  const want = judgeOffline(plain).verdict;
  for (const v of ['hxxps://uaepass-login-update[.]online/auth/verify', 'hxxps[:]//uaepass-login-update[.]online/auth/verify',
    'https://uaepass-login-update(.)online/auth/verify', 'uaepass-login-update[dot]online/auth/verify', 'h**ps://uaepass-login-update{.}online/auth/verify',
    `<${plain}>`, `"${plain}"`, `'${plain}'`]) assert.equal(judgeOffline(v).verdict, want, v);
  assert.equal(judgeOffline('hxxps://www[.]emiratesnbd[.]com/en').verdict, 'legitimate');
  assert.equal(refang('https://example.com/a(b)c'), 'https://example.com/a(b)c', 'ordinary brackets stay');
});

test('lists: quoted commas, unfamiliar column names, other delimiters, label words', () => {
  const q = parseList('id,url,label\n1,"https://a.example/p?x=1,2",phishing\n2,https://b.example/,legitimate');
  assert.deepEqual(q, [{ url: 'https://a.example/p?x=1,2', label: 1 }, { url: 'https://b.example/', label: 0 }]);
  const n = parseList('id,Website URL,is_fraud\n1,https://a.example/login,1\n2,https://b.example/,0');
  assert.deepEqual(n.map(r => [r.url, r.label]), [['https://a.example/login', 1], ['https://b.example/', 0]]);
  const s = parseList('url;label\nhttps://a.example/a;b,c;malicious\nhttps://b.example/;benign');
  assert.deepEqual(s.map(r => [r.url, r.label]), [['https://a.example/a;b,c', 1], ['https://b.example/', 0]]);
  const c = parseList('ref|link|truth\n7|hxxps://a[.]example/x|Phishing\n8|https://b.example/|Not Phishing');
  assert.deepEqual(c.map(r => r.label), [1, 0]);
  assert.equal(judgeOffline(c[0].url).verdict === 'invalid', false);
  const unnamed = parseList('a,b,c\n1,https://a.example/x,yes\n2,www.b.example,no'); // columns found by content
  assert.deepEqual(unnamed.map(r => [r.url, r.label]), [['https://a.example/x', 1], ['www.b.example', 0]]);
  const bare = parseList('https://a.example/x?a=1,2\nhttps://b.example/y'); // a comma in a bare URL list stays in the URL
  assert.deepEqual(bare.map(r => r.url), ['https://a.example/x?a=1,2', 'https://b.example/y']);
  const headless = parseList('https://a.example/x,1\nhttps://b.example/y,0');
  assert.deepEqual(headless.map(r => [r.url, r.label]), [['https://a.example/x', 1], ['https://b.example/y', 0]]);
});

test('a short link with a code is not vouched for by the shortener, but the shortener home page is fine', () => {
  for (const u of ['https://tinyurl.com/2v26ub55', 'https://bit.ly/3AbCdEf', 'hxxps://u[.]to/cfzZIg']) {
    const r = judgeOffline(u);
    assert.notEqual(r.verdict, 'legitimate', u); // at least suspicious: the floor is a minimum, and the model can still rate a link phishing
    assert.ok(r.reasons.some(x => x.id === 'short_link' && x.en && x.ar), u);
  }
  assert.equal(judgeOffline('https://tinyurl.com/').verdict, 'legitimate');
});

test('a subdomain on a provider that gives subdomains to anyone gets no popularity discount', () => {
  const r = judgeOffline('https://db2156.craftum.io/');
  assert.equal(r.layers.platform, true);
});

test('public-body registries abroad and Google country domains are not flagged; brand look-alikes still are', () => {
  for (const u of ['https://www.tjsp.jus.br/QuemSomos', 'https://www.gob.mx/sat', 'https://www.service-public.gouv.fr/', 'https://google.com.lb/', 'https://google.iq/'])
    assert.equal(judgeOffline(u).verdict, 'legitimate', u);
  for (const u of ['https://google-login.com.lb/', 'https://www.google.com.verify-account.top/', 'https://paypal-com.verify-login.xyz/'])
    assert.equal(judgeOffline(u).verdict, 'phishing', u);
});

test('country second-level zones give the right registrable domain', () => {
  assert.equal(splitDomain('google.com.lb').registrable, 'google.com.lb');
  assert.equal(splitDomain('www.fedfarm.org.nz').registrable, 'fedfarm.org.nz');
  assert.equal(splitDomain('shop.example.co.kr').registrable, 'example.co.kr');
  assert.equal(splitDomain('nic.ae').registrable, 'nic.ae');
  assert.equal(splitDomain('evil.github.io').registrable, 'evil.github.io');
});

test('metrics report how many labelled rows were not web addresses', () => {
  assert.equal(metrics([{ verdict: 'invalid', label: 1 }, { verdict: 'phishing', label: 1 }]).invalid, 1);
});

test('a tenant HTML page cannot borrow the storage provider’s popularity', () => {
  const result = judgeOffline('https://ab89kdefg23qw.s3.eu-north-1.amazonaws.com/start.html');
  assert.equal(result.layers.platform, true);
  assert.equal(result.verdict, 'suspicious');
  assert.equal(judgeOffline('https://ab89kdefg23qw.s3.eu-north-1.amazonaws.com/logo.png').layers.platform, false);
});
