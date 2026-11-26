// Sentinel, the case file, campaign linking, the official ledger and the takedown pack (offline: no network).
process.env.VETO_VAR = process.env.VETO_VAR || (await import('node:os')).tmpdir() + '/veto-test-var-' + process.pid;
import test from 'node:test';
import assert from 'node:assert/strict';
import { mmh3, shodanFaviconHash, sameImage, hamming64, simhash64, kitPrint, campaignKeys, matchLogos, brandSibling, cloakSignal } from '../server/forensics.js';
import { campaigns, _resetForTests } from '../server/cases.js';
import { permutations, scoreSuspect, listingSuspect } from '../server/sentinel.js';
import { reportTexts, dossierHtml, stixBundle } from '../server/dossier.js';
import { checkListing, outgoingCheck, contactsAudit, numberOwner } from '../engine/ledger.js';
import { INSTITUTIONS } from '../data/institutions.js';
import { LOGOS } from '../data/logos.js';

test('MurmurHash3 matches the reference vectors (Shodan favicon hashes depend on it)', () => {
  assert.equal(mmh3(Buffer.from('')), 0);
  assert.equal(mmh3(Buffer.from('hello')), 613153351);
  assert.equal(mmh3(Buffer.from('foo')), -156908512);
  assert.equal(mmh3(Buffer.from(''), 1), 1364076727);
  assert.equal(typeof shodanFaviconHash(Buffer.from('icon bytes')), 'number');
});

test('copied-logo matching: exact bytes or all three perceptual prints, never plain images, never the brand\'s own sites', () => {
  const a = { sha256: 'x', ph: { dh: '0f0f0f0f0f0f0f0f', ah: 'f0f0f0f0f0f0f0f0', rgb: [200, 30, 30], sd: 40 } };
  assert.deepEqual(sameImage(a, { sha256: 'x' }), { exact: true, d: 0 });
  assert.ok(sameImage(a, { sha256: 'y', ph: { dh: '0f0f0f0f0f0f0f0e', ah: 'f0f0f0f0f0f0f0f0', rgb: [205, 28, 33], sd: 38 } }), 'one bit apart, same colour');
  assert.equal(sameImage(a, { sha256: 'y', ph: { dh: '0f0f0f0f0f0f0f0e', ah: 'f0f0f0f0f0f0f0f0', rgb: [20, 30, 200], sd: 38 } }), null, 'different colour');
  assert.equal(sameImage({ ...a, ph: { ...a.ph, sd: 3 } }, { sha256: 'z', ph: { ...a.ph, sd: 3 } }), null, 'flat one-colour images never match');
  assert.equal(hamming64('ffffffffffffffff', '0000000000000000'), 64);
  const enbd = INSTITUTIONS.find(i => i.id === 'enbd');
  assert.ok(brandSibling(enbd, 'emiratesnbd.co.uk') && !brandSibling(enbd, 'emiratesnbd-verify.top'));
  const ref = LOGOS.find(l => l.inst === 'salik' && l.kind === 'favicon');
  if (ref) {
    assert.equal(matchLogos([{ url: 'x', kind: 'favicon', sha256: ref.sha256, ph: null }], 'salik-fine-pay.top')[0]?.inst, 'salik');
    assert.equal(matchLogos([{ url: 'x', kind: 'favicon', sha256: ref.sha256, ph: null }], 'salik.ae').length, 0, 'the real site wears its own icon');
  }
});

test('kit fingerprint: the same kit re-skinned for another bank lands within a few bits', () => {
  const tags = Array.from({ length: 120 }, (_, i) => ['div.card', 'form', 'label', 'input.f', 'button.btn'][i % 5]).join(' ');
  const a = kitPrint({ tags, fields: ['input:text:card_number::', 'input:text:cvv::', 'input:text:otp::'], assets: ['jquery.min.js', 'kit.js'], forms: ['post /next.php'] });
  const b = kitPrint({ tags: tags + ' div.footer p', fields: ['input:text:card_number::', 'input:text:cvv::', 'input:text:otp::'], assets: ['jquery.min.js', 'kit.js'], forms: ['post /next.php'] });
  const c = kitPrint({ tags: Array.from({ length: 120 }, (_, i) => ['section.hero', 'h1', 'p.lead', 'a.cta', 'img'][i % 5]).join(' '), fields: ['input:search:q::'], assets: ['react.js'], forms: ['get /search'] });
  assert.ok(hamming64(a.simhash, b.simhash) <= 6, `near: ${hamming64(a.simhash, b.simhash)}`);
  assert.ok(hamming64(a.simhash, c.simhash) >= 12, `far: ${hamming64(a.simhash, c.simhash)}`);
  assert.equal(kitPrint({ tags: 'div p' }).simhash, null, 'too small to fingerprint');
  assert.equal(simhash64(new Map([['a', 1]])).length, 16);
});

test('campaign keys: bots, wallets, analytics IDs and phone numbers criminals reuse', () => {
  const k = campaignKeys({ html: 'gtag("config","G-ABCDEF1234") https://api.telegram.org/bot7712345678:AAE/sendMessage wa.me/971501234567 0x52908400098527886E0F7030069857D2E4169EE7', text: 'Call 050 123 4567' });
  assert.deepEqual(k.analytics, ['G-ABCDEF1234']);
  assert.deepEqual(k.telegram_bot, ['7712345678']);
  assert.deepEqual(k.whatsapp, ['971501234567']);
  assert.equal(k.wallet.length, 1);
  assert.deepEqual(k.phone, ['+971501234567']);
});

test('campaign linking: shared criminal infrastructure links sites, shared CDNs and official icons do not', () => {
  const base = (id, extra) => ({ id, finalHost: id + '.top', verdict: 'dangerous', risk: 0.99, firstSeen: '2026-11-20T00:00:00Z', lastSeen: '2026-11-21T00:00:00Z', keys: {}, ...extra });
  const recs = [
    base('a1', { keys: { telegram_bot: ['7012345678'] }, imitates: { id: 'enbd', name: { en: 'Emirates NBD' } } }),
    base('b2', { keys: { telegram_bot: ['7012345678'], analytics: ['G-VT7DEMO2026'] }, imitates: { id: 'salik', name: { en: 'Salik' } } }),
    base('c3', { keys: { analytics: ['G-VT7DEMO2026'] } }),
    base('d4', { infra: { ip: '104.21.1.1', asName: 'CLOUDFLARENET' } }),
    base('e5', { infra: { ip: '104.21.1.1', asName: 'CLOUDFLARENET' } }),
    base('f6', { favicon: { sha256: LOGOS[0]?.sha256 || 'none', shodan: 1 } }),
    base('g7', { favicon: { sha256: LOGOS[0]?.sha256 || 'none', shodan: 1 } })
  ];
  _resetForTests(recs);
  const c = campaigns(recs);
  assert.equal(c.length, 1, 'only the bot + analytics group');
  assert.deepEqual(c[0].members.map(m => m.id).sort(), ['a1', 'b2', 'c3']);
  assert.ok(c[0].links.some(l => l.why === 'telegram_bot') && c[0].links.some(l => l.why === 'analytics'));
  assert.equal(c[0].brands.length, 2);
});

test('Sentinel look-alike names: realistic, valid, and never the official domain itself', () => {
  const p = permutations('emiratesnbd.com', ['enbd']);
  const hosts = new Set(p.map(x => x.host));
  for (const h of ['emiratesbd.com', 'emiratesnbd.top', 'emiratesnbd-verify.com', 'emirates-nbd.com', 'em1ratesnbd.com', 'enbd-uae.online']) assert.ok(hosts.has(h), h);
  assert.ok(!hosts.has('emiratesnbd.com'));
  assert.ok([...hosts].every(h => /^[a-z0-9-]+\.[a-z]+$/.test(h) && !/--/.test(h)));
  const gov = permutations('adpolice.gov.ae');
  assert.ok(gov.every(x => !x.host.endsWith('.gov.ae')), 'nobody can register under gov.ae, so edits go to .com/.ae');
  assert.ok(permutations('dib.ae').every(x => x.how !== 'missing letter'), 'short names only get endings and words, not letter edits');
});

test('Sentinel ranking: an unrelated business that shares letters ranks low; an armed UAE-targeted copy ranks high', () => {
  const unrelated = scoreSuspect({ host: 'rta.org', inst: 'rta', how: 'other ending', sources: ['lookalike'], status: 'live', web: { brandInPage: true, uae: false, secrets: 6 } });
  const armed = scoreSuspect({ host: 'rta-fines.top', inst: 'rta', how: 'brand + word', sources: ['lookalike', 'ct'], status: 'live', web: { brandInPage: true, uae: true, secrets: 3 }, ml: { p: 0.95, brand: true }, verdict: 'dangerous', armed: true, proof: ['asks_secrets', 'exfil_telegram'] });
  const nameOnly = scoreSuspect({ host: 'emiratesnbd.live', inst: 'enbd', how: 'other ending', sources: ['lookalike'], status: 'live', web: {}, verdict: 'suspicious', armed: false });
  assert.ok(unrelated.score < 0.5, `unrelated ${unrelated.score}`);
  assert.ok(armed.score > 0.95, `armed ${armed.score}`);
  assert.ok(nameOnly.score < armed.score && nameOnly.score < 0.7, `name only ${nameOnly.score}`);
  assert.equal(scoreSuspect({ host: 'x', inst: 'enbd', status: 'brand_owned', sources: [] }).score, 0);
});

test('cloaking signal: only a difference between phone and computer/crawler counts', () => {
  assert.equal(cloakSignal({ verdict: 'none', who: [] }), null);
  const s = cloakSignal({ verdict: 'cloaked', who: [{ who: 'crawler', how: 'elsewhere', to: 'blog.example' }] });
  assert.equal(s.id, 'cloaking');
  assert.ok(s.w >= 0.55 && s.en.includes('blog.example') && s.ar.length > 10);
});

test('official ledger: fake Maps listings, the real listing, outgoing calls and contacts', () => {
  assert.equal(checkListing({ name: 'Emirates NBD Customer Care 24/7', phone: '+971 52 318 4407' }).verdict, 'fake');
  assert.equal(checkListing({ name: 'Emirates NBD', phone: '600 54 0000', website: 'https://www.emiratesnbd.com/en' }).verdict, 'official');
  const adcb = checkListing({ name: 'ADCB Card Refund Center', phone: '04 330 1288', website: 'https://adcb-refund-uae.com/claim' });
  assert.equal(adcb.verdict, 'fake');
  assert.ok(adcb.signals.some(s => s.id === 'listing_site'));
  const branch = checkListing({ name: 'ADCB', phone: '02 621 0090' });
  assert.equal(branch.verdict, 'suspicious', 'an unknown landline may be a branch: it warns, it does not condemn');
  assert.equal(checkListing({ name: "Joe's Pizza", phone: '04 555 1234' }).verdict, 'unknown');
  assert.equal(numberOwner('8002626')?.id, 'adpolice');
  const o = outgoingCheck('+971 52 318 4407', { flagged: [{ number: '523184407', inst: 'enbd', why: 'a scam SMS' }] });
  assert.equal(o.verdict, 'intercept');
  assert.equal(o.official.number, '600540000');
  assert.equal(outgoingCheck('600540000').verdict, 'official');
  assert.equal(outgoingCheck('0501112233').verdict, 'ok', 'an ordinary call is never touched');
  const audit = contactsAudit([{ name: 'ENBD Bank Security', number: '+971 55 123 4567' }, { name: 'Emirates NBD', number: '600540000' }, { name: 'Mum', number: '0501234567' }]);
  assert.equal(audit.length, 1);
  assert.equal(audit[0].inst.id, 'enbd');
});

test('takedown pack: escapes everything the scam page controls, and the STIX bundle is well-formed', () => {
  const rec = { id: 'abc123abc123', finalUrl: 'https://evil.top/login', input: 'https://evil.top/login', finalHost: 'evil.top', registrable: 'evil.top', verdict: 'dangerous', risk: 0.99,
    title: '<script>alert(1)</script>', firstSeen: '2026-11-23T10:00:00.000Z', asks: ['card', 'otp'], exfil: [{ kind: 'telegram', host: 'api.telegram.org', bot: 'bot7••' }],
    imitates: { id: 'enbd', name: { en: 'Emirates NBD' } }, signals: [{ id: 'x', w: 0.9, en: '<img src=x onerror=alert(1)>', ar: 'ع' }],
    keys: { telegram_bot: ['7012345678'] }, infra: { registrar: 'Evil Registrar <b>', abuseEmail: 'abuse@reg.example', ip: '203.0.113.5', asName: 'HOST', asn: 64500, country: 'NL', created: '2026-11-20T00:00:00Z' },
    takedown: [{ name: 'Telegram', email: 'abuse@telegram.org', why: 'ban the bot' }] };
  const html = dossierHtml(rec);
  assert.ok(!html.includes('<script>alert(1)') && !html.includes('<img src=x'), 'scam-controlled text is escaped');
  assert.ok(html.includes('&lt;script&gt;'));
  const t = reportTexts(rec);
  assert.ok(t.registrar.includes('ICANN') && t.registrar.includes('evil.top') && t.telegram.includes('7012345678'));
  const b = stixBundle(rec);
  assert.equal(b.type, 'bundle');
  const ind = b.objects.filter(o => o.type === 'indicator');
  assert.ok(ind.some(o => o.pattern === "[url:value = 'https://evil.top/login']"));
  assert.ok(ind.some(o => o.pattern === "[ipv4-addr:value = '203.0.113.5']"));
  assert.ok(b.objects.every(o => /^[a-z-]+--[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(o.id)), 'STIX ids are UUIDv4-shaped');
});

test('weak shared traces never merge sites, and a campaign states how strong its links are', () => {
  const base = (id, extra) => ({ id, finalHost: id + '.top', verdict: 'dangerous', risk: 0.9, firstSeen: '2026-11-20T00:00:00Z', lastSeen: '2026-11-21T00:00:00Z', keys: {}, ...extra });
  const weak = [
    base('w1', { favicon: { sha256: 'a1b2c3', shodan: 77 } }),
    base('w2', { favicon: { sha256: 'a1b2c3', shodan: 77 } }),
    base('w3', { infra: { registrar: 'NameCheap', created: '2026-11-20T10:00:00Z' } }),
    base('w4', { infra: { registrar: 'NameCheap', created: '2026-11-20T11:00:00Z' } })
  ];
  _resetForTests(weak);
  assert.equal(campaigns(weak).length, 0);
  const strong = [base('s1', { keys: { telegram_bot: ['7098765432'] } }), base('s2', { keys: { telegram_bot: ['7098765432'] } })];
  _resetForTests(strong);
  const c = campaigns(strong);
  assert.equal(c.length, 1);
  assert.equal(c[0].confidence, 'high');
});

test('historical DFSA contact matches exact UAE formats and preserves genuine NBK contact', () => {
  for (const phone of ['+971 54 759 6133', '00971547596133', '0547596133', '٠٥٤ ٧٥٩ ٦١٣٣']) {
    const result = checkListing({ name: 'Sidra Capital', phone });
    assert.equal(result.verdict, 'suspicious');
    assert.match(result.signals[0].source.en, /12 January 2026/);
  }
  assert.equal(checkListing({ phone: '+966 54 759 6133' }).signals.length, 0);
  const result = checkListing({ name: 'NBK', phone: '+971 4 316 1700' });
  assert.equal(result.verdict, 'official');
  assert.equal(result.signals.length, 0);
  assert.ok(result.positives.some(p => p.source?.url.includes('nbk.com')));
});

test('official matches retain country codes and accept Arabic digits', () => {
  assert.equal(numberOwner('+966 600 54 0000'), null);
  assert.equal(numberOwner('+971 600 54 0000').id, 'enbd');
  assert.equal(checkListing({ name: 'NBK', phone: '٠٤ ٣١٦ ١٧٠٠' }).verdict, 'official');
});

test('MOI caller advisory requires both the claimed ministry and exact displayed digits', () => {
  const check = (phone, name = 'Ministry of Interior') => checkListing({ name, phone });
  assert.equal(check('+971 800 5000').verdict, 'official');
  const hit = check('٧٠٦١٤٢١٣');
  assert.equal(hit.verdict, 'suspicious');
  assert.equal(hit.signals[0].source.url, 'https://x.com/moiuae/status/2028040738475483569');
  for (const result of [check('+97170614213'), check('70614213', 'Unrelated help desk')]) {
    assert.ok(!result.signals.some(signal => signal.id === 'moi_reported_caller'));
  }
});

test('reviewed Wio guide is attributed to its publisher only with matching evidence', () => {
  const guide = { name: 'Wio Bank Business Account UAE', phone: '+971 50 496 3962', website: 'https://www.emirhub.ae/banking/wio/' };
  assert.equal(checkListing(guide).verdict, 'guide');
  assert.equal(listingSuspect(guide), null);
  for (const change of [{name:'Official Wio Customer Support'}, {phone:'0501234567'}, {website:'https://emirhub.ae.example/banking/wio/'}, {text:'Call our Wio customer support desk'}]) {
    assert.equal(checkListing({...guide, ...change}).verdict, 'fake');
  }
});
