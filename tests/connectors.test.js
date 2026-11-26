// The search, ads and Maps hunt (server/connectors.js) is tested with fake SerpApi answers only: no network, no credits.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { INSTITUTIONS } from '../data/institutions.js';
import { helplineHunt, connectors, huntPlan, serpGoogle, serpSpent } from '../server/connectors.js';

const realFetch = globalThis.fetch;
const KEYS = ['SEARCHAPI_KEY', 'SERPAPI_KEY', 'SERPAPI_BUDGET', 'BRAVE_API_KEY', 'GOOGLE_PLACES_KEY', 'SERPER_API_KEY'];
const reply = body => ({ ok: true, status: 200, json: async () => body });
function fakeSerp(body) {
  globalThis.fetch = async url => (String(url).includes('engine=google_maps') ? reply({ local_results: [] }) : reply(body));
}
function setKeys(vals) {
  for (const k of KEYS) delete process.env[k];
  Object.assign(process.env, vals);
}

test.afterEach(() => { globalThis.fetch = realFetch; for (const k of KEYS) delete process.env[k]; });

test('a full hunt on 23 institutions needs 115 SerpApi searches, which is over the 100 free', () => {
  setKeys({ SERPAPI_KEY: 'test-key' });
  const plan = huntPlan(Array.from({ length: 23 }, (_, i) => ({ id: 'x' + i, name: { en: 'X', ar: 'X' } })));
  assert.equal(plan.serpApiSearches, 115);
  assert.equal(plan.fitsBudget, false);
  assert.equal(plan.hoursAtThatRate, 3);
});

test('20 institutions fit the 100-search budget exactly', () => {
  setKeys({ SERPAPI_KEY: 'test-key' });
  const plan = huntPlan(Array.from({ length: 20 }, (_, i) => ({ id: 'x' + i, name: { en: 'X', ar: 'X' } })));
  assert.equal(plan.serpApiSearches, 100);
  assert.equal(plan.fitsBudget, true);
});

test('Brave and Google Places take the search and Maps work, so SerpApi spends nothing', () => {
  setKeys({ SERPAPI_KEY: 'test-key', BRAVE_API_KEY: 'b', GOOGLE_PLACES_KEY: 'p' });
  const plan = huntPlan(Array.from({ length: 23 }, (_, i) => ({ id: 'x' + i, name: { en: 'X', ar: 'X' } })));
  assert.equal(plan.serpApiSearches, 0);
  assert.equal(plan.search, 'Brave');
  assert.equal(plan.maps, 'Google Places');
});

test('the budget stops the run before it spends another search', async () => {
  setKeys({ SERPAPI_KEY: 'test-key', SERPAPI_BUDGET: String(serpSpent() + 2) });
  fakeSerp({ organic_results: [] });
  await serpGoogle('first');
  await serpGoogle('second');
  await assert.rejects(() => serpGoogle('third'), /budget reached/);
});

test('an unofficial phone number in a search result is flagged; the answer is fake, not live', async () => {
  setKeys({ SERPAPI_KEY: 'test-key', SERPAPI_BUDGET: String(serpSpent() + 50) });
  const enbd = INSTITUTIONS.find(i => i.id === 'enbd');
  fakeSerp({ organic_results: [{ position: 1, title: 'Emirates NBD customer care', link: 'https://enbd-care-help.xyz/',
    snippet: 'Call our care line 800 123456 any time' }] });
  const found = await connectors.suspects([enbd], () => {});
  assert.ok(found.some(s => /search result/.test(s.how)), 'expected a suspect from a search result');
});

test('helpline hunt attaches regulator evidence across channels and leaves unrelated leads unverified', async () => {
  setKeys({ SEARCHAPI_KEY: 'test' });
  globalThis.fetch = async url => reply(url.searchParams.get('engine') === 'google_maps'
    ? { local_results: [{ title: 'Maps lead', phone: '+971 54 759 6133' }] }
    : { ads: [{ title: 'Advert', phone: '0547596133' }], organic_results: [
      { title: 'Search lead', snippet: 'Call 054 759 6133' },
      { title: 'Other lead', phone: '+971 4 316 1700' }] });
  const { rows } = await helplineHunt(INSTITUTIONS.find(i => i.id === 'fab'));
  assert.deepEqual(rows.filter(r => r.advisory?.source.en.includes('12 January 2026')).map(r => r.channel), ['Ads','Search','Maps']);
  assert.equal(rows.find(r => r.title === 'Other lead').advisory, null);
});

test('ministry hunt scopes the caller warning to the result title and exact phone', async () => {
  setKeys({ SEARCHAPI_KEY: 'test' });
  globalThis.fetch = async url => reply(url.searchParams.get('engine') === 'google_maps'
    ? { local_results: [{ title: 'Unrelated business', phone: '70614213' }] }
    : { organic_results: [{ title: 'Ministry of Interior', snippet: 'Phone: ٧٠٦١٤٢١٣' }] });
  const { rows } = await helplineHunt(INSTITUTIONS.find(i => i.id === 'moi'));
  assert.equal(rows[0].advisory.id, 'moi_reported_caller');
  assert.equal(rows[1].advisory, null);
});

test('RAKBANK hunt preserves the full service number and drops incomplete fragments', async () => {
  setKeys({ SEARCHAPI_KEY: 'test' });
  globalThis.fetch = async url => reply(url.searchParams.get('engine') === 'google_maps'
    ? { local_results: [{title: 'RAKBANK Elite', phone: '800 4048'}] }
    : { organic_results: [{title: 'RAKBANK', snippet: 'Call 600 576 361 or 600 544049. International: +971600576361. Incomplete: 600 576.'}] });
  const { rows } = await helplineHunt(INSTITUTIONS.find(i => i.id === 'rakbank'));
  assert.deepEqual(rows.map(row => [row.phone, row.match]), [
    ['600 576 361', true], ['600 544049', true], ['+971600576361', true], ['800 4048', true]
  ]);
});
