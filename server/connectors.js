// Optional search and maps connectors for Sentinel. OFF unless the operator sets a key:
//   BRAVE_API_KEY       Brave Search API, web results  (https://api.search.brave.com, free tier available)
//   GOOGLE_PLACES_KEY   Google Places API (New) Text Search, business listings with phone + website
//                       (phone fields are billed at the Enterprise SKU: keep sweeps small)
//   SERPER_API_KEY      Serper.dev: Google results and Google Maps listings (phone, website), one key for both
//   SERPAPI_KEY         SerpApi: Google results INCLUDING PAID ADS, and Google Maps listings (phone, website), one key
//                       for both (free plan: 100 searches a month)
// Only queries ABOUT institutions are sent ("Emirates NBD customer care number"), never any user data.
// Google's Custom Search JSON API is closed to new customers (2026), so web search uses Brave.

import { analyzeUrl, splitDomain, officialFor } from '../engine/url.js';
import { findInstitutions } from '../engine/extract.js';
import { foldDigits, matchForm } from '../engine/normalize.js';
import { NEUTRAL_DOMAINS } from '../data/institutions.js';
import { checkListing, guidePublisher } from '../engine/ledger.js';
import { sameNumber, exactShort } from '../engine/context.js';
import { listingSuspect } from './sentinel.js';

const BRAVE = () => process.env.BRAVE_API_KEY || '';
const PLACES = () => process.env.GOOGLE_PLACES_KEY || '';
const SERP = () => process.env.SERPAPI_KEY || process.env.SERPAPI_API_KEY || '';
const SERPER = () => process.env.SERPER_API_KEY || '';
const searchApiKey = () => process.env.SEARCHAPI_KEY;
export const connectorsConfigured = () => ({ search: !!(searchApiKey() || BRAVE() || SERPER() || SERP()), maps: !!(searchApiKey() || PLACES() || SERPER() || SERP()), ads: !!(searchApiKey() || SERP()) });

let searchApiCalls = 0;
async function searchApi(engine, q) {
  if (!searchApiKey()) throw new Error('SearchApi key missing');
  if (searchApiCalls >= 50) throw new Error('SearchApi process limit reached');
  searchApiCalls++;
  const url = new URL('https://www.searchapi.io/api/v1/search');
  url.search = new URLSearchParams({ engine, q, hl: 'en', ...(engine === 'google' ? { gl: 'ae', location: 'United Arab Emirates' } : { ll: '@24.4539,54.3773,12z' }) });
  const r = await fetch(url, { headers: { Authorization: 'Bearer ' + searchApiKey() }, signal: AbortSignal.timeout(30000) });
  if (!r.ok) throw new Error('SearchApi HTTP ' + r.status);
  const j = await r.json();
  if (j.error) throw new Error('SearchApi query rejected');
  return j;
}
async function searchApiResults(q) {
  const j = await searchApi('google', q);
  const ads = [...(j.ads || []), ...(j.local_ads?.ads || [])];
  return [...ads.map(x => ({...x, ad: true})), ...(j.organic_results || [])].map((x,i) => ({
    title: x.title || '', url: x.link || '', description: x.description || x.snippet || '', rank: x.position || i+1, ad: !!x.ad, phone: x.phone
  }));
}
async function searchApiMaps(q) {
  const j = await searchApi('google_maps', q);
  return (j.local_results || []).map(p => ({name: p.title, phone: p.phone, website: p.website, address: p.address, placeId: p.place_id}));
}
export async function helplineHunt(inst) {
  const q = inst.name.en + ' customer service phone number UAE';
  const [web, maps] = await Promise.allSettled([searchApiResults(q), searchApiMaps(q)]);
  const rows = [];
  const add = (channel,title,phone,url,text,sourceUrl = url) => {
    if (!phone) return;
    const match = (inst.phones || []).some(p => p.v && (sameNumber(p.n, phone) || exactShort(p.n, phone)));
    const result = checkListing({ name: title, phone, website: url, text });
    const advisory = result.signals.find(signal => signal.source) || null;
    rows.push({channel,title,phone,url,sourceUrl,excerpt:text || '',match,advisory,guide:result.verdict === 'guide'});
  };
  for (const r of web.value || []) {
    const snippet = foldDigits(r.title + ' ' + r.description);
    const labelled = snippet.matchAll(/(?:phone|call|tel|helpline|رقم|اتصل)\s*[:：]?\s*(\d{8})(?![\d-])/gi);
    const phones = new Set([r.phone, ...(snippet.match(PHONE_RX) || []), ...Array.from(labelled, m => m[1])]);
    for (const phone of phones) add(r.ad ? 'Ads' : 'Search',r.title,phone,r.url,r.description);
  }
  for (const r of maps.value || []) add('Maps',r.name,r.phone,r.website,undefined,
    r.placeId ? 'https://www.google.com/maps/search/?api=1&query='+encodeURIComponent(r.name)+'&query_place_id='+encodeURIComponent(r.placeId) : r.website);
  return { at: new Date().toISOString(), query:q, rows, counts: {
    Search:web.value?.filter(r=>!r.ad).length ?? null, Ads:web.value?.filter(r=>r.ad).length ?? null, Maps:maps.value?.length ?? null
  }, errors:[web,maps].flatMap((r,i)=>r.status==='rejected' ? [(i?'Maps':'Search / Ads')+' · '+r.reason.message] : []) };
}
// Serper.dev calls in this process are capped too, so a mistake cannot empty the account (SERPER_BUDGET to change it).
let serperUsed = 0;
async function serper(kind, q) {
  if (serperUsed >= (Number(process.env.SERPER_BUDGET) || 300)) throw new Error('Serper budget reached for this run (set SERPER_BUDGET to allow more)');
  serperUsed++;
  const r = await fetch(`https://google.serper.dev/${kind}`, { method: 'POST', signal: AbortSignal.timeout(15000),
    headers: { 'content-type': 'application/json', 'x-api-key': SERPER() }, body: JSON.stringify({ q, gl: 'ae', hl: 'en', num: 20 }) });
  if (!r.ok) throw new Error(`Serper HTTP ${r.status}`);
  return r.json();
}
/** Google results through Serper.dev. */
export async function serperSearch(q) {
  if (!SERPER()) return null;
  const j = await serper('search', q);
  return (j.organic || []).map((x, i) => ({ rank: x.position || i + 1, ad: false, title: x.title || '', url: x.link || '', description: x.snippet || '' }));
}
/** Google Maps listings through Serper.dev (name, phone, website, address). */
export async function serperPlaces(q) {
  if (!SERPER()) return null;
  const j = await serper('places', q);
  return (j.places || []).map(p => ({ name: p.title || '', phone: p.phoneNumber || null, website: p.website || null, address: p.address || null,
    mapsUri: p.cid ? `https://www.google.com/maps?cid=${p.cid}` : null, placeId: p.placeId || p.cid || null }));
}
// A budget for paid SerpApi calls in one run. SerpApi's free plan gives 100 searches (check the current limit on their site).
// A full hunt over the 23 priority institutions needs 115, so a run stops at the budget unless SERPAPI_BUDGET is set.
let serpUsed = 0;
export const serpBudget = () => Number(process.env.SERPAPI_BUDGET) || 100;
export const serpSpent = () => serpUsed;
function spend() {
  if (serpUsed >= serpBudget()) throw new Error(`SerpApi budget reached: ${serpBudget()} searches in this run (set SERPAPI_BUDGET to allow more)`);
  serpUsed++;
}
/** The searches a hunt would spend, counted with no network call. Run it before any paid hunt. */
export function huntPlan(insts) {
  const searchOn = !!searchApiKey() || !!BRAVE() || !!SERPER() || !!SERP();
  const mapsOn = !!searchApiKey() || !!PLACES() || !!SERPER() || !!SERP();
  const perInst = QUERIES({ name: { en: 'x', ar: 'x' } }).length;
  const serpSearch = !searchApiKey() && !BRAVE() && !SERPER() && !!SERP();
  const serpMapsOn = !searchApiKey() && !PLACES() && !SERPER() && !!SERP();
  const serpCalls = insts.length * ((serpSearch ? perInst : 0) + (serpMapsOn ? 1 : 0));
  return { institutions: insts.length, search: searchOn ? (searchApiKey() ? 'SearchApi' : BRAVE() ? 'Brave' : SERPER() ? 'Serper' : 'SerpApi') : 'off',
    maps: mapsOn ? (searchApiKey() ? 'SearchApi' : PLACES() ? 'Google Places' : SERPER() ? 'Serper' : 'SerpApi') : 'off', serpApiSearches: serpCalls, budget: serpBudget(), fitsBudget: serpCalls <= serpBudget(), perHourAtGuaranteedRate: 50, hoursAtThatRate: Math.ceil(serpCalls / 50) };
}

/** Google results through SerpApi: organic results AND the paid ads scammers buy for "<bank> customer care". */
export async function serpGoogle(q) {
  if (!SERP()) return null;
  spend();
  const r = await fetch(`https://serpapi.com/search.json?engine=google&q=${encodeURIComponent(q)}&gl=ae&hl=en&num=20&api_key=${encodeURIComponent(SERP())}`, { signal: AbortSignal.timeout(20000) });
  if (!r.ok) throw new Error(`SerpApi HTTP ${r.status}`);
  const j = await r.json();
  const ads = [...(j.ads || []), ...(j.top_ads || []), ...(j.bottom_ads || [])].map((x, i) => ({ rank: i + 1, ad: true, title: x.title || '', url: x.link || x.tracking_link || '', description: x.description || x.snippet || '' }));
  const organic = (j.organic_results || []).map(x => ({ rank: x.position, ad: false, title: x.title || '', url: x.link || '', description: x.snippet || '' }));
  return [...ads, ...organic];
}
/** Google Maps listings through SerpApi (name, phone, website, address). */
export async function serpMaps(q) {
  if (!SERP()) return null;
  spend();
  const r = await fetch(`https://serpapi.com/search.json?engine=google_maps&type=search&q=${encodeURIComponent(q)}&ll=${encodeURIComponent('@24.4539,54.3773,9z')}&hl=en&api_key=${encodeURIComponent(SERP())}`, { signal: AbortSignal.timeout(20000) });
  if (!r.ok) throw new Error(`SerpApi Maps HTTP ${r.status}`);
  const j = await r.json();
  return (j.local_results || []).map(p => ({ name: p.title || '', phone: p.phone || null, website: p.website || null, address: p.address || null, mapsUri: p.place_id ? `https://www.google.com/maps/place/?q=place_id:${p.place_id}` : null, placeId: p.place_id || null }));
}
const NEUTRAL = new Set(NEUTRAL_DOMAINS || []);
const PHONE_RX = /(?<![\w+])(?:(?:\+|00)971[\s-]?)?600(?:[\s-]?\d){6}\b|(?:\+|00)971[\s-]?\d{1,2}[\s-]?\d{3}[\s-]?\d{3,4}|\b0(?:5\d|[2-4679])[\s-]?\d{3}[\s-]?\d{4}\b|\b800[\s-]?\d{3,7}\b/g;

export async function braveSearch(q, count = 20) {
  if (!BRAVE()) return null;
  const r = await fetch(`https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(q)}&count=${count}&safesearch=off`, {
    signal: AbortSignal.timeout(10000), headers: { accept: 'application/json', 'x-subscription-token': BRAVE() }
  });
  if (!r.ok) throw new Error(`Brave HTTP ${r.status}`);
  const j = await r.json();
  return (j.web?.results || []).map((x, i) => ({ rank: i + 1, title: x.title || '', url: x.url || '', description: (x.description || '').replace(/<[^>]+>/g, '') }));
}

export async function placesSearch(textQuery) {
  if (!PLACES()) return null;
  const r = await fetch('https://places.googleapis.com/v1/places:searchText', {
    method: 'POST', signal: AbortSignal.timeout(10000),
    headers: { 'content-type': 'application/json', 'x-goog-api-key': PLACES(),
      'x-goog-fieldmask': 'places.id,places.displayName,places.formattedAddress,places.nationalPhoneNumber,places.internationalPhoneNumber,places.websiteUri,places.googleMapsUri' },
    body: JSON.stringify({ textQuery, regionCode: 'AE', languageCode: 'en', pageSize: 20 })
  });
  if (!r.ok) throw new Error(`Places HTTP ${r.status}`);
  const j = await r.json();
  return (j.places || []).map(p => ({ name: p.displayName?.text || '', phone: p.internationalPhoneNumber || p.nationalPhoneNumber || null, website: p.websiteUri || null,
    address: p.formattedAddress || null, mapsUri: p.googleMapsUri || null, placeId: p.id }));
}

const QUERIES = inst => [`${inst.name.en} customer care number`, `${inst.name.en} login`, `${inst.name.en} refund`, `${inst.name.ar} رقم خدمة العملاء`];

/** Sentinel hook: suspects found in search results and map listings for these institutions. */
export const connectors = {
  async suspects(insts, say = () => {}) {
    const out = [];
    const on = connectorsConfigured();
    if (!on.search && !on.maps) { say('search & maps: no API keys set, skipped'); return out; }
    for (const inst of insts) {
      if (on.search) {
        for (const q of QUERIES(inst)) {
          let res = [];
          try { res = searchApiKey() ? await searchApiResults(q) : BRAVE() ? await braveSearch(q) : SERPER() ? await serperSearch(q) : await serpGoogle(q); } catch (e) { say(`search "${q}": ${e.message}`); continue; }
          for (const r of res) {
            let host;
            try { host = new URL(r.url).hostname.toLowerCase(); } catch { continue; }
            const reg = splitDomain(host).registrable;
            const blob = `${r.title} ${r.description}`;
            // a phone number shown in the result for this institution, which the institution does not publish
            for (const m of blob.match(PHONE_RX) || []) {
              if (guidePublisher({name:r.title, website:r.url, phone:m, text:r.description})) continue;
              const s = listingSuspect({ name: inst.name.en, phone: m }, { source: 'search', query: q });
              if (s && s.listing.verdict !== 'official') out.push({ ...s, how: `number in search result #${r.rank} for “${q}”`, resultUrl: r.url });
            }
            if (officialFor(reg) || NEUTRAL.has(reg)) continue;
            const a = analyzeUrl(r.url);
            const claims = findInstitutions(matchForm(blob), blob).some(c => c.inst.id === inst.id);
            if (a.lookalike || a.brand || (claims && /login|sign in|verify|refund|customer care|خدمة العملاء|تسجيل الدخول/i.test(blob))) {
              out.push({ host, inst: inst.id, how: `${r.ad ? 'PAID AD' : 'search result'} #${r.rank} for “${q}”`, sources: r.ad ? ['search', 'ad'] : ['search'], query: q });
            }
          }
        }
        say(`search: ${inst.name.en} done`);
      }
      if (on.maps) {
        const q = `${inst.name.en} customer service`;
        let places = [];
        try { places = searchApiKey() ? await searchApiMaps(q) : PLACES() ? await placesSearch(q) : SERPER() ? await serperPlaces(q) : await serpMaps(q); } catch (e) { say(`maps "${q}": ${e.message}`); }
        for (const p of places) { const s = listingSuspect(p, { source: 'maps', query: q }); if (s) out.push(s); }
        say(`maps: ${inst.name.en}, ${places.length} listings checked`);
      }
    }
    return out;
  }
};
