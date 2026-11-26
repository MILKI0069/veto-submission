// Veto official ledger: does a business listing match what the institution itself publishes?
//
// Fake Google Maps listings and sponsored search results keep the real name ("Emirates NBD Customer Care")
// and swap in the criminal's phone number or website. Victims call it and are "helped" into giving their card
// and OTP (Huang et al., "Detecting fake business listings", Google + UC San Diego, 2017; Abu Dhabi Police
// warnings about fake numbers in search and map results, 2026). Veto checks each field of a listing against
// the institution's published numbers and domains (data/institutions.js). Runs on the device; the server's
// Sentinel uses the same check for listings it pulls from search and maps.

import { INSTITUTIONS } from '../data/institutions.js';
import { findInstitutions } from './extract.js';
import { foldDigits, matchForm } from './normalize.js';
import { analyzeUrl } from './url.js';
import { sameNumber, exactShort, countryOf } from './context.js';

const sig = (id, w, en, ar) => ({ id, w, en, ar });
const isUaeMobile = n => /^(?:\+?971|00971|0)?5\d{8}$/.test(String(n || '').replace(/[\s()-]/g, ''));
const shown = inst => (inst.phones || []).map(p => p.d).join(', ');

function uaeLocalPhone(number) {
  return foldDigits(String(number || '')).replace(/[\s()-]/g, '').replace(/^(?:00971|\+971|971)/, '0');
}

export function historicalPhoneAlert(number) {
  if (uaeLocalPhone(number) === '0547596133') {
    return {
      ...sig('dfsa_historical_contact', 0.8,
        'DFSA reported that Sidra Capital impersonators used this number in a loan scam. Current ownership is unverified.',
        'أفادت سلطة دبي للخدمات المالية بأن منتحلي صفة سدرة المالية استخدموا هذا الرقم في عملية احتيال بالقروض. لم تُتحقق الملكية الحالية.'),
      source: { en: 'DFSA alert · 12 January 2026', ar: 'تنبيه سلطة دبي للخدمات المالية · ١٢ يناير ٢٠٢٦', url: 'https://www.dfsa.ae/alerts/dfsa-licensed-firm-impersonated-scam-1' }
    };
  }
  return null;
}

// Scope reviewed guides to the article, its advertised contact and its title.
// A bank-support claim, a look-alike URL or a different phone remains subject to the usual checks.
export function guidePublisher(listing) {
  const title = String(listing.name || '').trim();
  if (!/^Wio Bank Business Account UAE(?:\s*\|\s*EmirHub)?$/i.test(title)) return null;
  if (!sameNumber(listing.phone, '+971 50 496 3962') || listing.whatsapp) return null;
  if (/customer (?:care|support|service)|helpline|official support|خدمة العملاء|الدعم الرسمي/i.test(listing.text || '')) return null;
  const address = String(listing.website || '').trim();
  if (!/^(?:https:\/\/)?(?:www\.)?emirhub\.ae\/banking\/wio\/?$/i.test(address)) return null;
  return {
    en: 'EmirHub publishes this number for its account-opening consultancy. Contact Wio directly for bank support.',
    ar: 'تنشر إمير هب هذا الرقم لاستشارات فتح الحسابات. تواصل مع بنك ويو مباشرةً للحصول على الدعم المصرفي.',
    source: { en: 'EmirHub contact details', ar: 'بيانات التواصل مع إمير هب', url: 'https://www.emirhub.ae/contact-us/' }
  };
}

/** Which institution publishes this number (or null). */
export function numberOwner(number) {
  return INSTITUTIONS.find(i => (i.phones || []).some(p => sameNumber(p.n, number) || exactShort(p.n, number))) || null;
}

/**
 * @param {{name?:string, phone?:string, website?:string, whatsapp?:string, text?:string}} listing
 * @returns {{inst, verdict:'official'|'fake'|'suspicious'|'unknown'|'guide', signals, positives, official}}
 */
export function checkListing(listing = {}) {
  const name = String(listing.name || '').trim();
  const text = `${name} ${listing.text || ''}`.trim();
  const signals = [], positives = [];
  const publisher = guidePublisher(listing);
  if (publisher) return { inst: null, verdict: 'guide', risk: 0, signals, positives: [publisher], official: null };
  const historical = historicalPhoneAlert(listing.phone);
  if (historical) signals.push(historical);
  // who does the listing CLAIM to be? its name first, else what its website or number belongs to
  let inst = text ? (findInstitutions(matchForm(text), text).find(c => !c.inst.generic) || {}).inst || null : null;
  const site = listing.website ? analyzeUrl(listing.website) : null;
  const owner = listing.phone ? numberOwner(listing.phone) : null;
  if (!inst && site?.official) inst = INSTITUTIONS.find(i => i.id === site.official.id) || null;
  if (!inst && (site?.lookalike?.inst || site?.brand?.inst)) inst = site.lookalike?.inst || site.brand?.inst;

  // The ministry published the displayed digits only, without a country code.
  if (inst?.id === 'moi' && foldDigits(String(listing.phone || '')).replace(/[\s()-]/g, '') === '70614213') {
    signals.push({
      ...sig('moi_reported_caller', 0.8,
        'The UAE Ministry of Interior warned about impersonation calls displaying these digits. Current ownership is unverified.',
        'حذرت وزارة الداخلية الإماراتية من مكالمات انتحال الصفة التي يظهر فيها هذا الرقم. لم يتم التحقق من ملكيته الحالية.'),
      source: { en: 'UAE Ministry of Interior · 1 March 2026', ar: 'وزارة الداخلية الإماراتية · ١ مارس ٢٠٢٦', url: 'https://x.com/moiuae/status/2028040738475483569' }
    });
  }

  if (listing.phone) {
    if (inst && owner && owner.id === inst.id) positives.push({ id: 'phone_official', en: `${listing.phone} is ${inst.name.en}'s published number.`, ar: `${listing.phone} هو الرقم المعلن لـ${inst.name.ar}.` });
    else if (inst && inst.phones?.length && !signals.some(s => s.source)) {
      const mobile = isUaeMobile(listing.phone);
      const c = countryOf(listing.phone);
      const foreign = c && c.code !== 'AE' && c.code !== '??';
      // a landline that is not the published number may still be a real branch line, so it only warns
      signals.push(sig('listing_phone', mobile || foreign ? 0.9 : 0.45,
        `The listing says “${inst.name.en}”, but ${listing.phone} is not a number ${inst.name.en} publishes (theirs: ${shown(inst)}).${!mobile && !foreign ? ' It may be a branch line: to be safe, call the published number instead.' : ''}${mobile ? ' Banks and government offices do not run customer service from a personal mobile number.' : ''}${foreign ? ` It is a number from ${c.name.en}.` : ''}`,
        `الإدراج يقول «${inst.name.ar}»، لكن ${listing.phone} ليس رقماً تعلنه هذه الجهة (أرقامها: ${shown(inst)}).${!mobile && !foreign ? ' قد يكون خط فرع: للأمان اتصل بالرقم المعلن.' : ''}${mobile ? ' البنوك والجهات الحكومية لا تقدّم خدمة العملاء من رقم هاتف متحرك شخصي.' : ''}${foreign ? ` إنه رقم من ${c.name.ar}.` : ''}`));
    } else if (inst && owner && owner.id !== inst.id) {
      signals.push(sig('listing_phone_other', 0.6, `The listing says “${inst.name.en}” but the number belongs to ${owner.name.en}.`, `الإدراج يقول «${inst.name.ar}» لكن الرقم يخص ${owner.name.ar}.`));
    }
  }
  if (uaeLocalPhone(listing.phone) === '043161700' && (!inst || inst.id === 'nbk')) {
    positives.push({ id: 'nbk_published_contact', en: 'NBK publishes this UAE number and warns that callers can spoof it. Dial it independently to reach the bank.', ar: 'ينشر بنك الكويت الوطني هذا الرقم في الإمارات ويحذر من انتحال هوية المتصل. اتصل بالرقم بنفسك للتواصل مع البنك.',
      source: { en: 'NBK UAE · Banking awareness', ar: 'بنك الكويت الوطني · التوعية المصرفية', url: 'https://nbk.com/uae/services-and-support/banking-awareness/faqs.html' } });
  }
  if (site) {
    if (site.official && (!inst || site.official.id === inst.id)) positives.push({ id: 'site_official', en: `${site.host} is an official ${site.official.name.en} website.`, ar: `${site.host} موقع رسمي لـ${site.official.name.ar}.` });
    else if (inst) {
      const top = [...site.signals].sort((a, b) => b.w - a.w)[0];
      signals.push(sig('listing_site', site.lookalike ? 0.92 : 0.8,
        `The listing says “${inst.name.en}”, but its website ${site.hostUnicode || site.host} is not an official ${inst.name.en} site (${inst.domains.join(', ')}).${top ? ' ' + top.en : ''}`,
        `الإدراج يقول «${inst.name.ar}»، لكن موقعه ${site.hostUnicode || site.host} ليس موقعاً رسمياً (${inst.domains.join('، ')}).${top ? ' ' + top.ar : ''}`));
    } else if (site.risk >= 0.5) {
      const top = [...site.signals].sort((a, b) => b.w - a.w)[0];
      signals.push(sig('listing_site_risky', Math.min(0.8, site.risk), `The listing's website looks unsafe: ${top?.en || ''}`, `موقع الإدراج يبدو غير آمن: ${top?.ar || ''}`));
    }
  }
  if (listing.whatsapp || /wa\.me|whatsapp/i.test(listing.website || '')) {
    if (inst) signals.push(sig('listing_whatsapp', 0.7, `“${inst.name.en}” customer service on a WhatsApp number from a listing: banks list their official channels on their own website, check there.`,
      `خدمة عملاء «${inst.name.ar}» على رقم واتساب من إدراج: البنوك تعلن قنواتها الرسمية على موقعها، تحقق من هناك.`));
  }
  const risk = 1 - signals.reduce((p, s) => p * (1 - s.w), 1);
  const verdict = risk >= 0.85 ? 'fake' : signals.length ? 'suspicious' : positives.length ? 'official' : 'unknown';
  return {
    inst: inst ? { id: inst.id, name: inst.name, type: inst.type } : null, verdict, risk: +risk.toFixed(3), signals, positives,
    official: inst ? { phones: (inst.phones || []).map(p => ({ display: p.d, verified: p.v })), domains: inst.domains } : null
  };
}

/**
 * Before an OUTGOING call (Android CallRedirectionService): is the user about to call a number a scam gave them?
 * Fake "customer care" numbers from listings and messages are where victims are talked into giving codes.
 * @param {string} number
 * @param {{contactName?:string, flagged?:Array<{number,inst,why}>, reported?:string[]}} ctx
 * @returns {{verdict:'official'|'ok'|'intercept', inst, reasons, official}}
 */
export function outgoingCheck(number, { contactName = '', flagged = [], reported = [] } = {}) {
  const owner = numberOwner(number);
  if (owner) return { verdict: 'official', inst: { id: owner.id, name: owner.name }, reasons: [], official: null };
  const reasons = [];
  let inst = null;
  // 1. saved under an institution's name, but not that institution's number (scammers ask victims to save "Bank Security")
  if (contactName) {
    const c = findInstitutions(matchForm(contactName), contactName).find(x => !x.inst.generic);
    if (c && c.inst.phones?.length) {
      inst = c.inst;
      reasons.push(sig('contact_name', 0.85, `You saved this number as “${contactName}”, but ${inst.name.en} does not publish it (theirs: ${shown(inst)}).`,
        `حفظت هذا الرقم باسم «${contactName}»، لكن ${inst.name.ar} لا تعلنه (أرقامها: ${shown(inst)}).`));
    }
  }
  // 2. Veto saw this number in a scam message or a fake listing
  const f = (flagged || []).find(x => x && sameNumber(x.number, number));
  if (f) {
    inst = inst || INSTITUTIONS.find(i => i.id === f.inst) || null;
    reasons.push(sig('flagged', 0.9, `Veto flagged this number ${f.why ? `(${f.why})` : 'in a scam message'}.`, `سبق أن نبّه فيتو إلى هذا الرقم ${f.whyAr ? `(${f.whyAr})` : 'في رسالة احتيال'}.`));
  }
  // 3. the user reported it
  if ((reported || []).some(r => sameNumber(r, number))) reasons.push(sig('reported', 0.9, 'You reported this number to Veto before.', 'سبق أن أبلغت فيتو عن هذا الرقم.'));
  if (!reasons.length) return { verdict: 'ok', inst: null, reasons, official: null };
  const p = inst?.phones?.[0];
  return { verdict: 'intercept', inst: inst ? { id: inst.id, name: inst.name } : null, reasons,
    official: p ? { number: p.n, display: p.d, name: inst.name } : null };
}

/** Contacts that claim to be an institution but hold a number it does not publish (on-device audit). */
export function contactsAudit(list = []) {
  const out = [];
  for (const c of list.slice(0, 5000)) {
    if (!c || !c.name || !c.number) continue;
    const r = outgoingCheck(c.number, { contactName: c.name });
    if (r.verdict === 'intercept') out.push({ name: c.name, number: c.number, inst: r.inst, reason: r.reasons[0], official: r.official });
  }
  return out;
}
