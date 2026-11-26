// Phone-context reasoning, what the phone already KNOWS vs. What a message CLAIMS.
//
// WhatsApp (2025 to 26) shows facts about unknown senders: not a contact, another country, new account.
// Veto turns those facts into CONTRADICTIONS, on the device:
//   • "Hi Mum, new number"  vs  your saved "Mum" uses a different number   -> known-contact impersonation
//   • "This is Dubai Police" from a +44 WhatsApp                            -> identity / origin mismatch
//   • a stranger's FIRST message already asks for money, a code or a click  -> first-contact pressure
//   • on a call with an unknown number + a code arrives / bank app opens    -> coached scam in progress
// and it decides how much attention a chat deserves (trusted chats sleep, strangers get watched).
//
// The context object is filled automatically by the Android companion (contacts, chat history, call
// state, notification metadata). In the web demo it can be typed in. Nothing here leaves the device.

import { matchForm } from './normalize.js';
import { foldDigits } from './normalize.js';
import { INSTITUTIONS } from '../data/institutions.js';

// ---------- country of a phone number (E.164 prefix, longest match) ----------
const CC = [
  ['971', 'AE', 'UAE', 'الإمارات'], ['966', 'SA', 'Saudi Arabia', 'السعودية'], ['974', 'QA', 'Qatar', 'قطر'], ['965', 'KW', 'Kuwait', 'الكويت'],
  ['968', 'OM', 'Oman', 'عُمان'], ['973', 'BH', 'Bahrain', 'البحرين'], ['962', 'JO', 'Jordan', 'الأردن'], ['961', 'LB', 'Lebanon', 'لبنان'],
  ['20', 'EG', 'Egypt', 'مصر'], ['212', 'MA', 'Morocco', 'المغرب'], ['44', 'GB', 'the UK', 'بريطانيا'], ['1', 'US', 'the US/Canada', 'أمريكا/كندا'],
  ['91', 'IN', 'India', 'الهند'], ['92', 'PK', 'Pakistan', 'باكستان'], ['880', 'BD', 'Bangladesh', 'بنغلاديش'], ['94', 'LK', 'Sri Lanka', 'سريلانكا'],
  ['977', 'NP', 'Nepal', 'نيبال'], ['63', 'PH', 'the Philippines', 'الفلبين'], ['62', 'ID', 'Indonesia', 'إندونيسيا'], ['60', 'MY', 'Malaysia', 'ماليزيا'],
  ['66', 'TH', 'Thailand', 'تايلاند'], ['84', 'VN', 'Vietnam', 'فيتنام'], ['855', 'KH', 'Cambodia', 'كمبوديا'], ['95', 'MM', 'Myanmar', 'ميانمار'],
  ['856', 'LA', 'Laos', 'لاوس'], ['86', 'CN', 'China', 'الصين'], ['7', 'RU', 'Russia', 'روسيا'], ['90', 'TR', 'Türkiye', 'تركيا'], ['98', 'IR', 'Iran', 'إيران'],
  ['93', 'AF', 'Afghanistan', 'أفغانستان'], ['234', 'NG', 'Nigeria', 'نيجيريا'], ['233', 'GH', 'Ghana', 'غانا'], ['254', 'KE', 'Kenya', 'كينيا'],
  ['255', 'TZ', 'Tanzania', 'تنزانيا'], ['27', 'ZA', 'South Africa', 'جنوب أفريقيا'], ['49', 'DE', 'Germany', 'ألمانيا'], ['33', 'FR', 'France', 'فرنسا'],
  ['34', 'ES', 'Spain', 'إسبانيا'], ['39', 'IT', 'Italy', 'إيطاليا'], ['31', 'NL', 'the Netherlands', 'هولندا'], ['61', 'AU', 'Australia', 'أستراليا']
].sort((a, b) => b[0].length - a[0].length);

export function countryOf(number) {
  const raw = foldDigits(String(number || '')).trim();
  let d = raw.replace(/[^\d+]/g, '');
  if (!d) return null;
  if (d.startsWith('00')) d = '+' + d.slice(2);
  if (!d.startsWith('+')) {
    // local UAE formats: 05x…, 0[2-9]…, 800/600 numbers
    if (/^0[2-9]\d{7,8}$/.test(d) || /^(800|600)\d+/.test(d)) return { code: 'AE', name: { en: 'UAE', ar: 'الإمارات' }, local: true };
    return null;
  }
  const n = d.slice(1);
  const hit = CC.find(([p]) => n.startsWith(p));
  return hit ? { code: hit[1], name: { en: hit[2], ar: hit[3] }, prefix: '+' + hit[0] } : { code: '??', name: { en: 'another country', ar: 'دولة أخرى' }, prefix: '+' + n.slice(0, 3) };
}

export function maskNumber(number) {
  let d = String(number || '').replace(/[^\d+]/g, '');
  if (d.startsWith('00')) d = '+' + d.slice(2);
  if (d.length < 6) return d;
  const c = d.startsWith('+') ? countryOf(d) : null;
  return (c?.prefix || d.slice(0, 3)) + ' ••• ' + d.slice(-4);
}
export const sameNumber = (a, b) => {
  const n = x => {
    let d = foldDigits(String(x || '')).replace(/\D/g, '');
    if (/^\s*\+/.test(String(x)) || d.startsWith('00')) return d.replace(/^00/, '');
    if (/^5\d{8}$/.test(d)) return '971' + d;
    if (/^0\d{8,9}$/.test(d)) d = '971' + d.slice(1); // UAE local format
    if (/^(?:600|800)\d+$/.test(d)) d = '971' + d;
    return d;
  };
  const A = n(a), B = n(b);
  return A.length >= 7 && B.length >= 7 && A === B;
};

// ---------- an incoming call: what can we know BEFORE you answer? (offline) ----------
// Online reputation (IPQualityScore, opt-in) is added by the server / Android app on top of this.
// One-ring ("Wangiri") ranges: satellite / international networks and tiny Pacific numbering plans that
// UAE operators and press have named in call-back scams (The National: Nauru, Antarctica; others +27/+674).
const ONE_RING = [['870', 'Inmarsat satellite'], ['881', 'satellite phone'], ['882', 'international network'], ['883', 'international network'],
  ['672', 'Antarctica / Norfolk Island'], ['674', 'Nauru'], ['675', 'Papua New Guinea'], ['677', 'Solomon Islands'], ['678', 'Vanuatu'],
  ['682', 'Cook Islands'], ['683', 'Niue'], ['686', 'Kiribati'], ['688', 'Tuvalu'], ['690', 'Tokelau'], ['691', 'Micronesia'], ['692', 'Marshall Islands']];
const intlDigits = x => {
  let d = String(x || '').replace(/[^\d+]/g, '');
  if (d.startsWith('00')) d = '+' + d.slice(2);
  return d.startsWith('+') ? d.slice(1) : null;
};
export const exactShort = (a, b) => { const A = foldDigits(String(a || '')).replace(/\D/g, ''), B = foldDigits(String(b || '')).replace(/\D/g, ''); return A.length >= 3 && A === B; };

/**
 * @param {string} number            caller number as delivered by the phone (may be empty = hidden)
 * @param {object} o  { inContacts, savedName, reported: [numbers the user reported before], callCount }
 */
export function callerCheck(number, o = {}) {
  const signals = [], positives = [];
  const add = (id, w, en, ar) => signals.push({ id, w, en, ar });
  const digits = String(number || '').replace(/\D/g, '');
  const country = digits ? countryOf(number) : null;
  const intl = intlDigits(number);
  if (!digits) add('hidden', 0.35, 'Hidden number. It cannot be checked or called back. Banks and the police have no reason to hide their number.', 'رقم مخفي، لا يمكن فحصه أو معاودة الاتصال به. البنوك والشرطة لا تخفي أرقامها.');
  const ring = intl && ONE_RING.find(([p]) => intl.startsWith(p));
  if (ring) add('one_ring', 0.75, `+${ring[0]} (${ring[1]}) is a range used in “one-ring” scams. Don't call back. It can cost up to US$50 a minute.`, `+${ring[0]} (${ring[1]}) نطاق يُستخدم في احتيال «الرنّة الواحدة». لا تعاود الاتصال، قد يكلّف حتى 50 دولاراً للدقيقة.`);
  else if (country && country.code !== 'AE' && !o.inContacts) add('foreign', 0.25, `Unknown number from ${country.name.en}. Background check: not in your contacts or reports.`, `رقم مجهول من ${country.name.ar}. فحص في الخلفية: ليس في جهات اتصالك ولا في بلاغاتك.`);
  const official = INSTITUTIONS.find(i => (i.phones || []).some(p => sameNumber(p.n, number) || exactShort(p.n, number)));
  if (official) positives.push({ id: 'official_number', en: `This is ${official.name.en}'s published number, but caller ID can be faked. If they ask for a code, PIN or a transfer, hang up and call back yourself.`, ar: `هذا الرقم المعلن لـ${official.name.ar}، لكن يمكن تزوير هوية المتصل. إذا طلبوا رمزاً أو رقماً سرياً أو تحويلاً، أغلق واتصل بنفسك.`, inst: official.id });
  if ((o.reported || []).some(r => sameNumber(r, number))) add('reported_by_you', 0.9, 'You reported this number to Veto before.', 'سبق أن أبلغت فيتو عن هذا الرقم.');
  if (o.inContacts) positives.push({ id: 'contact', en: `Saved contact${o.savedName ? `: ${o.savedName}` : ''}.`, ar: `جهة اتصال محفوظة${o.savedName ? `: ${o.savedName}` : ''}.` });
  const risk = 1 - signals.reduce((p, s) => p * (1 - s.w), 1);
  return {
    number: digits ? maskNumber(number) : null, country, signals, positives, risk: +risk.toFixed(3),
    verdict: risk >= 0.7 ? 'danger' : risk >= 0.3 ? 'caution' : o.inContacts || official ? 'known' : 'unknown'
  };
}

// ---------- who the message says it is (family / a named person) ----------
const RELATIONS = {
  mother: /\b(?:mum|mom|mummy|mommy|mama|mother|mam|ammi|amma)\b|ماما|امي|يمه|يما|والدتي/,
  father: /\b(?:dad|daddy|papa|baba|father|abba|abbu)\b|بابا|يبه|ابوي|والدي/,
  son: /\b(?:son)\b|ابنك|ولدك/,
  daughter: /\b(?:daughter)\b|بنتك/,
  brother: /\b(?:bro|brother|bhai)\b|اخوك/,
  sister: /\b(?:sis|sister|didi)\b|اختك/,
  wife: /\b(?:wife)\b|زوجتك/,
  husband: /\b(?:husband|hubby)\b|زوجك/
};
// How a relation is usually SAVED in an address book
const SAVED_AS = {
  mother: /\b(?:mum|mom|mama|mother|ammi|amma|mummy|mommy)\b|ماما|امي|أمي|والدتي|يمه/i,
  father: /\b(?:dad|papa|baba|father|abba|abbu|daddy)\b|بابا|ابوي|أبوي|ابي|أبي|والدي/i,
  son: /\bson\b|ابني|ولدي/i, daughter: /\bdaughter\b|بنتي|ابنتي/i,
  brother: /\b(?:bro|brother)\b|اخي|أخي|اخوي/i, sister: /\b(?:sis|sister)\b|اختي|أختي/i,
  wife: /\bwife\b|زوجتي/i, husband: /\b(?:husband|hubby)\b|زوجي/i
};
const REL_TEXT = {
  mother: { en: 'mum', ar: 'أمك' }, father: { en: 'dad', ar: 'أبوك' }, son: { en: 'son', ar: 'ابنك' }, daughter: { en: 'daughter', ar: 'ابنتك' },
  brother: { en: 'brother', ar: 'أخوك' }, sister: { en: 'sister', ar: 'أختك' }, wife: { en: 'wife', ar: 'زوجتك' }, husband: { en: 'husband', ar: 'زوجك' }
};

export function claimedRelation(text) {
  const mt = matchForm(text);
  // greeting the reader as a relative ("Hi Mum") means the SENDER claims to be their child
  const greet = /^(?:\s*(?:hi|hello|hey|hii|salam|مرحبا|هلا|السلام عليكم))?[\s,!.]*(mum|mom|mummy|mommy|mama|ma|dad|daddy|papa|baba|ماما|بابا|يمه|يبه)(?=$|[\s,!.?،])/.exec(mt);
  if (greet) return { relation: 'child', via: greet[1] };
  const self = /\b(?:this is|it'?s|its|i'?m|i am)\s+(?:your\s+)?(son|daughter|brother|sister|bro|sis|wife|husband|mum|mom|dad|father|mother)\b/.exec(mt);
  if (self) {
    const w = self[1];
    const rel = Object.keys(RELATIONS).find(r => RELATIONS[r].test(w)) || (w === 'bro' ? 'brother' : w === 'sis' ? 'sister' : null);
    if (rel) return { relation: rel, via: w };
  }
  for (const [rel, re] of [['son', /انا ابنك|أنا ابنك|انا ولدك/], ['daughter', /انا بنتك/], ['brother', /انا اخوك/], ['sister', /انا اختك/]]) {
    if (re.test(mt)) return { relation: rel, via: rel };
  }
  return null;
}
export function claimedName(text) {
  const m = /\b(?:this is|it'?s|its|i'?m|i am)\s+([A-Z][a-z]{2,15})\b/.exec(String(text || ''));
  if (!m || /^(Your|The|Not|Just|Very|Really|Urgent|Important)$/.test(m[1])) return null;
  return m[1];
}

// ---------- attention: trusted chats sleep, strangers are watched ----------
const HOT = /\b(?:otp|code|pin|password|cvv|transfer|send (?:me )?money|aed|dhs?|usdt|crypto|gift ?card|https?:|www\.|link|bank|police|urgent|verify|install|anydesk|beneficiary)\b|\d{4,8}|رمز|كود|تحويل|درهم|رابط|بنك|شرطة|عاجل|حول/i;

export function triage(text, ctx = {}) {
  const country = ctx.country || countryOf(ctx.sender)?.code;
  const trusted = !!ctx.inContacts && ((ctx.priorMessages ?? 0) >= 20 || (ctx.contactAgeDays ?? 0) >= 90) && !ctx.accountNew;
  const stranger = ctx.inContacts === false || !!ctx.firstContact || !!ctx.accountNew || (!!country && country !== 'AE' && !ctx.inContacts);
  const hot = HOT.test(String(text || ''));
  if (trusted && !hot) return { mode: 'sleep', analyze: false, reason: { en: 'Trusted contact, nothing sensitive, the pet stays asleep.', ar: 'جهة موثوقة ولا شيء حساس، يبقى الحارس نائماً.' } };
  if (trusted) return { mode: 'light', analyze: true, reason: { en: 'Trusted contact, but this message mentions a code, money or a link.', ar: 'جهة موثوقة لكن الرسالة تذكر رمزاً أو مالاً أو رابطاً.' } };
  return { mode: 'watch', analyze: true, reason: stranger
    ? { en: 'New, unknown or foreign sender, watching closely.', ar: 'مرسل جديد أو مجهول أو من الخارج، مراقبة دقيقة.' }
    : { en: 'Contact with little chat history, watching.', ar: 'جهة بتاريخ محادثة قصير، مراقبة.' } };
}

// ---------- findings from context ----------
const f = (id, w, title, detail, key) => ({ id, w, title, detail, key: key || id });
const ASKS = ['share_otp', 'share_pin', 'share_cvv', 'share_card', 'share_password', 'share_eid', 'approve_app_prompt', 'approve_uaepass', 'install_remote',
  'share_screen', 'install_apk', 'click_update_link', 'pay_fee', 'transfer_safe_account', 'add_beneficiary', 'pay_giftcard', 'pay_crypto', 'send_money_urgent'];
const UAE_TYPES = ['bank', 'regulator', 'police', 'gov', 'telecom', 'courier'];

/**
 * @param {object} r     report from analyze() (claims, actions, links, otp …)
 * @param {object} ctx   { sender, inContacts, savedName, firstContact, priorMessages, contactAgeDays, accountNew,
 *                         verifiedSender, savedContacts:[{name, number}], onCall:{number,inContacts}, bankAppOpen, screenSharing }
 * @param {string} text  original message text
 */
export function contextFindings(r, ctx = {}, text = '') {
  const out = [], positives = [];
  if (!ctx || typeof ctx !== 'object') return { findings: out, positives };
  const country = ctx.sender ? countryOf(ctx.sender) : null;
  const claims = (r.claims || []).filter(c => !c.generic && UAE_TYPES.includes(c.type));
  const asks = (r.actions || []).filter(a => ASKS.includes(a));
  const unknown = ctx.inContacts === false || (!!ctx.sender && ctx.inContacts !== true && !ctx.savedName);

  // 1) Known-contact impersonation ("Hi Mum, new number")
  const rel = claimedRelation(text);
  const name = claimedName(text);
  if (unknown && (rel || name) && Array.isArray(ctx.savedContacts)) {
    let match = null;
    if (rel?.relation === 'child') match = ctx.savedContacts.find(c => ['son', 'daughter'].some(k => SAVED_AS[k].test(c.name)) || /\b(?:kid|child)\b|ولدي|بنتي/i.test(c.name));
    else if (rel) match = ctx.savedContacts.find(c => SAVED_AS[rel.relation]?.test(c.name));
    if (!match && name) match = ctx.savedContacts.find(c => new RegExp(`\\b${name}\\b`, 'i').test(c.name));
    if (match && !sameNumber(match.number, ctx.sender)) {
      const who = rel && rel.relation !== 'child' ? REL_TEXT[rel.relation] : null;
      out.push(f('contact_impersonation', 0.9,
        { en: `Claims to be ${who ? 'your ' + who.en : name || 'a family member'}, but your saved “${match.name}” uses a different number.`,
          ar: `يدّعي أنه ${who ? who.ar : name || 'أحد أفراد عائلتك'}، لكن «${match.name}» المحفوظ لديك يستخدم رقماً مختلفاً.` },
        { en: `This message comes from ${maskNumber(ctx.sender)}${country && country.code !== 'AE' ? ` (${country.name.en})` : ''}; “${match.name}” is saved as ${maskNumber(match.number)}. Call them on the saved number before you reply or send anything.`,
          ar: `الرسالة من ${maskNumber(ctx.sender)}${country && country.code !== 'AE' ? ` (${country.name.ar})` : ''}؛ و«${match.name}» محفوظ برقم ${maskNumber(match.number)}. اتصل به على الرقم المحفوظ قبل أن ترد أو ترسل أي شيء.` },
        'contact_impersonation'));
    }
  }

  // 2) Institution claimed from a foreign / personal origin
  if (claims.length && country && country.code !== 'AE' && !ctx.verifiedSender) {
    const c = claims[0];
    out.push(f('origin_mismatch', 0.8,
      { en: `Claims to be ${c.name.en} but writes from a ${country.name.en} number (${country.prefix || ''}).`, ar: `يدّعي أنه ${c.name.ar} لكنه يتواصل من رقم من ${country.name.ar} (${country.prefix || ''}).` },
      { en: `${c.name.en} contacts people from UAE numbers and registered sender names, never from a foreign mobile on WhatsApp or SMS.`,
        ar: `تتواصل ${c.name.ar} عبر أرقام إماراتية وأسماء مرسلين مسجّلة، وليس من جوال أجنبي عبر واتساب أو الرسائل.` },
      'sender'));
  } else if (claims.length && unknown && ctx.verifiedSender === false && /^(?:whatsapp|telegram)$/i.test(ctx.app || '')) {
    const c = claims[0];
    out.push(f('unverified_business', 0.55,
      { en: `Claims to be ${c.name.en} from an unverified personal ${ctx.app} account.`, ar: `يدّعي أنه ${c.name.ar} من حساب ${ctx.app} شخصي غير موثّق.` },
      { en: 'Official organisations use verified business accounts and their own apps.', ar: 'الجهات الرسمية تستخدم حسابات أعمال موثّقة وتطبيقاتها الخاصة.' }, 'unverified_business'));
  }

  // 3) A stranger's FIRST message already asks for something
  if ((ctx.firstContact || ctx.accountNew) && (asks.length || (r.links || []).some(l => !l.official))) {
    out.push(f('first_contact', ctx.accountNew ? 0.5 : 0.4,
      { en: `${ctx.accountNew ? 'A brand-new account' : 'Someone you have never chatted with'} is already asking you to act.`,
        ar: `${ctx.accountNew ? 'حساب جديد تماماً' : 'شخص لم تتحدث معه من قبل'} يطلب منك التصرّف منذ أول رسالة.` },
      { en: 'Genuine contacts and institutions rarely open with a request for money, a code or a click.', ar: 'نادراً ما تبدأ الجهات الحقيقية برسالة تطلب مالاً أو رمزاً أو ضغط رابط.' }, 'first_contact'));
  }

  // 4) Coached scam in progress, device context during a call (no call audio needed)
  const call = ctx.onCall;
  if (call && call.inContacts !== true) {
    const cc = countryOf(call.number);
    const from = `${call.number ? maskNumber(call.number) : 'an unknown number'}${cc && cc.code !== 'AE' ? ` (${cc.name.en})` : ''}`;
    const fromAr = `${call.number ? maskNumber(call.number) : 'رقم مجهول'}${cc && cc.code !== 'AE' ? ` (${cc.name.ar})` : ''}`;
    if (r.otp) out.push(f('call_context', 0.95,
      { en: `A code just arrived while you are on a call with ${from}. Hang up. This is how the money leaves.`, ar: `وصل رمز للتو وأنت في مكالمة مع ${fromAr}. أنهِ المكالمة، هكذا تُسرق الأموال.` },
      { en: `The code is for ${r.otp.unlocks.en}. No real caller ever needs it.`, ar: `الرمز مخصص لـ${r.otp.unlocks.ar}. لا يحتاجه أي متصل حقيقي.` }, 'call_context:otp'));
    if (ctx.bankAppOpen) out.push(f('call_context', 0.85,
      { en: `You opened a banking app during a call with ${from}.`, ar: `فتحت تطبيقاً بنكياً أثناء مكالمة مع ${fromAr}.` },
      { en: 'Scammers stay on the line and talk victims through the transfer. Hang up first, then decide.', ar: 'يبقى المحتالون على الخط ويرشدون الضحية خطوة بخطوة. أنهِ المكالمة أولاً ثم قرّر.' }, 'call_context:bank'));
    if (ctx.screenSharing) out.push(f('call_context', 0.9,
      { en: `Your screen is being shared during a call with ${from}.`, ar: `شاشتك مُشاركة أثناء مكالمة مع ${fromAr}.` },
      { en: 'Stop sharing: they can read your codes and balances.', ar: 'أوقف المشاركة: يمكنهم قراءة رموزك وأرصدتك.' }, 'call_context:screen'));
  }

  // 5) Trust from history (only ever lowers soft signals; finalize() ignores it if a critical finding exists)
  if (ctx.inContacts && ((ctx.priorMessages ?? 0) >= 20 || (ctx.contactAgeDays ?? 0) >= 90) && !ctx.accountNew) {
    positives.push({ en: `${ctx.savedName ? `“${ctx.savedName}”` : 'This contact'} is saved and you have a long chat history together.`,
      ar: `${ctx.savedName ? `«${ctx.savedName}»` : 'هذه الجهة'} محفوظة ولديكما تاريخ محادثة طويل.`, kind: 'history' });
  }
  return { findings: out, positives };
}
