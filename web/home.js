// The front door of the Veto web app: two ways in (resident, police) and a quick check that runs in the browser.
import { analyze } from '/engine/index.js';
import { h, ic, L, lang, setLang } from './ui.js';

const TX = {
  en: {
    tagline: 'The scam guard that reads the rulebook', langBtn: 'العربية',
    h1a: 'Veto warns you ', h1b: 'before you tap.',
    lead: 'Scammers can copy a logo, a sender name, even a voice. They cannot copy what a UAE bank, police force or government office has said it will never ask you to do.',
    resTitle: 'I am a resident', resText: 'Check a message, a link, a call or a map listing. Everything is checked on your device and nothing is uploaded.',
    res1: 'Paste an SMS, WhatsApp message or link and get a clear answer with the reason', res2: 'Put a suspicious call on speaker and Veto tells you when to hang up', res3: 'See the institution’s real number and how to report to Aman 800 2626',
    resGo: 'Open the checker',
    polTitle: 'Police and analysts', polText: 'See look-alike sites of UAE institutions before the first victim, with the evidence to take them down.',
    pol1: 'Hunts new domains and certificate logs for UAE look-alikes', pol2: 'X-rays each site in a sealed browser and links sites into campaigns', pol3: 'Evidence pack with SHA-256 manifest and STIX 2.1, signed off by an officer',
    polGo: 'Open the dashboard', polNote: 'Officer access code required',
    tryTitle: 'Try it now', tryHelp: 'Pick an example or paste your own message. The check runs in this page.', tryBtn: 'Check', tryPh: 'Paste a message or link…', full: 'See the full explanation',
    s1: 'Fake police fine', s2: 'TAMM fee (Arabic)', s3: 'Bank asks for OTP (Arabic)', s4: 'Real bank notice',
    f1: 'of scam links caught on 33,766 held-out links, at 0.59% false alarms', f2: 'official UAE government and bank pages wrongly flagged', f3: 'median from a new certificate being logged to Veto seeing it', f4: 'UAE institutions whose published rules Veto checks against',
    f2n: '0 of 2,231', f3n: '17 s',
    foot1: 'Built by team veto.ai for the ScamShield AI hackathon, Abu Dhabi Police × 42 Abu Dhabi.', foot2: 'Veto never says “100% safe”. When in doubt, call the institution on its published number.', foot3: 'Link judge for a whole list'
  },
  ar: {
    tagline: 'الحارس الذي يقرأ قواعد الجهات الرسمية', langBtn: 'English',
    h1a: 'فيتو يحذّرك ', h1b: 'قبل أن تضغط.',
    lead: 'يستطيع المحتال تقليد الشعار واسم المرسل وحتى الصوت. لكنه لا يستطيع تقليد ما أعلنت البنوك والشرطة والجهات الحكومية في الإمارات أنها لن تطلبه منك أبداً.',
    resTitle: 'أنا من السكان', resText: 'افحص رسالة أو رابطاً أو مكالمة أو إدراجاً على الخريطة. الفحص يتم على جهازك ولا يُرفع أي شيء.',
    res1: 'الصق رسالة نصية أو واتساب أو رابطاً واحصل على جواب واضح مع السبب', res2: 'ضع المكالمة المشبوهة على مكبر الصوت وسيخبرك فيتو متى تغلق الخط', res3: 'اعرف الرقم الحقيقي للجهة وطريقة الإبلاغ عبر أمان 8002626',
    resGo: 'افتح الفاحص',
    polTitle: 'الشرطة والمحللون', polText: 'اكتشف المواقع المقلِّدة للجهات الإماراتية قبل أول ضحية، مع الأدلة اللازمة لإزالتها.',
    pol1: 'يرصد النطاقات الجديدة وسجلات الشهادات بحثاً عن أسماء مشابهة', pol2: 'يفحص كل موقع في متصفح معزول ويربط المواقع في حملات', pol3: 'ملف أدلة مع بصمات SHA-256 وصيغة STIX 2.1 يعتمده ضابط',
    polGo: 'افتح لوحة التحكم', polNote: 'يتطلب رمز دخول الضابط',
    tryTitle: 'جرّب الآن', tryHelp: 'اختر مثالاً أو الصق رسالتك. الفحص يتم داخل هذه الصفحة.', tryBtn: 'افحص', tryPh: 'الصق رسالة أو رابطاً…', full: 'اعرض الشرح الكامل',
    s1: 'مخالفة شرطة مزيفة', s2: 'رسوم «تم» (بالعربية)', s3: 'بنك يطلب رمز التحقق', s4: 'إشعار بنكي حقيقي',
    f1: 'من روابط الاحتيال كُشفت في 33,766 رابطاً لم يرها النموذج، مع 0.59% إنذارات خاطئة', f2: 'صفحة حكومية وبنكية رسمية صُنّفت خطأً', f3: 'الوسيط بين تسجيل شهادة جديدة ورصد فيتو لها', f4: 'جهة إماراتية يطابق فيتو قواعدها المعلنة',
    f2n: '0 من 2,231', f3n: '17 ث',
    foot1: 'من إعداد فريق veto.ai لهاكاثون ScamShield AI، شرطة أبوظبي × 42 أبوظبي.', foot2: 'فيتو لا يقول أبداً «آمن 100%». عند الشك اتصل بالجهة على رقمها المعلن.', foot3: 'فاحص الروابط لقائمة كاملة'
  }
};
const T = k => TX[lang.cur][k] ?? TX.en[k] ?? k;

const SAMPLES = [
  { k: 's1', sender: '+44 7911 123456', text: 'Dubai Police: You have an unpaid traffic fine of AED 300. Pay within 24 hours to avoid legal action: https://cutt.ly/dxb-fine' },
  { k: 's2', sender: '+92 300 1234567', text: 'تم: لديك رسوم خدمة غير مدفوعة. لتجنب إيقاف الخدمة ادفع الآن عبر الرابط https://tamm-abudhabi-pay.top/ae' },
  { k: 's3', sender: 'FAB-Alert', text: 'عزيزي العميل، تم إيقاف بطاقتك في بنك أبوظبي الأول. لإعادة التفعيل أرسل رمز التحقق OTP الذي وصلك الآن.' },
  { k: 's4', sender: 'EmiratesNBD', text: 'Your Emirates NBD statement is ready. View it in the app or at https://www.emiratesnbd.com' }
];
const S = { text: '', sender: '', report: null };

function quick() {
  const r = S.report;
  if (!r) return null;
  return h('div', { class: `quick ${r.verdict}`, role: 'status' },
    h('b', {}, L(r.headline)), h('span', {}, L(r.reason)),
    r.next?.length ? h('ul', {}, r.next.slice(0, 2).map(n => h('li', {}, L(n)))) : null,
    h('a', { href: '/resident#text=' + encodeURIComponent(S.text) }, T('full'), ' →'));
}
function run() {
  if (!S.text.trim()) return;
  S.report = analyze({ text: S.text, sender: S.sender, channel: 'sms' });
  render();
}
function render() {
  setLang(lang.cur);
  document.getElementById('tagline').textContent = T('tagline');
  document.getElementById('langBtn').textContent = T('langBtn');
  const li = t => h('li', {}, ic('circle-check'), h('span', {}, t));
  const input = h('textarea', { class: 'field', rows: 2, dir: 'auto', placeholder: T('tryPh'), 'aria-label': T('tryPh'), oninput: e => { S.text = e.target.value; S.sender = ''; } });
  input.value = S.text;
  document.getElementById('app').replaceChildren(
    h('section', { class: 'hero' },
      h('div', {}, h('h1', {}, T('h1a'), h('em', {}, T('h1b'))), h('p', {}, T('lead'))),
      h('img', { class: 'kiki', src: '/pet/idle.png', alt: '', width: 210, height: 210 })),
    h('section', { class: 'doors' },
      h('a', { class: 'door', href: '/resident' }, h('div', { class: 'badge' }, ic('shield-check')), h('h2', {}, T('resTitle')), h('p', {}, T('resText')),
        h('ul', {}, li(T('res1')), li(T('res2')), li(T('res3'))), h('span', { class: 'btn blue go' }, T('resGo'), ' →')),
      h('a', { class: 'door police', href: '/police' }, h('div', { class: 'badge' }, ic('radar')), h('h2', {}, T('polTitle')), h('p', {}, T('polText')),
        h('ul', {}, li(T('pol1')), li(T('pol2')), li(T('pol3'))), h('span', { class: 'btn go' }, T('polGo'), ' →'), h('span', { class: 'note' }, ic('lock'), T('polNote')))),
    h('section', { class: 'try' },
      h('h2', {}, ic('sparkles'), T('tryTitle')), h('p', { class: 'muted small', style: 'margin-top:4px' }, T('tryHelp')),
      h('div', { class: 'samples' }, SAMPLES.map(s => h('button', { class: 'btn sm', type: 'button', onclick: () => { S.text = s.text; S.sender = s.sender; run(); } }, T(s.k)))),
      h('div', { class: 'row' }, input, h('button', { class: 'btn primary', type: 'button', onclick: run }, ic('shield-check'), T('tryBtn'))),
      quick()),
    h('section', { class: 'facts' },
      h('div', { class: 'fact' }, h('b', {}, '94.5%'), h('span', {}, T('f1'))),
      h('div', { class: 'fact' }, h('b', {}, T('f2n')), h('span', {}, T('f2'))),
      h('div', { class: 'fact' }, h('b', {}, T('f3n')), h('span', {}, T('f3'))),
      h('div', { class: 'fact' }, h('b', {}, '77'), h('span', {}, T('f4')))));
  document.getElementById('foot').replaceChildren(h('span', {}, T('foot1')), h('span', {}, T('foot2')), h('a', { href: '/judge.html' }, T('foot3')));
}
document.getElementById('langBtn').addEventListener('click', () => { setLang(lang.cur === 'ar' ? 'en' : 'ar'); render(); });
render();
