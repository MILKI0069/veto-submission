// Demo content. Links on *.localhost open Veto's built-in harmless demo pages (served by `npm start`),
// so the X-ray demo never touches real criminal infrastructure.
const port = typeof location !== 'undefined' && location.port ? `:${location.port}` : ':8787';

const DEMO_CONTACTS = 'Mum: +971 50 111 2233\nAhmed (son): 050 444 5566';

export const EXAMPLES = [
  { id: 'tamm_ar', label: { en: 'Arabic: fake TAMM fee with a link', ar: 'رسوم «تم» مزيفة مع رابط' }, channel: 'sms', sender: '+92 300 1234567',
    text: 'تم: لديك رسوم خدمة غير مدفوعة. لتجنب إيقاف الخدمة ادفع الآن عبر الرابط https://tamm-abudhabi-pay.top/ae' },
  { id: 'fab_otp_ar', label: { en: 'Arabic: “FAB” asks for your OTP', ar: '«بنك أبوظبي الأول» يطلب رمز التحقق' }, channel: 'sms', sender: 'FAB-Alert',
    text: 'عزيزي العميل، تم إيقاف بطاقتك في بنك أبوظبي الأول. لإعادة التفعيل أرسل رمز التحقق OTP الذي وصلك الآن.' },
  { id: 'police_fine', label: { en: 'Fake Dubai Police fine, UK number, short link', ar: 'مخالفة «شرطة دبي» مزيفة من رقم بريطاني ورابط مختصر' }, channel: 'sms', sender: '+44 7911 123456',
    text: 'Dubai Police: You have an unpaid traffic fine of AED 300. Pay within 24 hours to avoid legal action: https://cutt.ly/dxb-fine' },
  { id: 'himum', label: { en: '“Hi Mum” from a new number (contacts check)', ar: '«مرحبا ماما» من رقم جديد (فحص جهات الاتصال)' }, channel: 'whatsapp', sender: '+44 7700 900123',
    text: 'Hi Mum, this is my new number, my phone broke. Can you send me AED 2,000 urgently? Don’t tell dad.',
    context: { inContacts: false, firstContact: true, savedList: DEMO_CONTACTS } },
  { id: 'police_wa', label: { en: '“Dubai Police” on WhatsApp from +92', ar: '«شرطة دبي» على واتساب من +92' }, channel: 'whatsapp', sender: '+92 300 1234567',
    text: 'Dubai Police: a case has been registered against your Emirates ID. Contact the officer on this chat today to settle it.',
    context: { inContacts: false, firstContact: true, verifiedSender: false, app: 'whatsapp' } },
  { id: 'callcode', label: { en: 'A code arrives during a call with an unknown number', ar: 'يصل رمز أثناء مكالمة مع رقم مجهول' }, channel: 'sms', sender: 'ADCB',
    text: 'ADCB: 771204 is your one-time password to add a beneficiary in ADCB Hayyak. Never share it.',
    context: { onCallNumber: '+44 20 7946 0000' } },
  { id: 'trusted', label: { en: 'Trusted chat (the pet stays hidden)', ar: 'محادثة موثوقة (يبقى الحارس مخفياً)' }, channel: 'whatsapp', sender: '050 444 5566',
    text: 'See you at dinner tonight, I will bring dessert.',
    context: { inContacts: true, savedName: 'Ahmed (son)', priorMessages: 340, savedList: DEMO_CONTACTS } },
  { id: 'bankcall', label: { en: '“Bank” call asking for the code', ar: '«البنك» يطلب الرمز في مكالمة' }, channel: 'call', sender: '+971 4 609 1188',
    text: 'Hello, this is Emirates NBD fraud team. We blocked a suspicious payment of AED 4,800 on your card. To cancel it, please read me the 6 digit code you just received.' },
  { id: 'fine', label: { en: 'Fake traffic-fine SMS', ar: 'رسالة مخالفة مرورية مزيّفة' }, channel: 'sms', sender: '+971 52 445 9081',
    text: 'Abu Dhabi Police: You have an unpaid traffic fine of AED 350. Pay within 24 hours to avoid vehicle impoundment: adpolice-fines.com/pay' },
  { id: 'parcel', label: { en: 'Parcel fee (try X-ray)', ar: 'رسوم طرد (جرّب الأشعة)' }, channel: 'sms', sender: '+44 7911 123456',
    text: `Emirates Post: Your parcel is on hold due to an incomplete address. Pay the AED 5.89 redelivery fee within 24 hours: http://go-short.localhost${port}/go` },
  { id: 'apk', label: { en: '“Update your bank app” (try X-ray)', ar: '«حدّث تطبيق البنك» (جرّب الأشعة)' }, channel: 'whatsapp', sender: '+92 300 1234567',
    text: `Mashreq Security: your mobile banking will stop today. Install the new secure app from this link: http://bank-app-update.localhost${port}/` },
  { id: 'verify', label: { en: '“Verify your card” page (try X-ray)', ar: 'صفحة «تحقق من بطاقتك» (جرّب الأشعة)' }, channel: 'sms', sender: '+971 50 771 2290',
    text: `Dear customer, your card is temporarily suspended due to incomplete KYC. Verify now: http://secure-verify-uae.localhost${port}/` },
  { id: 'fab_ar', label: { en: 'Arabic: FAB card blocked', ar: 'بطاقة بنك أبوظبي الأول موقوفة' }, channel: 'sms', sender: '+971501234567',
    text: 'عميلنا العزيز، تم إيقاف بطاقتك من بنك أبوظبي الأول. يرجى تحديث بياناتك عبر الرابط: fab-update.info' },
  { id: 'homoglyph', label: { en: 'Look-alike letters in a link', ar: 'حروف متشابهة في رابط' }, channel: 'sms',
    text: 'ADCB: Your debit card is locked. Unlock it here: https://аdcb.com/unlock' },
  { id: 'uaepass', label: { en: 'UAE PASS approval scam', ar: 'احتيال الموافقة على UAE PASS' }, channel: 'call',
    text: 'Hello, I am calling from ICP about your Emirates ID renewal. You will get a UAE PASS request now, please approve it and tell me the code you receive.' },
  { id: 'wa', label: { en: '“I sent you my code by mistake”', ar: '«أرسلت لك رمزي بالخطأ»' }, channel: 'whatsapp', sender: '+44 7700 900123',
    text: 'Hi! I accidentally sent my WhatsApp verification code to your number. Can you please send it to me? It is urgent' },
  { id: 'job', label: { en: 'Paid “tasks” job', ar: 'وظيفة «مهام» مدفوعة' }, channel: 'whatsapp',
    text: 'Hello! We are hiring part-time staff. Earn AED 500-1500 per day by liking YouTube videos. No experience needed. Contact us on WhatsApp: wa.me/971501112233' },
  { id: 'otp', label: { en: 'Real OTP SMS (what does it unlock?)', ar: 'رسالة رمز حقيقية (ماذا يفتح؟)' }, channel: 'sms', sender: 'EmiratesNBD',
    text: 'Emirates NBD: 552910 is your code to add your card ending 4321 to Apple Pay. Do not share it with anyone.' },
  { id: 'aware', label: { en: 'Real police awareness SMS', ar: 'رسالة توعية حقيقية من الشرطة' }, channel: 'sms', sender: 'ADPolice',
    text: 'Abu Dhabi Police: Beware of fraudsters. Never share your bank details or OTP with anyone. Report suspicious calls to Aman 8002626.' }
];

export const CALL_SCRIPTS = {
  en: [
    ['caller', 'Good afternoon, this is Ahmed from the Emirates NBD fraud prevention department.'],
    ['you', 'Oh, hello.'],
    ['caller', 'We have detected a suspicious transaction of 4,800 dirhams on your card at an electronics store.'],
    ['you', 'I did not make any transaction!'],
    ['caller', 'Do not worry, we can stop it right now. Please do not hang up, this line is recorded for your security.'],
    ['caller', 'You will receive a six digit code by SMS. Please read me the code so I can cancel the transaction.'],
    ['caller', 'Also, for your safety, we will move your balance to a secure account until the investigation is finished.']
  ],
  ar: [
    ['caller', 'السلام عليكم، معك أحمد من قسم مكافحة الاحتيال في بنك الإمارات دبي الوطني.'],
    ['you', 'وعليكم السلام.'],
    ['caller', 'رصدنا عملية مشبوهة بقيمة 4800 درهم على بطاقتك في متجر إلكترونيات.'],
    ['you', 'أنا ما سويت أي عملية!'],
    ['caller', 'لا تقلق، نقدر نوقفها الحين. لا تغلق الخط، المكالمة مسجلة لحمايتك.'],
    ['caller', 'بيوصلك رمز التحقق برسالة، اقرأ لي الرمز عشان نلغي العملية.'],
    ['caller', 'وعشان سلامتك بنحول رصيدك لحساب آمن لين يخلص التحقيق.']
  ]
};
