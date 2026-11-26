// Veto Institutional Rulebook (UAE), who the real institutions are, where they live online,
// and what they have publicly said they will NEVER ask you to do.
//
// Every "never" rule is backed by public sources (RULE_SOURCES). Institution-specific quotes
// are added by `npm run ingest` (tools/ingest-policy.js) into data/evidence.js, straight from
// each institution's own security page, so every alert can cite the institution's own words.
//
// phones[].v = true  -> number confirmed on an official/public source during research
// phones[].v = false -> believed correct, re-check before production (UI also says "or the
//                       number on the back of your card").

export const KB_VERSION = '2026.11.20';

// What each kind of institution never asks for.
const MONEY_SECRETS = ['share_otp', 'share_pin', 'share_cvv', 'share_card', 'share_password', 'approve_app_prompt', 'approve_uaepass'];
const COERCION = ['install_remote', 'share_screen', 'transfer_safe_account', 'pay_giftcard', 'pay_crypto', 'install_apk'];
export const TYPE_NEVER = {
  bank: [...MONEY_SECRETS, ...COERCION, 'add_beneficiary', 'keep_secret'],
  regulator: [...MONEY_SECRETS, ...COERCION, 'add_beneficiary', 'keep_secret'],
  police: [...MONEY_SECRETS, ...COERCION, 'add_beneficiary', 'keep_secret'],
  gov: [...MONEY_SECRETS, ...COERCION, 'add_beneficiary', 'keep_secret'],
  telecom: [...MONEY_SECRETS, 'install_remote', 'share_screen', 'transfer_safe_account', 'pay_giftcard', 'pay_crypto', 'install_apk'],
  courier: [...MONEY_SECRETS, 'install_remote', 'share_screen', 'transfer_safe_account', 'pay_giftcard', 'pay_crypto', 'install_apk'],
  retail: [...MONEY_SECRETS, 'install_remote', 'share_screen', 'transfer_safe_account', 'pay_giftcard', 'pay_crypto', 'install_apk'],
  airline: [...MONEY_SECRETS, 'install_remote', 'share_screen', 'transfer_safe_account', 'pay_giftcard', 'pay_crypto', 'install_apk'],
  platform: ['share_otp', 'share_password', 'install_remote', 'share_screen', 'pay_giftcard', 'approve_uaepass']
};

// Rules that hold even when the message names nobody ("I sent you a code by mistake…").
export const UNIVERSAL_NEVER = ['share_otp', 'share_pin', 'share_cvv', 'share_password', 'approve_app_prompt', 'approve_uaepass', 'install_remote', 'transfer_safe_account', 'pay_giftcard'];

const SRC = {
  enbd_security: { title: 'Emirates NBD, Protect yourself against fraud', url: 'https://www.emiratesnbd.com/en/security' },
  enbd_uaf: { title: 'Emirates NBD, United Against Fraud', url: 'https://www.emiratesnbd.com/en/campaigns/united-against-fraud' },
  fab_tips: { title: 'FAB, Comprehensive security tips', url: 'https://www.bankfab.com/en-ae/about-fab/security-and-certifications/comprehensive-security-tips' },
  fab_fraud: { title: 'FAB, Fraud and security', url: 'https://www.bankfab.com/en-ae/personal/help-and-support/fraud-and-security' },
  adcb_fraud: { title: 'ADCB, Protecting your banking information', url: 'https://www.adcb.com/en/consumer-education-awareness/fraud-awareness/protecting-your-banking-information' },
  uaepass_tdra: { title: 'TDRA advisory on UAE PASS fraud attempts (Gulf News)', url: 'https://gulfnews.com/uae/uae-pass-security-alert-tdra-issues-advisory-amid-fraud-attempts-1.500459682' },
  uaepass_dxbpolice: { title: 'Dubai Police: fake calls seeking UAE PASS details (Gulf News)', url: 'https://gulfnews.com/uae/crime/dubai-police-caution-residents-against-fake-calls-seeking-uae-pass-details-1.500460239' },
  remote_adpolice: { title: 'Abu Dhabi Police warn against remote-control app scams (Gulf Today, 10 Apr 2026)', url: 'https://www.gulftoday.ae/news/2026/04/10/abu-dhabi-police-warn-against-remote-control-app-scams' },
  consumer_sites: { title: 'Dubai Police: fake consumer-protection sites push remote-control apps (Khaleej Times)', url: 'https://www.khaleejtimes.com/uae/dubai-police-fake-consumer-protection-links-banking-scam-warning' },
  cbuae_otp: { title: 'UAE banks move OTPs from SMS/email into apps (CBUAE notice 3057, Gulf News)', url: 'https://gulfnews.com/business/banking/new-rule-uae-banks-to-stop-sending-otps-via-sms-and-email-from-july-25-1.500209071' },
  delivery_fee: { title: 'Abu Dhabi Police: fake "Dh3 delivery" messages (Gulf News)', url: 'https://gulfnews.com/uae/crime/dh3-delivery-scam-abu-dhabi-police-alert-uae-residents-of-fake-messages-1.500272577' },
  fine_link: { title: 'Abu Dhabi Police: suspicious traffic-fine link (Gulf News)', url: 'https://gulfnews.com/uae/crime/scam-alert-abu-dhabi-police-warn-against-traffic-fine-suspicious-link-1.500243502' },
  cbuae_impersonation: { title: 'Abu Dhabi Police: scammers posing as the UAE Central Bank (Gulf News)', url: 'https://gulfnews.com/uae/be-wary-of-scammers-purporting-to-be-from-uae-central-bank-abu-dhabi-police-warns-1.80068299' },
  jobs: { title: 'Dubai Police warn against fake visa and job scams (Gulf News)', url: 'https://gulfnews.com/uae/crime/dubai-police-warn-public-against-fake-visa-and-job-scams-online-1.500612157' },
  search_links: { title: 'Abu Dhabi Police: fake links in search engines (Gulf News)', url: 'https://gulfnews.com/uae/crime/abu-dhabi-police-warn-public-about-fake-links-in-search-engines-1.500566188' },
  labour_fees: { title: 'UAE Labour Law Art. 6, employers may not charge workers recruitment costs (u.ae)', url: 'https://u.ae/en/information-and-services/jobs/employment-in-the-private-sector/labour-rights' }
};
export const SOURCES = SRC;

// Public sources behind each rule (shown as "Source" under an alert when no institution-specific
// quote is available).
export const RULE_SOURCES = {
  share_otp: [SRC.enbd_security, SRC.fab_tips, SRC.uaepass_dxbpolice],
  share_pin: [SRC.enbd_security, SRC.fab_tips],
  share_cvv: [SRC.fab_fraud, SRC.enbd_security],
  share_card: [SRC.fab_fraud, SRC.adcb_fraud],
  share_password: [SRC.enbd_security, SRC.fab_tips],
  approve_app_prompt: [SRC.cbuae_otp, SRC.enbd_uaf],
  approve_uaepass: [SRC.uaepass_tdra, SRC.uaepass_dxbpolice],
  install_remote: [SRC.remote_adpolice, SRC.consumer_sites],
  share_screen: [SRC.remote_adpolice],
  transfer_safe_account: [SRC.cbuae_impersonation],
  add_beneficiary: [SRC.enbd_uaf],
  pay_giftcard: [SRC.cbuae_impersonation],
  pay_crypto: [SRC.jobs],
  install_apk: [SRC.remote_adpolice],
  keep_secret: [SRC.cbuae_impersonation],
  pay_fee: [SRC.delivery_fee],
  click_update_link: [SRC.fine_link, SRC.search_links]
};

export const REPORTING = [
  { id: 'aman', name: { en: 'Abu Dhabi Police, Aman (toll-free, 24/7)', ar: 'شرطة أبوظبي، خدمة أمان (مجاني)' }, phone: '8002626', display: '800 2626', sms: '2828', email: 'aman@adpolice.gov.ae' },
  { id: 'dxb', name: { en: 'Dubai Police, eCrime platform / 901', ar: 'شرطة دبي، منصة الجرائم الإلكترونية / 901' }, phone: '901', display: '901', url: 'https://www.ecrime.ae' },
  { id: 'emergency', name: { en: 'Emergency (crime in progress)', ar: 'الطوارئ (جريمة جارية)' }, phone: '999', display: '999' }
];

// ---- helpers ----
const P = (n, d, v = false) => ({ n, d, v });
function I(id, type, en, ar, o = {}) {
  return {
    id, type, name: { en, ar },
    aliases: o.aliases || [],          // matched case-insensitively (EN) / normalised (AR)
    strict: o.strict || [],            // short acronyms matched case-sensitively as whole words
    ctxAliases: o.ctxAliases || [],    // ambiguous words that only count with context (e.g. "اتصالات")
    context: o.context || null,        // words that must also appear for strict/ctx aliases (e.g. "du")
    domains: o.domains || [],
    tokens: o.tokens || [],            // extra brand tokens for look-alike URL detection
    phones: o.phones || [],
    generic: !!o.generic
  };
}

export const INSTITUTIONS = [
  // ---------------- Banks ----------------
  I('enbd', 'bank', 'Emirates NBD', 'بنك الإمارات دبي الوطني', {
    aliases: ['emirates nbd', 'emiratesnbd', 'enbd', 'emirates national bank of dubai', 'الإمارات دبي الوطني', 'بنك الإمارات دبي'],
    domains: ['emiratesnbd.com'], tokens: ['emiratesnbd', 'enbd'], phones: [P('600540000', '600 54 0000', true), P('800100', '800 100', true)] // Priority Banking: https://www.emiratesnbd.com/en/priority-banking
  }),
  I('fab', 'bank', 'First Abu Dhabi Bank (FAB)', 'بنك أبوظبي الأول', {
    aliases: ['first abu dhabi bank', 'bankfab', 'fab bank', 'بنك أبوظبي الأول', 'بنك ابوظبي الاول'], strict: ['FAB'],
    domains: ['bankfab.com'], tokens: ['bankfab', 'fab'], phones: [P('600525500', '600 52 5500', true), P('97126811511', '+971 2 681 1511', true)] // FAB publishes both: https://www.bankfab.com/en-ae/personal/fab-first
  }),
  I('nbk', 'bank', 'National Bank of Kuwait', 'بنك الكويت الوطني', {
    aliases: ['national bank of kuwait', 'nbk', 'بنك الكويت الوطني'],
    domains: ['nbk.com'], tokens: ['nbk'], phones: [P('97143161700', '+971 4 316 1700', true)] // https://nbk.com/uae/services-and-support/banking-awareness/faqs.html
  }),
  I('adcb', 'bank', 'ADCB', 'بنك أبوظبي التجاري', {
    aliases: ['adcb', 'abu dhabi commercial bank', 'بنك أبوظبي التجاري', 'بنك ابوظبي التجاري'],
    domains: ['adcb.com'], tokens: ['adcb'], phones: [P('600502030', '600 50 2030', true), P('600502004', '600 50 2004', true)] // Contact centre and Excellency: https://www.adcb.com/en/get-in-touch/faqs/cards/adcb-debit-cards
  }),
  I('mashreq', 'bank', 'Mashreq', 'بنك المشرق', {
    aliases: ['mashreq', 'mashreqbank', 'mashreq neo', 'بنك المشرق'],
    domains: ['mashreq.com', 'mashreqbank.com'], tokens: ['mashreq'], phones: [P('044244444', '04 424 4444', true)]
  }),
  I('dib', 'bank', 'Dubai Islamic Bank', 'بنك دبي الإسلامي', {
    aliases: ['dubai islamic bank', 'بنك دبي الإسلامي'], strict: ['DIB'],
    domains: ['dib.ae'], tokens: ['dib', 'dubaiislamic'], phones: [P('046092222', '04 609 2222', true)]
  }),
  I('adib', 'bank', 'Abu Dhabi Islamic Bank (ADIB)', 'مصرف أبوظبي الإسلامي', {
    aliases: ['adib', 'abu dhabi islamic bank', 'مصرف أبوظبي الإسلامي', 'مصرف ابوظبي الاسلامي'],
    domains: ['adib.ae'], tokens: ['adib'], phones: [P('600543216', '600 543 216')]
  }),
  I('cbd', 'bank', 'Commercial Bank of Dubai', 'بنك دبي التجاري', {
    aliases: ['commercial bank of dubai', 'بنك دبي التجاري'], strict: ['CBD'],
    domains: ['cbd.ae'], tokens: ['cbd'], phones: [P('600575556', '600 575 556')]
  }),
  I('rakbank', 'bank', 'RAKBANK', 'بنك رأس الخيمة الوطني', {
    aliases: ['rakbank', 'rak bank', 'national bank of ras al khaimah', 'بنك رأس الخيمة', 'راك بنك'],
    domains: ['rakbank.ae'], tokens: ['rakbank'],
    phones: [
      P('042130000', '04 213 0000', true), // Phone banking: /en/islamic/personal/digital-banking/stay-safe/security-tips
      P('600544049', '600 544049', true), P('8004048', '800 4048', true), // General and Elite: https://www.rakbank.ae/ar/contact-us
      P('600576361', '600 576 361', true) // https://www.rakbank.ae/en/help-centre/debt-counseling/ask-us-anything
    ]
  }),
  I('ei', 'bank', 'Emirates Islamic', 'مصرف الإمارات الإسلامي', {
    aliases: ['emirates islamic', 'emiratesislamic', 'الإمارات الإسلامي'],
    domains: ['emiratesislamic.ae'], tokens: ['emiratesislamic'], phones: [P('600599995', '600 59 9995', true)]
  }),
  I('hsbc', 'bank', 'HSBC UAE', 'إتش إس بي سي', { aliases: ['hsbc'], domains: ['hsbc.ae'], tokens: ['hsbc'], phones: [P('600554722', '600 55 4722')] }),
  I('scb', 'bank', 'Standard Chartered UAE', 'ستاندرد تشارترد', { aliases: ['standard chartered', 'ستاندرد تشارترد'], domains: ['sc.com'], tokens: ['standardchartered'], phones: [P('600522288', '600 52 2288')] }),
  I('nbf', 'bank', 'National Bank of Fujairah', 'بنك الفجيرة الوطني', { aliases: ['national bank of fujairah', 'بنك الفجيرة الوطني'], strict: ['NBF'], domains: ['nbf.ae'], tokens: ['nbf'] }),
  I('sib', 'bank', 'Sharjah Islamic Bank', 'مصرف الشارقة الإسلامي', { aliases: ['sharjah islamic bank', 'مصرف الشارقة الإسلامي'], strict: ['SIB'], domains: ['sib.ae'], tokens: ['sib'] }),
  I('ajman', 'bank', 'Ajman Bank', 'مصرف عجمان', { aliases: ['ajman bank', 'مصرف عجمان'], domains: ['ajmanbank.ae'], tokens: ['ajmanbank'] }),
  I('cbi', 'bank', 'Commercial Bank International', 'البنك التجاري الدولي', { aliases: ['commercial bank international', 'البنك التجاري الدولي'], strict: ['CBI'], domains: ['cbiuae.com'], tokens: ['cbiuae'] }),
  I('uab', 'bank', 'United Arab Bank', 'البنك العربي المتحد', { aliases: ['united arab bank', 'البنك العربي المتحد'], strict: ['UAB'], domains: ['uab.ae'], tokens: ['uab'],
    phones: [P('800474', '800 474', true), P('97165987332', '+971 6 598 7332', true), P('97137052111', '+971 3 705 2111', true)] // UAB 2025 annual report, Contact Us: https://www.uab.ae/-/media/project/uab/pdf/2026/feb/uab-annual-report-2025enfinal-adx.pdf
  }),
  I('bos', 'bank', 'Bank of Sharjah', 'بنك الشارقة', { aliases: ['bank of sharjah', 'بنك الشارقة'], domains: ['bankofsharjah.com'], tokens: ['bankofsharjah'] }),
  I('alhilal', 'bank', 'Al Hilal Bank', 'مصرف الهلال', { aliases: ['al hilal bank', 'alhilal bank', 'مصرف الهلال'], domains: ['alhilalbank.ae'], tokens: ['alhilalbank', 'alhilal'] }),
  I('wio', 'bank', 'Wio Bank', 'ويو بنك', { aliases: ['wio bank', 'wio'], domains: ['wio.io'], tokens: ['wio'],
    phones: [P('600500946', '600 500 946', true)] // https://desk.wio.io/support/solutions/articles/501000417121-wio-security-fraud-protection-complete-customer-guide-faqs
  }),
  I('liv', 'bank', 'Liv (Emirates NBD)', 'ليف', { aliases: ['liv bank', 'liv by emirates nbd'], domains: ['liv.me'], tokens: ['livbank'] }),
  I('mbank', 'bank', 'Mbank (Al Maryah Community Bank)', 'إم بنك', { aliases: ['mbank', 'al maryah community bank'], domains: ['mbank.ae'], tokens: ['mbank'] }),
  I('zand', 'bank', 'Zand Bank', 'بنك زاند', { aliases: ['zand bank', 'زاند'], domains: ['zand.ae'], tokens: ['zand'] }),
  I('alansari', 'bank', 'Al Ansari Exchange', 'الأنصاري للصرافة', { aliases: ['al ansari exchange', 'alansari', 'الأنصاري للصرافة'], domains: ['alansariexchange.com'], tokens: ['alansari'] }),
  I('luluex', 'bank', 'LuLu Exchange', 'لولو للصرافة', { aliases: ['lulu exchange', 'luluexchange', 'لولو للصرافة'], domains: ['luluexchange.com'], tokens: ['luluexchange'] }),
  I('generic_bank', 'bank', 'a bank', 'بنك', {
    generic: true,
    aliases: ['your bank', 'the bank', 'bank officer', 'bank representative', 'bank security team', 'fraud department', 'fraud team', 'card security department',
      'calling from the bank', 'من البنك', 'موظف البنك', 'ادارة الاحتيال', 'قسم الاحتيال', 'mein bank se', 'main bank se', 'bank se bol']
  }),

  // ---------------- Regulators ----------------
  I('cbuae', 'regulator', 'Central Bank of the UAE', 'مصرف الإمارات العربية المتحدة المركزي', {
    aliases: ['central bank', 'cbuae', 'uae central bank', 'المصرف المركزي', 'البنك المركزي', 'مصرف الإمارات المركزي'],
    domains: ['centralbank.ae'], tokens: ['centralbank', 'cbuae'], phones: [P('80022823', '800 CBUAE (800 22823)')]
  }),
  I('dfsa', 'regulator', 'Dubai Financial Services Authority', 'سلطة دبي للخدمات المالية', { aliases: ['dubai financial services authority', 'سلطة دبي للخدمات المالية'], strict: ['DFSA'], domains: ['dfsa.ae'], tokens: ['dfsa'] }),
  I('adgm', 'regulator', 'ADGM / FSRA', 'سوق أبوظبي العالمي', { aliases: ['adgm', 'fsra', 'abu dhabi global market', 'سوق أبوظبي العالمي'], domains: ['adgm.com'], tokens: ['adgm'] }),
  I('sca', 'regulator', 'Securities and Commodities Authority', 'هيئة الأوراق المالية والسلع', { aliases: ['securities and commodities authority', 'هيئة الأوراق المالية والسلع'], strict: ['SCA'], domains: ['sca.gov.ae'], tokens: [] }),
  I('vara', 'regulator', 'Virtual Assets Regulatory Authority', 'سلطة تنظيم الأصول الافتراضية', { aliases: ['virtual assets regulatory authority', 'سلطة تنظيم الأصول الافتراضية'], strict: ['VARA'], domains: ['vara.ae'], tokens: ['vara'] }),
  I('sanadak', 'regulator', 'Sanadak (banking & insurance ombudsman)', 'سندك', { aliases: ['sanadak', 'سندك'], domains: ['sanadak.gov.ae'], tokens: ['sanadak'] }),

  // ---------------- Police & security ----------------
  I('adpolice', 'police', 'Abu Dhabi Police', 'شرطة أبوظبي', {
    aliases: ['abu dhabi police', 'ad police', 'adpolice', 'شرطة أبوظبي', 'شرطة ابوظبي', 'شرطه ابوظبي'],
    domains: ['adpolice.gov.ae'], tokens: ['adpolice', 'abudhabipolice'], phones: [P('8002626', '800 2626 (Aman)', true), P('2828', '2828 (SMS)', true), P('999', '999', true)]
  }),
  I('dxbpolice', 'police', 'Dubai Police', 'شرطة دبي', {
    aliases: ['dubai police', 'dubaipolice', 'شرطة دبي', 'شرطه دبي'],
    domains: ['dubaipolice.gov.ae', 'ecrime.ae', 'ecrimehub.gov.ae'], tokens: ['dubaipolice', 'ecrime'], phones: [P('901', '901', true), P('999', '999', true)]
  }),
  I('moi', 'police', 'Ministry of Interior', 'وزارة الداخلية', { aliases: ['ministry of interior', 'وزارة الداخلية'], strict: ['MOI', 'MoI'], domains: ['moi.gov.ae'], tokens: ['moi'], phones: [P('8005000', '800 5000', true)] }), // https://cdservices.moi.gov.ae/index/faq
  I('csc', 'gov', 'UAE Cyber Security Council', 'مجلس الأمن السيبراني', { aliases: ['cyber security council', 'cybersecurity council', 'مجلس الأمن السيبراني'], domains: ['csc.gov.ae'], tokens: [] }),
  I('generic_police', 'police', 'the police', 'الشرطة', {
    generic: true,
    aliases: ['police officer', 'police department', 'from the police', 'calling from police', 'criminal investigation', 'investigation department', 'cid officer', 'الشرطة', 'التحريات', 'البحث الجنائي', 'ضابط'],
    strict: ['CID']
  }),

  // ---------------- Government services ----------------
  I('icp', 'gov', 'ICP (Identity, Citizenship, Customs & Port Security)', 'الهيئة الاتحادية للهوية والجنسية والجمارك وأمن المنافذ', {
    aliases: ['federal authority for identity', 'identity and citizenship', 'الهيئة الاتحادية للهوية', 'الهوية والجنسية', 'هيئة الهوية'], strict: ['ICP'],
    domains: ['icp.gov.ae'], tokens: ['icp', 'emiratesid'], phones: [P('600522222', '600 52 2222')]
  }),
  I('gdrfa', 'gov', 'GDRFA Dubai (residency)', 'الإدارة العامة للإقامة وشؤون الأجانب', { aliases: ['gdrfa', 'general directorate of residency', 'الإقامة وشؤون الأجانب'], domains: ['gdrfad.gov.ae'], tokens: ['gdrfa', 'gdrfad'],
    phones: [P('8005111', '800 5111', true), P('97143139999', '+971 4 313 9999', true)] // https://gdrfad.gov.ae/en/contact-information
  }),
  I('uaepass', 'gov', 'UAE PASS', 'الهوية الرقمية (UAE PASS)', { aliases: ['uae pass', 'uaepass', 'الهوية الرقمية', 'يو اي اي باس'], domains: ['uaepass.ae'], tokens: ['uaepass'] }),
  I('tdra', 'gov', 'TDRA', 'هيئة تنظيم الاتصالات والحكومة الرقمية', { aliases: ['tdra', 'telecommunications and digital government regulatory authority', 'هيئة تنظيم الاتصالات'], domains: ['tdra.gov.ae'], tokens: ['tdra'] }),
  I('digitaldubai', 'gov', 'Digital Dubai', 'دبي الرقمية', { aliases: ['digital dubai', 'دبي الرقمية'], domains: ['digitaldubai.ae'], tokens: ['digitaldubai'] }),
  I('uaegov', 'gov', 'UAE Government portal (u.ae)', 'البوابة الرسمية لحكومة الإمارات', { aliases: ['uae government', 'حكومة الإمارات'], domains: ['u.ae'] }),
  I('tamm', 'gov', 'TAMM (Abu Dhabi Government)', 'تم', { aliases: ['tamm'], domains: ['tamm.abudhabi'], tokens: ['tamm'], phones: [P('800555', '800 555', true)] }), // https://www.added.gov.ae/en/contact-us
  I('rta', 'gov', 'RTA Dubai', 'هيئة الطرق والمواصلات', { aliases: ['roads and transport authority', 'هيئة الطرق والمواصلات'], strict: ['RTA'], domains: ['rta.ae'], tokens: ['rta'], phones: [P('8009090', '800 9090')] }),
  I('salik', 'gov', 'Salik', 'سالك', { aliases: ['salik', 'سالك'], domains: ['salik.ae'], tokens: ['salik'], phones: [P('80072545', '800 SALIK (72545)')] }),
  I('itc', 'gov', 'Abu Dhabi ITC / Darb', 'مركز النقل المتكامل / درب', { aliases: ['integrated transport centre', 'darb toll', 'مركز النقل المتكامل'], strict: ['ITC'], domains: ['itc.gov.ae'], tokens: ['darb'] }),
  I('mohre', 'gov', 'MOHRE (Human Resources & Emiratisation)', 'وزارة الموارد البشرية والتوطين', { aliases: ['mohre', 'ministry of human resources', 'وزارة الموارد البشرية'], domains: ['mohre.gov.ae'], tokens: ['mohre'], phones: [P('80084', '80084 (labour advice, toll-free)', true), P('600590000', '600 590000')] }),
  I('fta', 'gov', 'Federal Tax Authority', 'الهيئة الاتحادية للضرائب', { aliases: ['federal tax authority', 'الهيئة الاتحادية للضرائب'], strict: ['FTA'], domains: ['tax.gov.ae'], tokens: [] }),
  I('dewa', 'gov', 'DEWA', 'هيئة كهرباء ومياه دبي', { aliases: ['dewa', 'dubai electricity and water', 'هيئة كهرباء ومياه دبي', 'ديوا'], domains: ['dewa.gov.ae'], tokens: ['dewa'] }),
  I('sewa', 'gov', 'SEWA', 'هيئة كهرباء ومياه وغاز الشارقة', { aliases: ['sharjah electricity', 'هيئة كهرباء ومياه وغاز الشارقة'], strict: ['SEWA'], domains: ['sewa.gov.ae'], tokens: ['sewa'] }),
  I('etihadwe', 'gov', 'Etihad Water & Electricity', 'الاتحاد للماء والكهرباء', { aliases: ['etihad water', 'etihad we', 'الاتحاد للماء والكهرباء'], domains: ['etihadwe.ae'], tokens: ['etihadwe'] }),
  I('consumer', 'gov', 'Consumer Protection', 'حماية المستهلك', { aliases: ['consumer protection', 'consumer rights', 'حماية المستهلك'], domains: ['moec.gov.ae', 'consumerrights.ae'], tokens: ['consumerrights', 'consumerprotection'] }),
  I('courts', 'gov', 'UAE Courts / Judicial Department', 'المحاكم', { aliases: ['dubai courts', 'judicial department', 'محاكم دبي', 'دائرة القضاء'], domains: ['dc.gov.ae', 'adjd.gov.ae', 'moj.gov.ae'], tokens: ['adjd'] }),
  I('mohap', 'gov', 'Ministry of Health & Prevention / DHA', 'وزارة الصحة', { aliases: ['ministry of health', 'dubai health authority', 'وزارة الصحة', 'هيئة الصحة'], strict: ['DHA'], domains: ['mohap.gov.ae', 'dha.gov.ae'], tokens: ['mohap'] }),
  I('generic_gov', 'gov', 'a government entity', 'جهة حكومية', {
    generic: true,
    aliases: ['ministry', 'government department', 'immigration department', 'customs department', 'visa department', 'الوزارة', 'جهة حكومية', 'الجمارك', 'الهجرة', 'الجوازات']
  }),

  // ---------------- Telecom ----------------
  I('eand', 'telecom', 'e& (Etisalat)', 'اتصالات (e&)', {
    aliases: ['etisalat', 'e&', 'eand'], ctxAliases: ['اتصالات'],
    context: ['bill', 'recharge', 'points', 'data', 'package', 'sim', 'فاتورة', 'رصيد', 'نقاط', 'باقة', 'شريحة', 'سحب', 'جائزة', 'مبروك'],
    domains: ['etisalat.ae', 'eand.com'], tokens: ['etisalat', 'eand'], phones: [P('101', '101'), P('800101', '800 101')]
  }),
  I('du', 'telecom', 'du', 'دو', {
    aliases: ['du telecom', 'du mobile'], strict: ['du', 'DU'],
    context: ['bill', 'recharge', 'sim', 'line', 'points', 'data', 'package', 'mobile', 'telecom', 'credit', 'فاتورة', 'رصيد', 'شريحة', 'باقة', 'نقاط'],
    domains: ['du.ae'], tokens: ['du'], phones: [P('155', '155')]
  }),
  I('virgin', 'telecom', 'Virgin Mobile UAE', 'فيرجن موبايل', { aliases: ['virgin mobile'], domains: ['virginmobile.ae'], tokens: ['virginmobile'] }),

  // ---------------- Post & couriers ----------------
  I('emiratespost', 'courier', 'Emirates Post', 'بريد الإمارات', { aliases: ['emirates post', 'emiratespost', 'بريد الإمارات', 'بريد الامارات'], domains: ['emiratespost.ae'], tokens: ['emiratespost', 'empost'] }),
  I('aramex', 'courier', 'Aramex', 'أرامكس', { aliases: ['aramex', 'أرامكس', 'ارامكس'], domains: ['aramex.com'], tokens: ['aramex'] }),
  I('dhl', 'courier', 'DHL', 'دي إتش إل', { aliases: ['dhl'], domains: ['dhl.com'], tokens: ['dhl'] }),
  I('fedex', 'courier', 'FedEx', 'فيديكس', { aliases: ['fedex', 'فيديكس'], domains: ['fedex.com'], tokens: ['fedex'] }),
  I('ups', 'courier', 'UPS', 'يو بي إس', { strict: ['UPS'], domains: ['ups.com'], tokens: [] }),

  // ---------------- Retail & services ----------------
  I('amazon', 'retail', 'Amazon', 'أمازون', { aliases: ['amazon', 'أمازون', 'امازون'], domains: ['amazon.ae', 'amazon.com', 'a.co', 'amzn.to', 'amzn.eu'], tokens: ['amazon'] }),
  I('noon', 'retail', 'noon', 'نون', { aliases: ['noon.com'], strict: ['noon', 'Noon', 'NOON'], context: ['order', 'delivery', 'shop', 'sale', 'voucher', 'refund', 'parcel'], domains: ['noon.com'], tokens: ['noon'] }),
  I('carrefour', 'retail', 'Carrefour UAE', 'كارفور', { aliases: ['carrefour', 'كارفور'], domains: ['carrefouruae.com'], tokens: ['carrefour'] }),
  I('lulu', 'retail', 'LuLu Hypermarket', 'لولو هايبرماركت', { aliases: ['lulu hypermarket', 'لولو هايبر'], domains: ['luluhypermarket.com'], tokens: ['luluhypermarket'] }),
  I('talabat', 'retail', 'talabat', 'طلبات', { aliases: ['talabat'], domains: ['talabat.com'], tokens: ['talabat'] }),
  I('careem', 'retail', 'Careem', 'كريم', { aliases: ['careem'], domains: ['careem.com'], tokens: ['careem'] }),

  // ---------------- Airlines ----------------
  I('emirates', 'airline', 'Emirates (airline)', 'طيران الإمارات', { aliases: ['emirates airline', 'fly emirates', 'طيران الإمارات'], domains: ['emirates.com'], tokens: ['flyemirates', 'emiratesairline'] }),
  I('etihad', 'airline', 'Etihad Airways', 'طيران الاتحاد', { aliases: ['etihad airways', 'طيران الاتحاد'], domains: ['etihad.com'], tokens: ['etihadairways'] }),
  I('flydubai', 'airline', 'flydubai', 'فلاي دبي', { aliases: ['flydubai', 'fly dubai', 'فلاي دبي'], domains: ['flydubai.com'], tokens: ['flydubai'] }),
  I('airarabia', 'airline', 'Air Arabia', 'العربية للطيران', { aliases: ['air arabia', 'العربية للطيران'], domains: ['airarabia.com'], tokens: ['airarabia'] }),

  // ---------------- Platforms often impersonated ----------------
  I('whatsapp', 'platform', 'WhatsApp', 'واتساب', { aliases: ['whatsapp support', 'whatsapp team', 'فريق واتساب'], domains: ['whatsapp.com', 'whatsapp.net'], tokens: ['whatsapp'] }),
  I('microsoft', 'platform', 'Microsoft', 'مايكروسوفت', { aliases: ['microsoft support', 'windows support', 'مايكروسوفت'], domains: ['microsoft.com', 'live.com', 'outlook.com'], tokens: ['microsoft'] }),
  I('apple', 'platform', 'Apple', 'أبل', { aliases: ['apple support', 'icloud'], domains: ['apple.com', 'icloud.com'], tokens: ['icloud'] }),
  I('google', 'platform', 'Google', 'جوجل', { aliases: ['google support'], domains: ['google.com', 'google.ae'], tokens: [] }),
  // Global services widely used in the UAE and often impersonated here too
  I('paypal', 'platform', 'PayPal', 'باي بال', { aliases: ['paypal', 'باي بال'], domains: ['paypal.com', 'paypal.me'], tokens: ['paypal'] }),
  I('netflix', 'platform', 'Netflix', 'نتفليكس', { aliases: ['netflix', 'نتفليكس'], domains: ['netflix.com'], tokens: ['netflix'] }),
  I('binance', 'platform', 'Binance', 'بينانس', { aliases: ['binance', 'بينانس'], domains: ['binance.com'], tokens: ['binance'] })
];

// Domains that are fine to link to but prove nothing about who sent the message.
export const NEUTRAL_DOMAINS = ['instagram.com', 'facebook.com', 'x.com', 'twitter.com', 'youtube.com', 'youtu.be', 'linkedin.com', 'tiktok.com',
  'apps.apple.com', 'play.google.com', 'google.com', 'maps.google.com', 'goo.gl', 'wikipedia.org', 'khaleejtimes.com', 'gulfnews.com', 'thenationalnews.com', 'wam.ae'];
