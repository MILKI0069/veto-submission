// Veto police dashboard: early warning (hunts and suspects), the case file with evidence, campaigns, quick tools
// and the officer sign-off log. It talks only to this Veto server. On the server machine itself it is open; when
// hosted, an officer signs in with the access code first (server/console.js).
import { analyze } from '/engine/index.js';
import { EXAMPLES } from './examples.js';
import { checkListing } from '/engine/ledger.js';
import { h, ic, L, lang, setLang, store, fmtDate, fmtNum, toast } from './ui.js';

const TX = {
  en: {
    ads: "Sponsored search results",
    message: "Reported message",
    sender: "Sender",
    messageText: "Message text",
    analyzeMessage: "Analyze message",
    examples: "Training examples",
    riskScore: "Risk score",
    pilot: "Police pilot",
    pilotHelp: "Start with one institution and a supervised review queue. Measure false alarms, time to review and evidence completeness before expanding coverage. Hosted access uses a shared pilot code. Production rollout needs individual officer identities and a retention policy.",
    verification: "Open saved URL verification (20 URLs)",
    evidenceInventory: "Collected evidence",
    missing: "Not captured",
    brandSub: 'Police dashboard', langBtn: 'العربية', home: 'Front door', resident: 'Resident checker', signOut: 'Sign out', refresh: 'Refresh',
    nOverview: 'Overview', nHunt: 'Early warning', nCases: 'Cases', nCamps: 'Campaigns', nTools: 'Check', nAudit: 'Sign-off log',
    sOverview: 'What needs an officer today, and what the early-warning sources are seeing.',
    sHunt: 'Look-alike sites of UAE institutions, found before the scam messages go out.',
    sCases: 'Every site Veto has X-rayed, with its evidence. Nothing is sent until an officer signs off.',
    sCampaigns: 'Sites run by the same people, linked only by things criminals reuse.',
    sTools: 'Check one link, a whole list, or a search or Maps listing.',
    sAudit: 'Every officer decision, chained with SHA-256 so a changed entry shows.',
    live: 'Connected', sec: 's',
    kWatched: 'Sites watched', kLive: 'Live now', kCases: 'Cases with evidence', kDanger: 'Proven dangerous', kCamps: 'Campaigns', kWaiting: 'Waiting for sign-off',
    queue: 'Needs an officer', queueHelp: 'Dangerous sites that nobody has reviewed yet, worst first.', queueEmpty: 'Nothing is waiting. Every case has a decision.', review: 'Review',
    sources: 'Early-warning sources', srcLook: 'Look-alike names (DNS)', srcNrd: 'Newly registered domains', srcCt: 'Certificate logs', srcSearch: 'Search results and ads', srcMaps: 'Map listings',
    on: 'On', needsKey: 'Needs an API key', lastHunt: 'Last hunt', never: 'never', names: 'names', registered: 'registered', liveFound: 'live', goHunt: 'Open early warning',
    measured: 'Measured on a recorded run', measuredHelp: 'Certificate watch, 24 Nov 2026, 10 minutes, 50 public logs. Counts and times only. Alerts are judgements, not confirmed scams.',
    mCerts: 'certificates read', mRate: 'certificates per second', mMedian: 'median, log entry to Veto', mAlerts: 'look-alike alerts on UAE names',
    emptyTitle: 'The case file is empty', emptyText: 'Run a hunt to look for live look-alike sites of UAE banks and government services, or load the training cases to see the whole workflow on Veto’s own harmless demo scam pages.',
    runFirst: 'Run a hunt', loadTraining: 'Load training cases', loadingTraining: 'X-raying the demo pages…', trainingDone: 'Training cases added',
    trainingNote: 'Training cases are Veto’s own harmless demo pages on this server. They are marked “training” and are not real sites.',
    hunt: 'Run a hunt', huntHelp: 'Veto builds the look-alikes of each official domain, checks which are registered, reads the certificate logs and new-domain lists, visits what is live and X-rays the worst.',
    scope: 'Institutions', priority: 'Priority banks and government', allInst: 'All institutions', xrayTop: 'Then X-ray the top', liveOnes: 'live suspects', run: 'Run the hunt', running: 'Hunting…', phase: 'Phase', checked: 'names checked',
    suspects: 'Suspects', fLive: 'Live', fDormant: 'Dormant', fAll: 'All', searchPh: 'Search a site or institution…', noSuspects: 'No suspects yet. Run a hunt.', noMatch: 'Nothing matches.',
    cSite: 'Site', cImitates: 'Imitates', cFound: 'Found by', cStatus: 'Status', cThreat: 'Threat', cVerdict: 'Verdict', cEvidence: 'Evidence', cSeen: 'Last seen', cSignoff: 'Sign-off', cAction: '',
    xray: 'X-ray', openCase: 'Open case', armedNow: 'just switched on',
    st_live: 'live', st_no_web: 'no website yet', st_parked: 'parked', st_error_page: 'error page', st_redirects_official: 'sends to the official site', st_brand_owned: 'brand-owned', st_gone: 'gone',
    src_lookalike: 'look-alike', src_ct: 'certificate', src_nrd: 'new domain', src_search: 'search', src_maps: 'maps', src_manual: 'manual', src_xray: 'checked link', src_sentinel: 'hunt', src_training: 'training',
    v_dangerous: 'dangerous', v_suspicious: 'suspicious', v_clean: 'no threat seen', v_unreachable: 'unreachable', v_phishing: 'phishing', v_legitimate: 'legitimate',
    cfAll: 'All', cfWaiting: 'Waiting', followUp: 'Follow-up required', cfApproved: 'Approved', cfRejected: 'Rejected', noCases: 'No cases yet. X-ray a suspect or check a link.',
    r_pending: 'waiting', r_approved: 'approved', r_rejected: 'rejected', r_needs_info: 'needs information',
    ev_cloaked: 'cloaked', ev_logo: 'copied logo',
    noCamps: 'No campaigns yet. They appear when two X-rayed sites share criminal infrastructure.', graphHelp: 'Circles are scam sites: click one to open its case. Squares are what links them: TG the same Telegram bot, GA the same analytics ID, IP the same server, KIT the same phishing kit.',
    sites: 'sites', firstSeen: 'first seen', confidence: 'confidence',
    close: 'Close', dWants: 'What this page wants', dPicture: 'The page, as a phone sees it', dWhy: 'Why Veto flagged it', dAsks: 'Asks for', dSends: 'Sends what is typed to', dCloak: 'Cloaking', dCloakText: 'Shows its real face only to some visitors',
    dInfra: 'Registration and hosting', dRegistrar: 'Registrar', dCreated: 'Domain registered', dServer: 'Server', dAbuse: 'Abuse contacts', dChain: 'Redirect chain', dUrl: 'Final address', dTitle: 'Page title', dFirst: 'First seen', dSource: 'Found by',
    dCamp: 'Linked sites', dReports: 'Ready-to-send takedown requests', dReportsHelp: 'Drafts only. Veto never sends them. An officer reviews, signs off and sends.', rp_registrar: 'To the registrar', rp_host: 'To the hosting network', rp_telegram: 'To Telegram', copy: 'Copy', copied: 'Copied',
    dSign: 'Officer sign-off', dSignPending: 'Waiting for an officer. No takedown request may be sent from this case until it is approved.', officer: 'Officer name or badge', note: 'Note (optional)',
    approve: 'Approve for takedown', reject: 'Reject, no action', needInfo: 'Needs more information', signedBy: 'by', auditEntry: 'Log entry', changeDecision: 'Record a new decision', needName: 'Enter the officer name first.',
    dlZip: 'Evidence ZIP', dlPdf: 'PDF', dlStix: 'STIX 2.1', dlPack: 'Full takedown pack', needApprove: 'Sign off first',
    tXray: 'X-ray a link', tList: 'Judge a list', tListing: 'Check a listing',
    xrayHelp: 'The link opens in a sealed, throw-away browser on the server. Veto types fake details, watches where they go and adds the site to the case file.', xrayBtn: 'X-ray it', xraying: 'X-raying…', url: 'Link',
    listHelp: 'Paste links, one per line, or a CSV with a url column and an optional label column (1 or 0). Judged offline in about a millisecond each, up to 20,000.', listBtn: 'Judge the list', listPh: 'https://…\nhttps://…', csv: 'Download CSV', judged: 'links judged',
    precision: 'Precision', recall: 'Recall', falseAlarms: 'False alarms', cScore: 'Score', cReason: 'Main reason',
    listingHelp: 'Compare a search result, ad or Maps listing with what the institution itself publishes. Fake customer-care numbers are the usual trick.', lName: 'Listing name', lPhone: 'Phone number', lWeb: 'Website', listingBtn: 'Check the listing',
    lv_guide: 'Third-party guide', lv_fake: 'Fake listing', lv_suspicious: 'Suspicious listing', lv_official: 'Matches the official details', lv_unknown: 'Insufficient evidence to verify this listing', officialIs: 'Official',
    connOff: 'Live search and Maps sweeps are switched off on this server until an API key is added. The listing check below works without one.',
    chainOk: 'Log intact', chainBad: 'Log broken at entry', entries: 'entries', noAudit: 'No decisions recorded yet.', aTime: 'Time (UTC)', aDecision: 'Decision', aOfficer: 'Officer', aHash: 'SHA-256', aNote: 'Note',
    humanRule: 'Human in the loop: Veto collects and explains. It never sends a takedown request or blocks anything by itself.',
    gateTitle: 'Police dashboard', gateText: 'This area shows suspect sites and evidence. Enter the officer access code to continue.', code: 'Access code', enter: 'Sign in', wrong: 'That code is not right.', rate: 'Too many tries. Wait a minute.', down: 'The server is waking up. Try again in a minute.',
    notConfigured: 'The dashboard is not opened on this server yet: no access code has been set.', gatePilot: 'Pilot sign-in. A police deployment would use the force’s own single sign-on.', back: 'Back to the front door',
    loadErr: 'Could not reach the server.', error: 'Something went wrong.'
  },
  ar: {
    ads: "إعلانات نتائج البحث",
    message: "الرسالة المبلّغ عنها",
    sender: "المرسل",
    messageText: "نص الرسالة",
    analyzeMessage: "تحليل الرسالة",
    examples: "أمثلة تدريبية",
    riskScore: "درجة المخاطر",
    pilot: "التجربة الشرطية",
    pilotHelp: "تبدأ التجربة بجهة واحدة وقائمة مراجعة تحت إشراف ضابط. تُقاس الإنذارات الخاطئة ومدة المراجعة واكتمال الأدلة قبل توسيع التغطية. يُستخدم رمز مشترك في النسخة التجريبية، ويتطلب التشغيل الفعلي حسابات فردية للضباط وسياسة للاحتفاظ بالبيانات.",
    verification: "فتح نتائج التحقق المحفوظة لعشرين رابطاً",
    evidenceInventory: "الأدلة المجمّعة",
    missing: "لم يُجمع",
    brandSub: 'لوحة الشرطة', langBtn: 'English', home: 'الصفحة الرئيسية', resident: 'فاحص السكان', signOut: 'تسجيل الخروج', refresh: 'تحديث',
    nOverview: 'نظرة عامة', nHunt: 'الإنذار المبكر', nCases: 'القضايا', nCamps: 'الحملات', nTools: 'افحص', nAudit: 'سجل الاعتماد',
    sOverview: 'ما يحتاج إلى ضابط اليوم، وما ترصده مصادر الإنذار المبكر.',
    sHunt: 'مواقع تقلّد الجهات الإماراتية، تُكتشف قبل إرسال رسائل الاحتيال.',
    sCases: 'كل موقع فحصه فيتو بالأشعة مع أدلته. لا يُرسل شيء قبل اعتماد الضابط.',
    sCampaigns: 'مواقع يديرها الأشخاص أنفسهم، مرتبطة فقط بما يعيد المحتالون استخدامه.',
    sTools: 'افحص رابطاً واحداً أو قائمة كاملة أو إدراجاً في البحث أو الخرائط.',
    sAudit: 'كل قرار لضابط، مسلسل ببصمات SHA-256 بحيث يظهر أي تعديل.',
    live: 'متصل', sec: 'ث',
    kWatched: 'مواقع تحت المراقبة', kLive: 'تعمل الآن', kCases: 'قضايا بأدلة', kDanger: 'ثبتت خطورتها', kCamps: 'الحملات', kWaiting: 'بانتظار الاعتماد',
    queue: 'يحتاج إلى ضابط', queueHelp: 'مواقع خطيرة لم يراجعها أحد بعد، الأخطر أولاً.', queueEmpty: 'لا شيء بالانتظار. لكل قضية قرار.', review: 'راجع',
    sources: 'مصادر الإنذار المبكر', srcLook: 'أسماء مشابهة (DNS)', srcNrd: 'نطاقات مسجّلة حديثاً', srcCt: 'سجلات الشهادات', srcSearch: 'نتائج البحث والإعلانات', srcMaps: 'إدراجات الخرائط',
    on: 'يعمل', needsKey: 'يحتاج مفتاح API', lastHunt: 'آخر صيد', never: 'لم يتم بعد', names: 'اسماً', registered: 'مسجّل', liveFound: 'يعمل', goHunt: 'افتح الإنذار المبكر',
    measured: 'قياس من تشغيل مسجَّل', measuredHelp: 'مراقبة الشهادات، 24 نوفمبر 2026، 10 دقائق، 50 سجلاً عاماً. أعداد وأزمنة فقط. التنبيهات تقديرات وليست احتيالاً مؤكداً.',
    mCerts: 'شهادة قُرئت', mRate: 'شهادة في الثانية', mMedian: 'الوسيط من التسجيل إلى الرصد', mAlerts: 'تنبيه عن أسماء إماراتية مشابهة',
    emptyTitle: 'ملف القضايا فارغ', emptyText: 'ابدأ صيداً للبحث عن مواقع تعمل الآن وتقلّد البنوك والخدمات الحكومية الإماراتية، أو حمّل قضايا التدريب لترى سير العمل كاملاً على صفحات فيتو التجريبية غير الضارة.',
    runFirst: 'ابدأ الصيد', loadTraining: 'حمّل قضايا التدريب', loadingTraining: 'جارٍ فحص الصفحات التجريبية…', trainingDone: 'أُضيفت قضايا التدريب',
    trainingNote: 'قضايا التدريب هي صفحات فيتو التجريبية غير الضارة على هذا الخادم. تحمل وسم «تدريب» وليست مواقع حقيقية.',
    hunt: 'ابدأ صيداً', huntHelp: 'يبني فيتو الأسماء المشابهة لكل نطاق رسمي، ويتحقق من المسجّل منها، ويقرأ سجلات الشهادات وقوائم النطاقات الجديدة، ويزور ما يعمل ويفحص الأخطر بالأشعة.',
    scope: 'الجهات', priority: 'البنوك والجهات الحكومية ذات الأولوية', allInst: 'كل الجهات', xrayTop: 'ثم افحص بالأشعة أخطر', liveOnes: 'مواقع تعمل', run: 'ابدأ الصيد', running: 'جارٍ الصيد…', phase: 'المرحلة', checked: 'اسماً تم فحصه',
    suspects: 'المشتبه بها', fLive: 'تعمل', fDormant: 'خاملة', fAll: 'الكل', searchPh: 'ابحث عن موقع أو جهة…', noSuspects: 'لا يوجد مشتبه بها بعد. ابدأ الصيد.', noMatch: 'لا توجد نتائج مطابقة.',
    cSite: 'الموقع', cImitates: 'يقلّد', cFound: 'اكتُشف عبر', cStatus: 'الحالة', cThreat: 'الخطورة', cVerdict: 'الحكم', cEvidence: 'الأدلة', cSeen: 'آخر ظهور', cSignoff: 'الاعتماد', cAction: '',
    xray: 'أشعة', openCase: 'افتح القضية', armedNow: 'بدأ العمل للتو',
    st_live: 'يعمل', st_no_web: 'بلا موقع بعد', st_parked: 'متوقف', st_error_page: 'صفحة خطأ', st_redirects_official: 'يحوّل إلى الموقع الرسمي', st_brand_owned: 'مملوك للجهة', st_gone: 'زال',
    src_lookalike: 'اسم مشابه', src_ct: 'شهادة', src_nrd: 'نطاق جديد', src_search: 'بحث', src_maps: 'خرائط', src_manual: 'يدوي', src_xray: 'رابط مفحوص', src_sentinel: 'صيد', src_training: 'تدريب',
    v_dangerous: 'خطير', v_suspicious: 'مشبوه', v_clean: 'لا خطر ظاهر', v_unreachable: 'لا يمكن الوصول', v_phishing: 'تصيّد', v_legitimate: 'سليم',
    cfAll: 'الكل', cfWaiting: 'بالانتظار', followUp: 'تتطلب متابعة', cfApproved: 'معتمدة', cfRejected: 'مرفوضة', noCases: 'لا توجد قضايا بعد. افحص مشتبهاً به أو رابطاً.',
    r_pending: 'بالانتظار', r_approved: 'معتمدة', r_rejected: 'مرفوضة', r_needs_info: 'تحتاج معلومات',
    ev_cloaked: 'تمويه', ev_logo: 'شعار منسوخ',
    noCamps: 'لا توجد حملات بعد. تظهر عندما يشترك موقعان مفحوصان في بنية إجرامية واحدة.', graphHelp: 'الدوائر مواقع احتيال: اضغط على أحدها لفتح قضيته. المربعات ما يربطها: TG بوت تيليجرام نفسه، GA معرّف التحليلات نفسه، IP الخادم نفسه، KIT أداة التصيّد نفسها.',
    sites: 'مواقع', firstSeen: 'أول ظهور', confidence: 'الثقة',
    close: 'إغلاق', dWants: 'ما تريده هذه الصفحة', dPicture: 'الصفحة كما يراها الهاتف', dWhy: 'لماذا صنّفها فيتو', dAsks: 'تطلب', dSends: 'ترسل ما يُكتب إلى', dCloak: 'تمويه', dCloakText: 'تُظهر وجهها الحقيقي لبعض الزوار فقط',
    dInfra: 'التسجيل والاستضافة', dRegistrar: 'المسجِّل', dCreated: 'تاريخ تسجيل النطاق', dServer: 'الخادم', dAbuse: 'جهات الإبلاغ', dChain: 'سلسلة التحويل', dUrl: 'العنوان النهائي', dTitle: 'عنوان الصفحة', dFirst: 'أول ظهور', dSource: 'اكتُشف عبر',
    dCamp: 'مواقع مرتبطة', dReports: 'طلبات إزالة جاهزة للإرسال', dReportsHelp: 'مسودات فقط. فيتو لا يرسلها أبداً. يراجعها الضابط ويعتمدها ثم يرسلها.', rp_registrar: 'إلى المسجِّل', rp_host: 'إلى شبكة الاستضافة', rp_telegram: 'إلى تيليجرام', copy: 'نسخ', copied: 'تم النسخ',
    dSign: 'اعتماد الضابط', dSignPending: 'بانتظار ضابط. لا يجوز إرسال أي طلب إزالة من هذه القضية قبل اعتمادها.', officer: 'اسم الضابط أو رقمه', note: 'ملاحظة (اختياري)',
    approve: 'اعتمد للإزالة', reject: 'ارفض، لا إجراء', needInfo: 'تحتاج معلومات إضافية', signedBy: 'بواسطة', auditEntry: 'قيد السجل', changeDecision: 'سجّل قراراً جديداً', needName: 'أدخل اسم الضابط أولاً.',
    dlZip: 'ملف الأدلة ZIP', dlPdf: 'PDF', dlStix: 'STIX 2.1', dlPack: 'ملف الإزالة الكامل', needApprove: 'اعتمد أولاً',
    tXray: 'أشعة لرابط', tList: 'افحص قائمة', tListing: 'افحص إدراجاً',
    xrayHelp: 'يُفتح الرابط في متصفح معزول يُتلف بعد الاستخدام على الخادم. يكتب فيتو بيانات وهمية ويراقب وجهتها ويضيف الموقع إلى ملف القضايا.', xrayBtn: 'افحصه بالأشعة', xraying: 'جارٍ الفحص…', url: 'الرابط',
    listHelp: 'الصق الروابط، رابط في كل سطر، أو ملف CSV بعمود url وعمود label اختياري (1 أو 0). يُفحص كل رابط دون اتصال في نحو جزء من الألف من الثانية، حتى 20,000 رابط.', listBtn: 'افحص القائمة', listPh: 'https://…\nhttps://…', csv: 'تنزيل CSV', judged: 'رابطاً تم فحصه',
    precision: 'الدقة', recall: 'الاستدعاء', falseAlarms: 'إنذارات خاطئة', cScore: 'الدرجة', cReason: 'السبب الرئيسي',
    listingHelp: 'قارن نتيجة بحث أو إعلاناً أو إدراجاً على الخرائط بما تنشره الجهة نفسها. أرقام خدمة العملاء المزيفة هي الحيلة المعتادة.', lName: 'اسم الإدراج', lPhone: 'رقم الهاتف', lWeb: 'الموقع', listingBtn: 'افحص الإدراج',
    lv_guide: 'دليل من جهة مستقلة', lv_fake: 'إدراج مزيف', lv_suspicious: 'إدراج مشبوه', lv_official: 'يطابق البيانات الرسمية', lv_unknown: 'الأدلة غير كافية للتحقق من هذا الإدراج', officialIs: 'الرسمي',
    connOff: 'عمليات البحث والخرائط المباشرة متوقفة على هذا الخادم إلى أن يُضاف مفتاح API. فحص الإدراج أدناه يعمل دونه.',
    chainOk: 'السجل سليم', chainBad: 'السجل مكسور عند القيد', entries: 'قيداً', noAudit: 'لم يُسجَّل أي قرار بعد.', aTime: 'الوقت (UTC)', aDecision: 'القرار', aOfficer: 'الضابط', aHash: 'SHA-256', aNote: 'ملاحظة',
    humanRule: 'القرار للإنسان: فيتو يجمع ويشرح. لا يرسل طلب إزالة ولا يحجب شيئاً من تلقاء نفسه.',
    gateTitle: 'لوحة الشرطة', gateText: 'تعرض هذه المنطقة مواقع مشتبهاً بها وأدلة. أدخل رمز دخول الضابط للمتابعة.', code: 'رمز الدخول', enter: 'دخول', wrong: 'الرمز غير صحيح.', rate: 'محاولات كثيرة. انتظر دقيقة.', down: 'الخادم قيد التشغيل. حاول بعد دقيقة.',
    notConfigured: 'لوحة التحكم غير مفعّلة على هذا الخادم بعد: لم يُحدَّد رمز دخول.', gatePilot: 'دخول تجريبي. في التشغيل الفعلي يُستخدم نظام الدخول الموحد للجهة الشرطية.', back: 'العودة إلى الصفحة الرئيسية',
    loadErr: 'تعذّر الاتصال بالخادم.', error: 'حدث خطأ.'
  }
};
const T = k => TX[lang.cur][k] ?? TX.en[k] ?? k;
const VIEWS = [['overview', 'nOverview', 'activity'], ['hunt', 'nHunt', 'radar'], ['cases', 'nCases', 'gavel'], ['campaigns', 'nCamps', 'waypoints'], ['tools', 'nTools', 'scan-search'], ['audit', 'nAudit', 'list-checks']];
const S = {
  session: null, data: null, view: 'overview', job: null, ct: null, audit: null, loadErr: false,
  filter: 'live', q: '', caseFilter: 'all', caseQ: '', kinds: new Set(['lookalike', 'nrd', 'ct', 'search', 'maps']), all: false, xrayTop: 3, busy: new Set(), training: false,
  drawer: null, officer: store.get('veto.officer', ''), note: '', redo: false,
  messageText: '', sender: '', messageReport: null, tool: 'xray', xUrl: '', xBusy: false, xRes: null, listText: '', listBusy: false, listRes: null, listing: { name: '', phone: '', website: '' }, listingRes: null,
  gateCode: '', gateErr: null
};
const root = document.getElementById('app');
const overlay = document.body.appendChild(h('div', { id: 'overlay' }));

async function api(path, body) {
  const r = await fetch(path, body !== undefined ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : {});
  if (r.status === 403) { S.session = { ...(S.session || {}), ok: false }; render(); throw new Error('forbidden'); }
  return r.json();
}
const needsFollowUp = c => c.review?.decision === 'needs_info';
const waiting = c => (c.verdict === 'dangerous' || c.verdict === 'suspicious') && !c.review;
const verdictTone = v => (v === 'dangerous' || v === 'phishing' ? 'bad' : v === 'suspicious' ? 'mid' : v === 'legitimate' ? 'ok' : '');
const pct = x => `${Math.round((x || 0) * 100)}%`;

// ---------------- data ----------------
async function loadSession() {
  try { S.session = await fetch('/api/console/session').then(r => r.json()); } catch { S.session = { ok: false, error: true }; }
}
async function loadData(quiet = false) {
  try {
    S.data = await api('/api/sentinel'); S.job = S.data.job; S.loadErr = false;
    if (S.job?.running) pollJob();
  } catch (e) { if (e.message !== 'forbidden') S.loadErr = true; }
  if (!quiet || !typing()) render();
}
async function loadAudit() { S.audit = await api('/api/audit').catch(() => null); render(); }
let jobTimer = null;
function pollJob() {
  clearTimeout(jobTimer);
  jobTimer = setTimeout(async () => {
    const j = await api('/api/sentinel/job').catch(() => null);
    S.job = j?.job || null;
    if (S.job?.running) { render(); pollJob(); } else loadData();
  }, 1200);
}
const typing = () => { const a = document.activeElement; return !!a && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName); };
setInterval(() => { if (S.session?.ok && !document.hidden && !S.job?.running && !S.drawer) loadData(true); }, 20000);

// ---------------- actions ----------------
function go(view) {
  S.view = view; history.replaceState(null, '', '#' + view);
  if (view === 'audit') loadAudit(); else render();
  window.scrollTo(0, 0);
}
async function runHunt() {
  const insts = S.all ? S.data.institutions.map(i => i.id) : S.data.institutions.filter(i => i.priority).map(i => i.id);
  const r = await api('/api/sentinel/sweep', { insts, kinds: [...S.kinds], xrayTop: S.xrayTop }).catch(() => null);
  S.job = r?.job || { running: true, phase: 'starting', checked: 0, total: 0, registered: 0, live: 0, log: [] };
  S.view = 'hunt'; render(); pollJob();
}
async function loadTraining() {
  S.training = true; render();
  const r = await api('/api/sentinel/training', {}).catch(() => null);
  S.training = false;
  toast(r?.ok ? T('trainingDone') : T('error'));
  await loadData();
}
async function xrayHost(host) {
  S.busy.add(host); render();
  const r = await api('/api/sentinel/xray', { host }).catch(() => null);
  S.busy.delete(host);
  await loadData();
  if (r?.caseId) openCase(r.caseId);
}
async function openCase(id) {
  S.drawer = { id, loading: true }; S.note = ''; S.redo = false; renderDrawer();
  const d = await api('/api/case/' + id).catch(() => null);
  if (S.drawer?.id !== id) return;
  S.drawer = d?.ok ? { id, ...d } : { id, error: true };
  renderDrawer();
}
function closeDrawer() { S.drawer = null; renderDrawer(); render(); }
async function signOff(decision) {
  if (S.officer.trim().length < 2) { toast(T('needName')); document.getElementById('officerIn')?.focus(); return; }
  store.set('veto.officer', S.officer.trim());
  const r = await api(`/api/case/${S.drawer.id}/review`, { decision, officer: S.officer, note: S.note }).catch(() => null);
  if (!r?.ok) return toast(T('error'));
  S.drawer.review = r.review; S.redo = false; S.note = '';
  toast(T('r_' + decision)); renderDrawer(); loadData(true).then(render);
}
async function signIn(e) {
  e.preventDefault();
  const r = await fetch('/api/console/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ code: S.gateCode.trim() }) }).catch(() => null);
  if (r?.ok) { S.gateCode = ''; S.gateErr = null; await loadSession(); await loadData(); return; }
  S.gateErr = r?.status === 429 ? 'rate' : r?.status === 401 ? 'wrong' : 'down'; render();
  document.getElementById('codeIn')?.focus();
}
async function signOut() { await fetch('/api/console/logout', { method: 'POST' }).catch(() => {}); S.data = null; await loadSession(); render(); }
async function runXray() {
  if (!S.xUrl.trim() || S.xBusy) return;
  S.xBusy = true; S.xRes = null; render();
  S.xRes = await fetch('/api/xray', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: S.xUrl.trim() }) }).then(r => r.json()).catch(() => ({ ok: false, message: T('loadErr') }));
  S.xBusy = false;
  await loadData();
}
async function runList() {
  if (!S.listText.trim() || S.listBusy) return;
  S.listBusy = true; render();
  S.listRes = await api('/api/v1/judge', { text: S.listText }).catch(() => ({ error: true }));
  S.listBusy = false; render();
}
function downloadCsv() {
  const q = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const rows = [['url', 'verdict', 'score', 'label', 'reason'], ...S.listRes.results.map(r => [r.url, r.verdict, r.score, r.label ?? '', r.reasons?.[0]?.en || ''])];
  const a = h('a', { href: URL.createObjectURL(new Blob([rows.map(r => r.map(q).join(',')).join('\n')], { type: 'text/csv' })), download: 'veto-judge.csv' });
  a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
async function copyText(text) { try { await navigator.clipboard.writeText(text); toast(T('copied')); } catch { toast(T('error')); } }

// ---------------- pieces ----------------
const langBtn = () => h('button', { class: 'btn sm', type: 'button', onclick: () => { setLang(lang.cur === 'ar' ? 'en' : 'ar'); render(); renderDrawer(); } }, ic('languages'), T('langBtn'));
const brand = () => h('a', { class: 'brand', href: '/' }, h('img', { class: 'mark', src: '/brand/officer-kiki.png', alt: '', width: 40, height: 40 }),
  h('span', {}, h('strong', { dir: 'ltr' }, 'Veto.ai'), h('small', {}, T('brandSub'))));
const reviewTag = c => { const d = c.review?.decision || 'pending'; return h('span', { class: `tag ${d === 'approved' ? 'ok' : d === 'pending' ? (waiting(c) ? 'mid' : '') : d === 'needs_info' ? 'info' : ''}` }, T('r_' + d)); };
const evidenceTags = c => h('div', { class: 'tags' }, (c.asks || []).map(a => h('span', { class: 'tag' }, a)), (c.exfil || []).map(x => h('span', { class: 'tag bad' }, String(x.kind || x).replace(/_/g, ' '))),
  c.cloaked ? h('span', { class: 'tag bad' }, T('ev_cloaked')) : null, c.copiedLogo ? h('span', { class: 'tag bad' }, T('ev_logo')) : null);
const segs = (items, cur, set) => h('div', { class: 'segs', role: 'group' }, items.map(([id, label]) => h('button', { type: 'button', class: 'seg', 'aria-pressed': String(cur === id), onclick: () => { set(id); render(); } }, label)));
const searchBox = (id, value, set) => h('label', { class: 'search' }, ic('search'), h('span', { class: 'sr' }, T('searchPh')),
  h('input', { id, class: 'field', type: 'search', placeholder: T('searchPh'), value, oninput: e => { set(e.target.value); render(); } }));

function kpis(d) {
  const k = (n, label, ico, tone, view, filter = 'all') => h('button', { class: `kpi ${n ? tone || '' : ''}`, type: 'button', onclick: () => {
    if (view === 'cases') { S.caseFilter = filter; S.caseQ = ''; }
    if (view === 'hunt') { S.filter = filter; S.q = ''; }
    go(view);
  } }, h('span', { class: 'ic' }, ic(ico)), h('b', {}, fmtNum(n)), h('span', {}, label));
  return h('section', { class: 'kpis' },
    k(d.counts.total, T('kWatched'), 'radar', '', 'hunt'), k(d.counts.live, T('kLive'), 'activity', 'warn', 'hunt', 'live'), k(d.cases.length, T('kCases'), 'file-text', '', 'cases'),
    k(d.cases.filter(c => c.verdict === 'dangerous').length, T('kDanger'), 'octagon-alert', 'bad', 'cases', 'dangerous'), k(d.campaigns.length, T('kCamps'), 'waypoints', 'bad', 'campaigns'),
    k(d.cases.filter(waiting).length, T('kWaiting'), 'user-check', 'warn', 'cases', 'waiting'));
}
function sourcesPanel(d) {
  const src = (label, ico, on) => h('div', { class: 'src' }, ic(ico), h('b', {}, label), h('span', { class: `tag ${on ? 'ok' : ''}` }, on ? T('on') : T('needsKey')));
  const last = d.sweeps?.[d.sweeps.length - 1];
  return h('section', { class: 'panel' }, h('h2', {}, ic('radar'), T('sources')),
    h('div', { class: 'sources' }, src(T('srcLook'), 'fingerprint', true), src(T('srcNrd'), 'clock', true), src(T('srcCt'), 'badge-check', true), src(T('srcSearch'), 'search', d.connectors.search), src(T('srcMaps'), 'map-pin', d.connectors.maps), src(T('ads'), 'search', d.connectors.ads)),
    h('p', { class: 'tiny muted', style: 'margin:10px 0' }, `${T('lastHunt')}: ${last ? `${fmtDate(last.t)} · ${fmtNum(last.names)} ${T('names')} · ${last.registered} ${T('registered')} · ${last.live} ${T('liveFound')}` : T('never')}`),
    h('button', { class: 'btn sm', type: 'button', onclick: () => go('hunt') }, T('goHunt'), ' →'));
}
function measuredPanel() {
  const c = S.ct;
  if (!c) return null;
  const st = (n, label) => h('div', { class: 'stat' }, h('b', {}, n), h('span', {}, label));
  return h('section', { class: 'panel' }, h('h2', {}, ic('activity'), T('measured')), h('p', { class: 'help' }, T('measuredHelp')),
    h('div', { class: 'stat-grid' }, st(fmtNum(c.entries.certs), T('mCerts')), st(fmtNum(Math.round(c.coverage.entries_per_s)), T('mRate')),
      st(`${Math.round(c.latency.log_to_watch_all.median_s)} ${T('sec')}`, T('mMedian')), st(fmtNum(c.brand_gate.alerts), T('mAlerts'))));
}
function overviewView(d) {
  const queue = d.cases.filter(waiting).sort((a, b) => (b.risk || 0) - (a.risk || 0)).slice(0, 6);
  const empty = !d.cases.length && !d.suspects.length;
  return [
    kpis(d),
    empty ? h('section', { class: 'panel empty' }, h('img', { src: '/brand/officer-kiki.png', alt: '' }), h('h2', {}, T('emptyTitle')), h('p', {}, T('emptyText')),
      h('div', { class: 'acts' }, h('button', { class: 'btn blue', type: 'button', onclick: () => go('hunt') }, ic('play'), T('runFirst')),
        h('button', { class: `btn${S.training ? ' spin' : ''}`, type: 'button', disabled: S.training, onclick: loadTraining }, ic(S.training ? 'refresh-cw' : 'graduation-cap'), S.training ? T('loadingTraining') : T('loadTraining'))),
      h('p', { class: 'tiny' }, T('trainingNote'))) : null,
    h('div', { class: 'cols' },
      h('div', {},
        h('section', { class: 'panel' }, h('h2', {}, ic('user-check'), T('queue')), h('p', { class: 'help' }, T('queueHelp')),
          queue.length ? h('div', { class: 'queue' }, queue.map(c => h('button', { class: 'qrow', type: 'button', onclick: () => openCase(c.id) },
            h('span', { class: 'who' }, h('code', { dir: 'ltr' }, c.host), h('span', { class: 'tags' }, c.imitates ? h('span', { class: 'tag info' }, L(c.imitates.name)) : null, c.source === 'training' ? h('span', { class: 'tag' }, T('src_training')) : null,
              (c.exfil || []).slice(0, 2).map(x => h('span', { class: 'tag bad' }, String(x).replace(/_/g, ' '))), c.cloaked ? h('span', { class: 'tag bad' }, T('ev_cloaked')) : null)),
            h('span', { class: 'risk' }, pct(c.risk)), h('span', { class: 'btn sm primary' }, T('review')))))
            : h('p', { class: 'muted small' }, d.cases.length ? T('queueEmpty') : T('noCases'))),
        d.cases.some(needsFollowUp) ? h('section', { class: 'panel' }, h('h2', {}, T('followUp')),
          d.cases.filter(needsFollowUp).map(c => h('button', { class: 'qrow', type: 'button', onclick: () => openCase(c.id) },
            h('code', { dir: 'ltr' }, c.host), reviewTag(c)))) : null,
        h('div', { class: 'notice' }, ic('user-check'), h('span', {}, T('humanRule')))),
      h('div', {}, sourcesPanel(d), measuredPanel(), h('details', { class: 'panel' },
        h('summary', {}, T('pilot')), h('p', { class: 'help' }, T('pilotHelp')),
        h('a', { href: '/data/web-verification-2026-11-25.json', target: '_blank', rel: 'noopener' }, T('verification')))))
  ];
}

const STATUS_TONE = { live: 'bad', no_web: 'mid', error_page: 'mid', parked: '', redirects_official: '', brand_owned: 'ok', gone: '' };
function huntView(d) {
  const kind = (id, label, needs) => {
    const off = needs && !d.connectors[needs];
    return h('label', { class: `kind${off ? ' off' : ''}` }, h('input', { type: 'checkbox', checked: S.kinds.has(id) && !off, disabled: off, onchange: e => { e.target.checked ? S.kinds.add(id) : S.kinds.delete(id); } }), label, off ? h('small', { class: 'muted' }, `(${T('needsKey')})`) : null);
  };
  const running = !!S.job?.running, j = S.job;
  const dormant = s => ['no_web', 'error_page', 'parked'].includes(s.status);
  const q = S.q.trim().toLowerCase();
  const pool = d.suspects.filter(s => !q || s.host.includes(q) || L(s.instName).toLowerCase().includes(q) || (s.inst || '').includes(q));
  const rows = pool.filter(s => (S.filter === 'all' ? true : S.filter === 'live' ? s.status === 'live' : dormant(s))).slice(0, 120);
  const n = { live: pool.filter(s => s.status === 'live').length, dormant: pool.filter(dormant).length, all: pool.length };
  return [
    h('section', {class:'panel'}, h('h2',{},L({en:'UAE helpline hunt',ar:'فحص أرقام المساعدة الإماراتية'})),
      h('form',{class:'form-row',onsubmit:async e=>{
        e.preventDefault(); if(S.phoneBusy) return;
        S.phoneBusy=true; render();
        try { S.phoneRun=await api('/api/sentinel/helplines',{inst:S.phoneInst || 'fab'}); }
        catch { S.phoneRun={errors:[T('error')]}; }
        finally { S.phoneBusy=false;render(); }
      }}, h('select',{'aria-label':T('scope'),onchange:e=>{S.phoneInst=e.target.value;S.phoneRun=null;render();}},
        d.institutions.map(i=>h('option',{value:i.id,selected:i.id===(S.phoneInst || 'fab')},L(i.name)))),
        h('button',{class:'btn primary',type:'submit',disabled:S.phoneBusy},S.phoneBusy ? T('running') : L({en:'Check live listings',ar:'فحص الإدراجات مباشرة'})))),
    S.phoneRun ? h('section',{class:'panel'},h('b',{},S.phoneRun.query), h('p',{},S.phoneRun.at),
      Object.entries(S.phoneRun.counts || {}).map(([k,v])=>h('span',{class:'tag'},k+' '+(v ?? '—'))),
      (S.phoneRun.errors || []).map(e=>h('p',{class:'notice'},e)),
      (S.phoneRun.rows || []).map(r=>h('div',{class:'src'},h('div',{},h('span',{},r.channel+' · '+r.title),
        r.sourceUrl || r.excerpt ? h('details',{},h('summary',{},L({en:'Source evidence',ar:'دليل المصدر'})),
          r.sourceUrl ? h('p',{class:'small',dir:'ltr',style:'overflow-wrap:anywhere'},r.sourceUrl) : null,
          r.excerpt ? h('p',{dir:'auto'},r.excerpt) : null) : null),
        h('code',{dir:'ltr'},r.phone),r.advisory ? h('span',{class:'notice warn'},L(r.advisory),h('a',{href:r.advisory.source.url,target:'_blank',rel:'noopener noreferrer'}, ' · '+L(r.advisory.source))) : h('span',{},r.guide ? T('lv_guide') : r.match ? L({en:'Published number',ar:'رقم منشور'}) : L({en:'Unverified number',ar:'رقم غير متحقق منه'}))))) : null,
    h('section', { class: 'panel' }, h('h2', {}, ic('crosshair'), T('hunt')), h('p', { class: 'help' }, T('huntHelp')),
      h('div', { class: 'kinds' }, kind('lookalike', T('srcLook')), kind('nrd', T('srcNrd')), kind('ct', T('srcCt')), kind('search', T('srcSearch'), 'search'), kind('maps', T('srcMaps'), 'maps')),
      h('div', { class: 'hunt-row' },
        h('label', {}, T('scope'), ' ', h('select', { onchange: e => { S.all = e.target.value === 'all'; } },
          h('option', { value: 'priority', selected: !S.all }, `${T('priority')} (${d.institutions.filter(i => i.priority).length})`), h('option', { value: 'all', selected: S.all }, `${T('allInst')} (${d.institutions.length})`))),
        h('label', {}, T('xrayTop'), ' ', h('input', { type: 'number', min: 0, max: 10, value: S.xrayTop, onchange: e => { S.xrayTop = Number(e.target.value) || 0; } }), ' ', T('liveOnes')),
        h('button', { class: `btn blue${running ? ' spin' : ''}`, type: 'button', disabled: running, onclick: runHunt }, ic(running ? 'refresh-cw' : 'play'), running ? T('running') : T('run'))),
      j && (j.running || j.error) ? h('div', { class: 'job' }, h('b', {}, `${T('phase')}: ${j.phase}`), ` · ${fmtNum(j.checked)}/${fmtNum(j.total)} ${T('checked')} · ${j.registered} ${T('registered')} · ${j.live} ${T('liveFound')}`,
        h('div', { class: 'progress' }, h('i', { style: `width:${j.total ? Math.round((j.checked / j.total) * 100) : 0}%` })), h('pre', {}, (j.log || []).slice(-5).join('\n'))) : null),
    h('section', { class: 'panel' },
      h('div', { class: 'panel-head' }, h('h2', {}, ic('telescope'), T('suspects'))),
      h('div', { class: 'tools' }, segs([['live', `${T('fLive')} (${n.live})`], ['dormant', `${T('fDormant')} (${n.dormant})`], ['all', `${T('fAll')} (${n.all})`]], S.filter, v => { S.filter = v; }), searchBox('qSus', S.q, v => { S.q = v; })),
      rows.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' },
        h('thead', {}, h('tr', {}, [T('cSite'), T('cImitates'), T('cFound'), T('cStatus'), T('cThreat'), T('cAction')].map(x => h('th', {}, x)))),
        h('tbody', {}, rows.map(s => h('tr', { class: s.caseId ? 'click' : null, onclick: s.caseId ? () => openCase(s.caseId) : null },
          h('td', {}, h('code', {}, s.host), s.armedAt ? h('span', { class: 'tag bad', style: 'margin-inline-start:6px' }, ic('siren'), T('armedNow')) : null, s.why?.[0] ? h('div', { class: 'tiny muted' }, L(s.why[0])) : null),
          h('td', { 'data-l': T('cImitates') }, L(s.instName) || s.inst || ''),
          h('td', { 'data-l': T('cFound') }, h('div', { class: 'tags' }, (s.sources || []).map(x => h('span', { class: 'tag' }, T('src_' + x))))),
          h('td', { 'data-l': T('cStatus') }, h('span', { class: `tag ${STATUS_TONE[s.status] || ''}` }, T('st_' + s.status))),
          h('td', { 'data-l': T('cThreat') }, h('span', { class: 'meter' }, h('i', { style: `width:${pct(s.score)}`, class: (s.score || 0) >= 0.7 ? 'bad' : (s.score || 0) >= 0.4 ? 'mid' : '' })), pct(s.score)),
          h('td', {}, s.caseId ? h('button', { class: 'btn sm', type: 'button' }, ic('file-text'), T('openCase'))
            : s.status === 'live' || s.status === 'error_page' ? h('button', { class: `btn sm${S.busy.has(s.host) ? ' spin' : ''}`, type: 'button', disabled: S.busy.has(s.host), onclick: e => { e.stopPropagation(); xrayHost(s.host); } }, ic(S.busy.has(s.host) ? 'refresh-cw' : 'scan-search'), T('xray')) : null))))))
        : h('p', { class: 'muted' }, d.suspects.length ? T('noMatch') : T('noSuspects')))
  ];
}
function casesView(d) {
  const q = S.caseQ.trim().toLowerCase();
  const pool = d.cases.filter(c => !q || c.host.includes(q) || L(c.imitates?.name).toLowerCase().includes(q));
  const f = { all: () => true, waiting, followUp: needsFollowUp, dangerous: c => c.verdict === 'dangerous', approved: c => c.review?.decision === 'approved', rejected: c => c.review?.decision === 'rejected' };
  const rows = pool.filter(f[S.caseFilter]);
  const cnt = k => pool.filter(f[k]).length;
  return [h('section', { class: 'panel' },
    h('div', { class: 'tools' }, segs([['all', `${T('cfAll')} (${cnt('all')})`], ['waiting', `${T('cfWaiting')} (${cnt('waiting')})`], ['followUp', `${T('followUp')} (${cnt('followUp')})`], ['dangerous', `${T('v_dangerous')} (${cnt('dangerous')})`], ['approved', `${T('cfApproved')} (${cnt('approved')})`], ['rejected', `${T('cfRejected')} (${cnt('rejected')})`]], S.caseFilter, v => { S.caseFilter = v; }),
      searchBox('qCase', S.caseQ, v => { S.caseQ = v; }), h('span', { class: 'grow' }),
      h('button', { class: `btn sm${S.training ? ' spin' : ''}`, type: 'button', disabled: S.training, onclick: loadTraining }, ic(S.training ? 'refresh-cw' : 'graduation-cap'), S.training ? T('loadingTraining') : T('loadTraining'))),
    rows.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, [T('cSite'), T('cVerdict'), T('cImitates'), T('cEvidence'), T('cSeen'), T('cSignoff')].map(x => h('th', {}, x)))),
      h('tbody', {}, rows.map(c => h('tr', { class: 'click', tabindex: 0, onclick: () => openCase(c.id), onkeydown: e => { if (e.key === 'Enter') openCase(c.id); } },
        h('td', {}, h('code', { dir: 'ltr' }, c.host), c.source === 'training' ? h('span', { class: 'tag', style: 'margin-inline-start:6px' }, T('src_training')) : null, c.title ? h('div', { class: 'tiny muted' }, `“${c.title.slice(0, 60)}”`) : null),
        h('td', { 'data-l': T('cVerdict') }, h('span', { class: `tag ${verdictTone(c.verdict)}` }, `${T('v_' + c.verdict)} ${pct(c.risk)}`)),
        h('td', { 'data-l': T('cImitates') }, L(c.imitates?.name) || ''),
        h('td', { 'data-l': T('cEvidence') }, evidenceTags({ ...c, exfil: (c.exfil || []).map(kind => ({ kind })) })),
        h('td', { 'data-l': T('cSeen'), class: 'small' }, fmtDate(c.lastSeen)),
        h('td', { 'data-l': T('cSignoff') }, reviewTag(c)))))))
      : h('p', { class: 'muted' }, d.cases.length ? T('noMatch') : T('noCases')))];
}

// The scam network: sites joined through the infrastructure they share. A small force-directed layout drawn as SVG.
const KEY_ICON = { telegram_bot: 'TG', telegram: 'TG', whatsapp: 'WA', wallet: '₿', analytics: 'GA', pixel: 'PX', metrika: 'YM', email: '@', phone: '☎', kit_exact: 'KIT', kit_near: 'KIT', favicon: 'ICO', ip: 'IP', ns: 'NS', bulk: 'REG', exfil: 'EXF', apk: 'APK' };
function networkGraph(campaigns) {
  const NS = 'http://www.w3.org/2000/svg';
  const nodes = new Map(), edges = [];
  const node = (id, o) => { if (!nodes.has(id)) nodes.set(id, { id, x: 400 + Math.cos(nodes.size * 2.4) * (60 + nodes.size * 9), y: 170 + Math.sin(nodes.size * 2.4) * (40 + nodes.size * 6), vx: 0, vy: 0, ...o }); return nodes.get(id); };
  for (const c of campaigns) {
    for (const m of c.members) node('s:' + m.id, { kind: 'site', label: m.host, verdict: m.verdict, caseId: m.id });
    for (const l of c.links) {
      const k = node('k:' + l.why + ':' + l.value, { kind: 'key', label: KEY_ICON[l.why] || 'LINK', title: `${L(l)}: ${l.value}`, value: String(l.value).slice(0, 14) });
      for (const sid of [l.a, l.b]) if (!edges.some(e => e.s === 's:' + sid && e.t === k.id)) edges.push({ s: 's:' + sid, t: k.id });
    }
  }
  const N = [...nodes.values()];
  for (let it = 0; it < 320; it++) {
    for (const a of N) for (const b of N) {
      if (a === b) continue;
      const dx = a.x - b.x, dy = a.y - b.y, d2 = Math.max(80, dx * dx + dy * dy);
      a.vx += (dx / Math.sqrt(d2)) * 2600 / d2; a.vy += (dy / Math.sqrt(d2)) * 2600 / d2;
    }
    for (const e of edges) {
      const a = nodes.get(e.s), b = nodes.get(e.t); if (!a || !b) continue;
      const dx = b.x - a.x, dy = b.y - a.y, dd = Math.sqrt(dx * dx + dy * dy) || 1, f = (dd - 95) * 0.02;
      a.vx += dx / dd * f; a.vy += dy / dd * f; b.vx -= dx / dd * f; b.vy -= dy / dd * f;
    }
    for (const n of N) { n.vx += (400 - n.x) * 0.004; n.vy += (170 - n.y) * 0.006; n.x += n.vx; n.y += n.vy; n.vx *= 0.6; n.vy *= 0.6; n.x = Math.max(90, Math.min(710, n.x)); n.y = Math.max(28, Math.min(300, n.y)); }
  }
  const el = (tag, attrs, text) => { const e = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); if (text != null) e.textContent = text; return e; };
  const svg = el('svg', { viewBox: '0 0 800 340', role: 'img', 'aria-label': T('nCamps') });
  const wrap = h('div', { class: 'graph' }, svg);
  const lines = edges.map(e => { const a = nodes.get(e.s), b = nodes.get(e.t); const ln = el('line', { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: 'ng-edge' }); svg.append(ln); return { e, ln }; });
  const groups = new Map();
  const focus = id => {
    wrap.classList.toggle('focus', !!id);
    const near = new Set(id ? [id] : []);
    for (const { e, ln } of lines) { const on = !!id && (e.s === id || e.t === id); ln.classList.toggle('on', on); if (on) { near.add(e.s); near.add(e.t); } }
    for (const [nid, g] of groups) g.classList.toggle('on', near.has(nid));
  };
  for (const n of N) {
    const g = el('g', { class: `ng-node ${n.kind} ${n.verdict || ''}`, transform: `translate(${n.x.toFixed(1)},${n.y.toFixed(1)})`, tabindex: n.kind === 'site' ? 0 : -1 });
    if (n.kind === 'site') {
      g.append(el('circle', { r: 15 }), el('text', { y: 33, 'text-anchor': 'middle', class: 'ng-label' }, n.label.length > 26 ? n.label.slice(0, 25) + '…' : n.label), el('title', {}, n.label));
      g.addEventListener('click', () => openCase(n.caseId));
      g.addEventListener('keydown', e => { if (e.key === 'Enter') openCase(n.caseId); });
    } else g.append(el('rect', { x: -17, y: -12, width: 34, height: 24, rx: 7 }), el('text', { y: 4.5, 'text-anchor': 'middle', class: 'ng-key' }, n.label), el('text', { y: 27, 'text-anchor': 'middle', class: 'ng-sub' }, n.value), el('title', {}, n.title));
    g.addEventListener('mouseenter', () => focus(n.id)); g.addEventListener('mouseleave', () => focus(null));
    g.addEventListener('focus', () => focus(n.id)); g.addEventListener('blur', () => focus(null));
    groups.set(n.id, g); svg.append(g);
  }
  return h('div', {}, wrap, h('p', { class: 'tiny muted', style: 'margin-top:8px' }, T('graphHelp')));
}
function campaignsView(d) {
  return [h('section', { class: 'panel' },
    d.campaigns.length ? [networkGraph(d.campaigns), d.campaigns.map(c => h('div', { class: 'camp' },
      h('div', { class: 'camp-head' }, h('b', {}, c.id), h('span', { class: 'tag bad' }, `${c.size} ${T('sites')}`), h('span', { class: 'tag' }, `${T('confidence')}: ${c.confidence}`), (c.brands || []).map(b => h('span', { class: 'tag info' }, L(b.name))),
        h('span', { class: 'tiny muted' }, `${T('firstSeen')} ${fmtDate(c.firstSeen)}`)),
      h('ul', {}, [...new Map(c.links.map(l => [l.why + l.value, l])).values()].slice(0, 6).map(l => h('li', {}, ic('link'), h('span', {}, L(l) + ':'), h('code', {}, l.value)))),
      h('div', { class: 'tags' }, c.members.map(m => h('button', { class: `tag ${verdictTone(m.verdict)}`, type: 'button', onclick: () => openCase(m.id) }, m.host)))))]
      : h('div', { class: 'empty' }, h('img', { src: '/brand/officer-kiki.png', alt: '' }), h('p', {}, T('noCamps'))))];
}

function toolsView(d) {
  const tab = (id, label, ico) => h('button', { class: `btn sm${S.tool === id ? ' primary' : ''}`, type: 'button', 'aria-pressed': String(S.tool === id), onclick: () => { S.tool = id; render(); } }, ic(ico), label);
  let body;
  if (S.tool === 'message') {
    const report = S.messageReport;
    const run = () => { S.messageReport = analyze({ channel: 'sms', sender: S.sender, text: S.messageText }); render(); };
    body = [h('div', { class: 'acts' }, h('b', {}, T('examples')), EXAMPLES.slice(0, 3).map(example =>
      h('button', { type: 'button', class: 'btn sm', onclick: () => { S.sender = example.sender; S.messageText = example.text; run(); } }, L(example.label)))),
      h('form', { class: 'panel', onsubmit: e => { e.preventDefault(); if (S.messageText.trim()) run(); } },
        h('label', { class: 'lbl' }, T('sender'), h('input', { class: 'field', dir: 'auto', value: S.sender, oninput: e => { S.sender = e.target.value; S.messageReport = null; render(); }, id: 'messageSender' })),
        h('label', { class: 'lbl' }, T('messageText'), h('textarea', { class: 'field', required: true, rows: 3, dir: 'auto', value: S.messageText, oninput: e => { S.messageText = e.target.value; S.messageReport = null; render(); }, id: 'messageText' })),
        h('button', { class: 'btn primary', type: 'submit' }, T('analyzeMessage'))),
      report ? h('section', { class: 'result' }, h('h3', {}, T('riskScore'), ' ', pct(report.risk)),
        h('ul', {}, report.findings.map(f => h('li', {}, h('b', {}, L(f.title)), ' ', L(f.detail))))) : null];
  } else if (S.tool === 'xray') {
    const r = S.xRes;
    body = [h('p', { class: 'help' }, T('xrayHelp')),
      h('form', { class: 'form-row', onsubmit: e => { e.preventDefault(); runXray(); } },
        h('label', { class: 'lbl' }, T('url'), h('input', { id: 'xUrl', class: 'field', type: 'text', inputmode: 'url', dir: 'ltr', placeholder: 'https://…', value: S.xUrl, oninput: e => { S.xUrl = e.target.value; } })),
        h('button', { class: `btn blue${S.xBusy ? ' spin' : ''}`, type: 'submit', disabled: S.xBusy }, ic(S.xBusy ? 'refresh-cw' : 'scan-search'), S.xBusy ? T('xraying') : T('xrayBtn'))),
      r ? (r.ok ? h('div', { class: `result ${verdictTone(r.verdict) || 'ok'}` },
        h('h3', {}, h('code', {}, r.finalHost), h('span', { class: `tag ${verdictTone(r.verdict) || 'ok'}` }, `${T('v_' + r.verdict)} ${pct(r.risk)}`), r.official ? h('span', { class: 'tag ok' }, L(r.official.name) || 'official') : null),
        r.chain?.length > 1 ? h('details', {}, h('summary', {}, T('dChain')), h('ol', {}, r.chain.map(url => h('li', {}, h('code', { dir: 'ltr' }, url))))) : null,
        r.intent ? h('p', {}, L(r.intent)) : null,
        h('ul', {}, (r.signals || []).slice(0, 4).map(s => h('li', {}, L(s)))),
        r.caseId ? h('div', {}, h('button', { class: 'btn primary sm', type: 'button', onclick: () => openCase(r.caseId) }, ic('file-text'), T('openCase'))) : null)
        : h('div', { class: 'result mid' }, r.message || T('error'))) : null];
  } else if (S.tool === 'list') {
    const res = S.listRes?.results;
    let stats = null;
    if (res) {
      const lab = res.filter(r => r.label === 1 || r.label === 0), flag = r => r.verdict === 'phishing';
      const tp = lab.filter(r => r.label === 1 && flag(r)).length, fp = lab.filter(r => r.label === 0 && flag(r)).length, pos = lab.filter(r => r.label === 1).length, neg = lab.length - pos;
      const by = v => res.filter(r => r.verdict === v).length;
      stats = h('div', { class: 'tags', style: 'margin:12px 0' }, h('span', { class: 'tag' }, `${fmtNum(res.length)} ${T('judged')}`), h('span', { class: 'tag bad' }, `${T('v_phishing')} ${by('phishing')}`), h('span', { class: 'tag mid' }, `${T('v_suspicious')} ${by('suspicious')}`), h('span', { class: 'tag ok' }, `${T('v_legitimate')} ${by('legitimate')}`),
        lab.length ? [h('span', { class: 'tag info' }, `${T('precision')} ${tp + fp ? (100 * tp / (tp + fp)).toFixed(1) : '–'}%`), h('span', { class: 'tag info' }, `${T('recall')} ${pos ? (100 * tp / pos).toFixed(1) : '–'}%`), h('span', { class: 'tag info' }, `${T('falseAlarms')} ${neg ? (100 * fp / neg).toFixed(1) : '–'}%`)] : null,
        h('button', { class: 'btn sm', type: 'button', onclick: downloadCsv }, ic('download'), T('csv')));
    }
    body = [h('p', { class: 'help' }, T('listHelp')),
      S.validation ? h('details', { class: 'report' }, h('summary', {}, L({en: 'Saved evaluation · 20 labelled URLs', ar: 'تقييم محفوظ · ٢٠ رابطاً مصنّفاً'})),
        h('p', { class: 'help' }, L({en: 'Offline sample of official UAE sites and OpenPhish entries. Training overlap is unknown. Your own labelled list is scored separately below.', ar: 'عينة محلية من مواقع إماراتية رسمية وروابط OpenPhish. التداخل مع بيانات التدريب غير معلوم. تُقيّم قائمتك المصنّفة بشكل مستقل أدناه.'})),
        h('p', {}, L(S.validationCounts)),
        h('a', { href: '/data/web-verification-2026-11-25.json', target: '_blank', rel: 'noopener noreferrer' }, L({en: 'Inspect the labelled results and URL hashes', ar: 'عرض النتائج المصنفة وبصمات الروابط'})),
        h('p', {}, S.validation.map(([key, value]) => T(key) + ' ' + value).join(' · '))) : null,
      h('textarea', { id: 'listIn', class: 'field mono', rows: 6, dir: 'ltr', placeholder: T('listPh'), 'aria-label': T('tList'), value: S.listText, oninput: e => { S.listText = e.target.value; } }),
      h('div', { style: 'margin-top:10px' }, h('button', { class: `btn blue${S.listBusy ? ' spin' : ''}`, type: 'button', disabled: S.listBusy, onclick: runList }, ic(S.listBusy ? 'refresh-cw' : 'list-checks'), T('listBtn'))),
      S.listRes?.error || S.listRes?.message ? h('div', { class: 'result mid' }, S.listRes.message || T('error')) : null, stats,
      res ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' }, h('thead', {}, h('tr', {}, [T('url'), T('cVerdict'), T('cScore'), T('cReason')].map(x => h('th', {}, x)))),
        h('tbody', {}, res.slice(0, 200).map(r => h('tr', {}, h('td', {}, h('code', {}, r.url.length > 80 ? r.url.slice(0, 79) + '…' : r.url)), h('td', { 'data-l': T('cVerdict') }, h('span', { class: `tag ${verdictTone(r.verdict)}` }, T('v_' + r.verdict))),
          h('td', { 'data-l': T('cScore') }, Number(r.score).toFixed(2)), h('td', { 'data-l': T('cReason'), class: 'small' }, L(r.reasons?.[0]))))))) : null];
  } else {
    const r = S.listingRes, fld = (k, label, ph, dir) => h('label', { class: 'lbl' }, label, h('input', { id: 'l_' + k, class: 'field', type: 'text', dir: dir || 'auto', placeholder: ph, value: S.listing[k], oninput: e => { S.listing[k] = e.target.value; } }));
    const evidence = s => h('li', {}, L(s), s.source ? h('a', { href: s.source.url, target: '_blank', rel: 'noopener noreferrer' }, ' · ' + L(s.source)) : null);
    const tone = { fake: 'bad', suspicious: 'mid', official: 'ok', guide: '', unknown: '' };
    body = [d.connectors.search || d.connectors.maps ? null : h('div', { class: 'notice warn' }, ic('info'), h('span', {}, T('connOff'))), h('p', { class: 'help' }, T('listingHelp')),
      h('form', { class: 'form-row', onsubmit: e => { e.preventDefault(); S.listingRes = checkListing(S.listing); render(); } },
        fld('name', T('lName'), 'Emirates NBD Customer Care 24/7'), fld('phone', T('lPhone'), '+971 5x xxx xxxx', 'ltr'), fld('website', T('lWeb'), 'example.com', 'ltr'),
        h('button', { class: 'btn blue', type: 'submit' }, ic('map-pin'), T('listingBtn'))),
      r ? h('div', { class: `result ${tone[r.verdict]}` }, h('h3', {}, T('lv_' + r.verdict), r.inst ? h('span', { class: 'tag info' }, L(r.inst.name)) : null),
        r.signals?.length ? h('p', {}, T('riskScore') + ' · ' + pct(r.risk)) : null,
        r.signals?.length ? h('ul', {}, r.signals.map(evidence)) : null, r.positives?.length ? h('ul', {}, r.positives.map(evidence)) : null,
        r.official ? h('p', { class: 'small' }, h('b', {}, T('officialIs') + ': '), [...(r.official.phones || []).map(p => p.display), ...(r.official.domains || [])].join(' · ')) : null) : null];
  }
  return [h('section', { class: 'panel' }, h('div', { class: 'tabs2' }, tab('xray', T('tXray'), 'scan-search'), tab('list', T('tList'), 'list-checks'), tab('listing', T('tListing'), 'map-pin'), tab('message', T('message'), 'file-text')), body)];
}
function auditView() {
  const a = S.audit;
  if (!a) return [h('section', { class: 'panel' }, h('p', { class: 'muted' }, '…'))];
  return [h('div', { class: `notice ${a.intact ? 'ok' : 'bad'}` }, ic(a.intact ? 'shield-check' : 'shield-alert'), h('span', {}, a.intact ? `${T('chainOk')} · ${a.count} ${T('entries')}` : `${T('chainBad')} ${a.brokenAt ?? ''}`, a.head ? h('div', { class: 'tiny' }, h('code', {}, a.head)) : null)),
    h('div', { class: 'notice' }, ic('user-check'), h('span', {}, T('humanRule'))),
    h('section', { class: 'panel' }, a.entries.length ? h('div', { class: 'tbl-wrap' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, ['#', T('aTime'), T('cSite'), T('aDecision'), T('aOfficer'), T('aNote'), T('aHash')].map(x => h('th', {}, x)))),
      h('tbody', {}, a.entries.map(e => h('tr', { class: 'click', onclick: () => openCase(e.caseId) }, h('td', {}, e.n), h('td', { 'data-l': T('aTime'), class: 'small' }, (e.t || '').slice(0, 16).replace('T', ' ')), h('td', { 'data-l': T('cSite') }, h('code', {}, e.host)),
        h('td', { 'data-l': T('aDecision') }, h('span', { class: `tag ${e.decision === 'approved' ? 'ok' : e.decision === 'needs_info' ? 'info' : ''}` }, T('r_' + e.decision))), h('td', { 'data-l': T('aOfficer') }, e.officer), h('td', { 'data-l': T('aNote'), class: 'small' }, e.note || ''),
        h('td', { 'data-l': T('aHash') }, h('code', { class: 'tiny' }, (e.hash || '').slice(0, 16) + '…'))))))) : h('p', { class: 'muted' }, T('noAudit')))];
}

// ---------------- case drawer ----------------
function renderDrawer() {
  const D = S.drawer;
  if (!D) { overlay.replaceChildren(); document.body.style.overflow = ''; return; }
  document.body.style.overflow = 'hidden';
  const head = (title, extra) => h('div', { class: 'drawer-head' }, h('div', { class: 'grow' }, h('h2', {}, title), extra), h('button', { class: 'btn sm', type: 'button', 'aria-label': T('close'), onclick: closeDrawer }, ic('x')));
  let inner;
  if (D.loading || D.error) inner = [head(D.error ? T('error') : '…'), h('div', { class: 'drawer-body' }, h('p', { class: 'muted' }, D.error ? T('loadErr') : '…'))];
  else {
    const c = D.case, rv = D.review, approved = rv?.decision === 'approved';
    const sec = (title, ...kids) => (kids.flat().some(Boolean) ? h('section', { class: 'sec' }, h('h3', {}, title), kids) : null);
    const kv = rows => h('dl', { class: 'kv' }, rows.filter(r => r[1]).map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)]));
    const inf = c.infra || {};
    const form = !rv || S.redo;
    inner = [
      head(h('code', {}, c.finalHost), h('div', { class: 'tags', style: 'margin-top:8px' }, h('span', { class: `tag ${c.verdict === 'dangerous' ? 'solid-bad' : verdictTone(c.verdict)}` }, `${T('v_' + c.verdict)} ${pct(c.risk)}`),
        c.imitates ? h('span', { class: 'tag info' }, `${T('cImitates')}: ${L(c.imitates.name)}`) : null, c.source === 'training' ? h('span', { class: 'tag' }, T('src_training')) : null, D.campaign ? h('span', { class: 'tag bad' }, `${D.campaign.id} · ${D.campaign.size} ${T('sites')}`) : null)),
      h('div', { class: 'drawer-body' },
        h('section', { class: `signoff ${rv?.decision || ''}` }, h('b', {}, ic('user-check'), ' ', T('dSign'), rv ? `: ${T('r_' + rv.decision)}` : ''),
          rv ? h('div', { class: 'small' }, `${T('signedBy')} ${rv.officer} · ${(rv.t || '').slice(0, 16).replace('T', ' ')} UTC`, rv.note ? ` · “${rv.note}”` : '', h('div', { class: 'hash' }, `${T('auditEntry')} ${rv.n} · SHA-256 `, h('code', {}, rv.hash))) : h('p', { class: 'small' }, T('dSignPending')),
          form ? [h('div', { class: 'form-row' }, h('label', { class: 'lbl' }, T('officer'), h('input', { id: 'officerIn', class: 'field', type: 'text', autocomplete: 'name', value: S.officer, oninput: e => { S.officer = e.target.value; } })),
            h('label', { class: 'lbl' }, T('note'), h('input', { id: 'noteIn', class: 'field', type: 'text', value: S.note, oninput: e => { S.note = e.target.value; } }))),
          h('div', { class: 'acts' }, h('button', { class: 'btn ok sm', type: 'button', onclick: () => signOff('approved') }, ic('check'), T('approve')), h('button', { class: 'btn sm', type: 'button', onclick: () => signOff('needs_info') }, ic('circle-help'), T('needInfo')),
            h('button', { class: 'btn sm', type: 'button', onclick: () => signOff('rejected') }, ic('x'), T('reject')))]
            : h('div', {}, h('button', { class: 'btn sm', type: 'button', onclick: () => { S.redo = true; renderDrawer(); } }, T('changeDecision')))),
        sec(T('evidenceInventory'), kv([[T('dPicture'), c.hasShot ? T('on') : T('missing')],
          [T('dRegistrar'), inf.registrar || T('missing')], [T('dServer'), inf.ip || T('missing')],
          [T('dFirst'), c.firstSeen || T('missing')]])),
        c.intent ? sec(T('dWants'), h('div', { class: 'intent' }, L(c.intent))) : null,
        c.hasShot ? sec(T('dPicture'), h('img', { class: 'shot', src: `/api/case/${c.id}/shot.jpg`, alt: T('dPicture'), loading: 'lazy' })) : null,
        sec(T('dWhy'), c.signals?.length ? h('ul', { class: 'why' }, c.signals.map(s => h('li', {}, h('b', {}, pct(s.w)), h('span', {}, L(s))))) : null),
        sec(T('cEvidence'), kv([[T('dAsks'), c.asks?.length ? h('div', { class: 'tags' }, c.asks.map(a => h('span', { class: 'tag' }, a))) : null],
          [T('dSends'), c.exfil?.length ? h('div', { class: 'tags' }, c.exfil.map(e => h('span', { class: 'tag bad' }, `${e.kind.replace(/_/g, ' ')}${e.host ? ' · ' + e.host : ''}${e.bot ? ' · bot ' + e.bot : ''}`))) : null],
          [T('dCloak'), c.cloaking?.verdict === 'cloaked' ? T('dCloakText') : null], [T('dUrl'), h('code', {}, c.finalUrl)], [L({en:'Browser HTTP status',ar:'حالة HTTP للمتصفح'}), c.browserStatus],
          [L({en:'Independent HTTP response',ar:'الاستجابة المستقلة لطلب HTTP'}), c.redirectObservation ? String(c.redirectObservation.status ?? '—') : null],
          [L({en:'Advertised redirect destination',ar:'وجهة إعادة التوجيه المعلنة'}), c.redirectObservation?.destination ? h('code', {}, c.redirectObservation.destination) : null], [T('dTitle'), c.title], [T('dChain'), c.chain?.length > 1 ? h('code', {}, c.chain.join(' → ')) : null],
          [T('dFirst'), `${(c.firstSeen || '').slice(0, 16).replace('T', ' ')} UTC`], [T('dSource'), T('src_' + c.source)]])),
        sec(T('dInfra'), inf.registrar || inf.ip || inf.created ? kv([[T('dRegistrar'), inf.registrar], [T('dCreated'), (inf.created || '').slice(0, 10)], [T('dServer'), inf.ip ? `${inf.ip}${inf.asName ? ` · ${inf.asName}` : ''}${inf.asn ? ` (AS${inf.asn})` : ''}${inf.country ? ` · ${inf.country}` : ''}` : null],
          [T('dAbuse'), [inf.abuseEmail, inf.hostAbuse].filter(Boolean).join(' · ')]]) : null),
        D.campaign ? sec(`${T('dCamp')} · ${D.campaign.id}`, h('ul', { class: 'why', style: 'margin-bottom:8px' }, [...new Map(D.campaign.links.map(l => [l.why + l.value, l])).values()].slice(0, 5).map(l => h('li', { style: 'grid-template-columns:1fr' }, h('span', {}, L(l) + ': ', h('code', {}, l.value))))),
          h('div', { class: 'tags' }, D.campaign.members.filter(m => m.id !== c.id).map(m => h('button', { class: `tag ${verdictTone(m.verdict)}`, type: 'button', onclick: () => openCase(m.id) }, m.host)))) : null,
        sec(T('dReports'), h('p', { class: 'small muted', style: 'margin-bottom:8px' }, T('dReportsHelp')), Object.entries(D.reports || {}).filter(([, v]) => v).map(([k, v]) => h('details', { class: 'report' }, h('summary', {}, T('rp_' + k)),
          h('textarea', { class: 'field', rows: 9, readonly: true, value: v }), h('button', { class: 'btn sm', type: 'button', style: 'margin-top:8px', onclick: () => copyText(v) }, ic('copy'), T('copy')))))),
      h('div', { class: 'drawer-foot' },
        h('a', { class: `btn sm${approved ? ' primary' : ''}`, download: `veto-evidence-${c.id}.zip`, href: `/api/case/${c.id}/evidence.zip` }, ic('download'), T('dlZip')), h('a', { class: 'btn sm', href: `/api/case/${c.id}/evidence.pdf`, target: '_blank', rel: 'noopener' }, ic('file-text'), T('dlPdf')),
        h('a', { class: 'btn sm', href: `/api/case/${c.id}/stix`, target: '_blank', rel: 'noopener' }, ic('share-2'), T('dlStix')), h('a', { class: 'btn sm', href: `/api/dossier/${c.id}`, target: '_blank', rel: 'noopener' }, ic('external-link'), T('dlPack')))
    ];
  }
  const keep = overlay.querySelector('.drawer-body')?.scrollTop || 0;
  const active = document.activeElement?.id;
  overlay.replaceChildren(h('div', { class: 'scrim', onclick: closeDrawer }), h('aside', { class: 'drawer', role: 'dialog', 'aria-modal': 'true' }, inner));
  const body = overlay.querySelector('.drawer-body'); if (body) body.scrollTop = keep;
  if (active) document.getElementById(active)?.focus();
}
document.addEventListener('keydown', e => { if (e.key === 'Escape' && S.drawer) closeDrawer(); });

// ---------------- frame ----------------
function gate() {
  const ses = S.session || {};
  return h('div', { class: 'gate' }, h('form', { class: 'card', onsubmit: signIn },
    h('img', { class: 'officer-mark', src: '/brand/officer-kiki.png', alt: '' }), h('h1', {}, T('gateTitle')),
    ses.codeConfigured === false ? h('p', { class: 'err' }, T('notConfigured')) : [h('p', {}, T('gateText')),
      h('label', { class: 'lbl' }, T('code'), h('input', { id: 'codeIn', class: 'field', type: 'password', autocomplete: 'current-password', required: true, value: S.gateCode, oninput: e => { S.gateCode = e.target.value; } })),
      S.gateErr ? h('p', { class: 'err', role: 'alert' }, T(S.gateErr)) : null, h('button', { class: 'btn blue', type: 'submit' }, ic('lock'), T('enter'))],
    h('p', { class: 'tiny' }, T('gatePilot')), h('div', { class: 'row' }, langBtn())));
}
function render() {
  setLang(lang.cur);
  if (!S.session) return;
  if (!S.session.ok) { root.replaceChildren(gate()); return; }
  const d = S.data;
  if (!d) { root.replaceChildren(h('div', { class: 'gate' }, h('div', { class: 'card' }, h('p', {}, S.loadErr ? T('loadErr') : '…')))); return; }
  const active = document.activeElement, keepId = active?.id, pos = active && 'selectionStart' in active ? active.selectionStart : null;
  const waitingN = d.cases.filter(waiting).length;
  const views = { overview: overviewView, hunt: huntView, cases: casesView, campaigns: campaignsView, tools: toolsView, audit: auditView };
  const [, titleKey] = VIEWS.find(v => v[0] === S.view) || VIEWS[0];
  const subKey = 's' + S.view[0].toUpperCase() + S.view.slice(1);
  root.replaceChildren(h('div', { class: 'shell' },
    h('aside', { class: 'side' }, brand(),
      h('nav', { 'aria-label': T('brandSub') }, VIEWS.map(([id, key, ico]) => h('button', { type: 'button', 'aria-current': S.view === id ? 'page' : null, onclick: () => go(id) }, ic(ico), h('span', { class: 't' }, T(key)),
        id === 'cases' && waitingN ? h('span', { class: 'count' }, waitingN) : null))),
      h('div', { class: 'foot' },
        S.session.mode === 'code' ? h('button', { type: 'button', onclick: signOut }, ic('lock'), T('signOut')) : null)),
    h('main', { class: 'main' },
      h('div', { class: 'mobile-top' }, h('a', { class: 'brand', href: '/' }, h('img', { class: 'mark', src: '/brand/officer-kiki.png', alt: 'Veto.ai', width: 36, height: 36 }), h('b', {}, T('brandSub'))), langBtn()),
      h('div', { class: 'bar' }, h('h1', {}, T(titleKey)), h('span', { class: 'live-dot' }, T('live')), h('span', { class: 'grow' }),
        h('button', { class: 'btn sm', type: 'button', onclick: () => (S.view === 'audit' ? loadAudit() : loadData()) }, ic('refresh-cw'), T('refresh')), h('span', { class: 'desk-lang' }, langBtn()),
        h('p', { class: 'sub' }, T(subKey))),
      S.loadErr ? h('div', { class: 'notice bad' }, ic('wifi-off'), T('loadErr')) : null,
      (views[S.view] || overviewView)(d))));
  if (keepId) { const el = document.getElementById(keepId); if (el) { el.focus(); if (pos != null && el.setSelectionRange) try { el.setSelectionRange(pos, pos); } catch { /* not a text field */ } } }
}

(async function init() {
  const v = location.hash.slice(1);
  if (VIEWS.some(x => x[0] === v)) S.view = v;
  setLang(lang.cur);
  await loadSession();
  render();
  fetch('/data/web-verification-2026-11-25.json').then(r => r.json()).then(({results}) => {
    const positive = results.filter(r => r.label === '1');
    const negative = results.filter(r => r.label === '0');
    const tp = positive.filter(r => r.verdict === 'phishing').length;
    const fp = negative.filter(r => r.verdict === 'phishing').length;
    const rate = (n, total) => total ? pct(n / total) : '—';
    S.validationCounts = {
      en: `${tp} of ${positive.length} phishing URLs flagged; ${positive.length - tp} missed. False alarms on legitimate URLs: ${fp} of ${negative.length}.`,
      ar: `رُصد ${tp} من أصل ${positive.length} روابط تصيد، وفات الكشف عن ${positive.length - tp}. الإنذارات الخاطئة على الروابط السليمة: ${fp} من ${negative.length}.`
    };
    S.validation = [['precision', rate(tp, tp + fp)], ['recall', rate(tp, positive.length)], ['falseAlarms', rate(fp, negative.length)]];
    render();
  }).catch(() => {});
  fetch('/data/ct-history/ct-watch-report-run4.json').then(r => r.json()).then(j => { S.ct = j; render(); }).catch(() => {});
  if (S.session.ok) { await loadData(); if (S.view === 'audit') loadAudit(); }
})();
