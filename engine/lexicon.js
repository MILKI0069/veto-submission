// Veto lexicon: what scammers ASK FOR (actions) and HOW they pressure (tactics).
// Patterns run on matchForm() text (lower-case, Arabic-normalised, look-alike letters folded),
// so Arabic sources are normalised with the same function before compiling.
// English + Arabic (Gulf/MSA) + common romanised Hindi/Urdu and Tagalog phrases.

import { normalizeArabic } from './normalize.js';

// Detection text has in-word dots ("noon.com", "250.00", "o.t.p") replaced by "·" so that
// sentence windows are not cut by domains or amounts; patterns that need a dot use DOT.
export const protectDots = s => s.replace(/(?<=[\p{L}\p{N}])\.(?=[\p{L}\p{N}])/gu, '·');
const DOT = '[.·]';
const SEP = String.raw`(?:^|[\s,.:;!?()"'«»\-])`;
const END = String.raw`(?=$|[\s,.:;!?()"'«»\-])`;
const W = String.raw`[^.!?\n]`; // "same sentence" character

export const rx = (parts, flags = 'giu') =>
  new RegExp(normalizeArabic(Array.isArray(parts) ? parts.join('|') : parts), flags);

// ---------- objects ----------
const OTP = [
  String.raw`\botp\b`, String.raw`\bo${DOT}\s?t${DOT}\s?p\b`, String.raw`\bo t p\b`,
  String.raw`\bone[\s-]?time[\s-]?(?:password|passcode|code|pin)\b`,
  String.raw`\b(?:verification|confirmation|activation|authentication|authori[sz]ation|sms|login|access|whatsapp|telegram|security) code\b`,
  String.raw`\b(?:4|5|6|8|four|five|six|eight)[\s-]?digits?(?: code| number| pin)?\b`,
  String.raw`\bthe code (?:you|we|i) (?:just )?(?:got|received|sent|get)\b`,
  String.raw`\bpasscode\b`, String.raw`\bthe code\b`, String.raw`\bthat code\b`, String.raw`\bthis code\b`,
  String.raw`\bverification (?:sms|message|text)\b`, String.raw`\bthe (?:number|digits) (?:in|from) the (?:sms|message|text)\b`,
  'رمز التحقق', 'رمز التفعيل', 'رمز otp', 'كود التحقق', 'الكود', 'رمز المرور', 'رقم التحقق',
  'كلمة المرور لمرة واحدة', 'الرمز', 'الكود اللي وصلك', 'الرقم اللي وصلك'
];
const PIN = [
  String.raw`\b(?:atm |card |debit card |credit card )?pin(?: code| number)?\b`,
  'الرقم السري', 'رقم سري', 'رمز pin', 'الرمز السري', 'رقم التعريف الشخصي'
];
const CVV = [
  String.raw`\bcvv2?\b`, String.raw`\bcvc2?\b`, String.raw`\bcv2\b`,
  String.raw`\b(?:3|three)[\s-]?digits? (?:code |number )?(?:on|at|from) the back\b`,
  String.raw`\bsecurity code (?:on|at) the back\b`, String.raw`\bcard verification (?:value|code)\b`,
  'الرمز الامني', 'رمز الامان', 'رمز cvv', 'الارقام الثلاثة', 'الثلاث ارقام'
];
const CARD = [
  String.raw`\b(?:full |complete |16[\s-]?digit )?card (?:number|no\.?|details|info(?:rmation)?|num)\b`,
  String.raw`\bcard\s?(?:expiry|expiration)\b`, String.raw`\bexpiry date\b`, String.raw`\bexpiration date\b`,
  'رقم البطاقة', 'بيانات البطاقة', 'تفاصيل البطاقة', 'تاريخ الانتهاء', 'تاريخ انتهاء البطاقة'
];
const PASSWORD = [
  String.raw`\b(?:online banking |mobile banking |internet banking |login |account )?(?:password|passwd)\b`,
  String.raw`\blog[\s-]?in (?:details|credentials|info)\b`, String.raw`\busername and password\b`,
  String.raw`\bcredentials\b`, 'كلمة المرور(?! لمرة)', 'كلمة السر', 'بيانات الدخول', 'اسم المستخدم'
];
const EID = [
  String.raw`\bemirates ?id\b`, String.raw`\beid\b`, String.raw`\bid card\b`, String.raw`\bpassport\b`,
  String.raw`\bvisa copy\b`, 'الهوية', 'بطاقة الهوية', 'جواز السفر', 'صورة الاقامة'
];

// ---------- verbs ----------
// Give something TO a person (never matches "we will send you an OTP").
const GIVE = [
  String.raw`\b(?:share|give|tell|read|provide|forward|dictate|spell|say|repeat|write)\b(?! you\b)`,
  String.raw`(?<!(?:\bwe|\bwill|\bwe'll|\bi'll|\bbeen|\bbe|\bshall|\bhas|\bhave)\s)\bsend (?:me|us|it|them|the|this|that|your|those|back|over)\b`,
  String.raw`\b(?:text|whatsapp|sms) (?:me|us|it|the|that|this)\b`,
  String.raw`\breply with\b`, String.raw`\bask(?:ing|ed)? (?:you )?for\b`,
  String.raw`\b(?:i|we) (?:just |urgently )?(?:need|require)\b`, String.raw`\bwhat(?:'s| is) (?:the|your)\b`,
  String.raw`\bconfirm (?:it|them|the|your)\b${W}{0,25}\b(?:to|with) (?:me|us)\b`,
  String.raw`\b(?:batao|bata do|bhejo|bhej do|de do|bolo|likho|share karo|send karo|ibigay|ipadala|sabihin)\b`,
  `${SEP}(?:ارسل|ابعث|ابعت|شارك|اعطني|اعطيني|عطني|عطنا|اعطنا|زودني|زودنا|قل|قولي|اخبرني|خبرني|اقرا|اكتب|هات|نحتاج|نبي|ابي|اريد|ابغي|ابغى|ترسل|تبعث|تبعت|تعطيني|تقرا|تقول|تشارك|تزودني|تخبرني|تكتب)(?:ه|ها|ي|لي|ني)?${END}`
];
// Arabic requests often use a noun after "please": «يرجى إرسال الرمز», «والموافقة عليها».
const AR_NOUN_REQUEST = `(?:(?:يرجى|رجاء|الرجاء|من فضلك|ممكن|لازم|عليك|نحتاج|اريد|ابي|ابغى|قم ب)\\s?(?:ال)?|${SEP}و)(?:ارسال|مشاركة|اعطاء|تزويدنا|تزويدي|قراءة|الموافقة|موافقة)`;
GIVE.push(AR_NOUN_REQUEST);
// Give OR type it somewhere (used for card / password / PIN / CVV, never for OTP).
const GIVE_OR_ENTER = [
  ...GIVE,
  String.raw`\b(?:enter|type|fill(?: in)?|submit|update|input|key in|confirm|verify|validate)\b`,
  `${SEP}(?:ادخل|اكتب|حدث|اكد)${END}`
];
const SEND_DOC = [
  String.raw`\b(?:send|share|upload|attach|provide|forward|whatsapp|submit|scan|snap)\b(?! you\b)`,
  String.raw`\btake a (?:photo|picture|selfie)\b`,
  `${SEP}(?:ارسل|ابعث|ابعت|صور|ارفق|ارفع|حمل|شارك)(?:ه|ها|ي|لي)?${END}`
];
const INSTALL = [
  String.raw`\b(?:install|download|open|get|use|run|launch|allow)\b`,
  String.raw`\b(?:give|tell|share|read|send)\b${W}{0,20}\b(?:id|code|address|number)\b`,
  String.raw`\b(?:9|nine|10|ten)[\s-]?digits?\b`,
  `${SEP}(?:حمل|نزل|ثبت|افتح|شغل|استخدم|تحميل|تنزيل|تثبيت)(?:ه|ي)?${END}`
];
const PAY = [String.raw`\b(?:pay|settle|transfer|send|deposit|clear)\b`, `${SEP}(?:ادفع|سدد|حول|دفع|سداد|تحويل)${END}`];
const MOVE_MONEY = [String.raw`\b(?:transfer|move|send|deposit|shift|put|wire|keep)\b`, `${SEP}(?:حول|انقل|ارسل|اودع|تحويل|نقل|تحول|تنقل|ترسل|تودع|نحول|بنحول|سنحول|بنقل|ننقل|سننقل)(?:ه|ها|ي)?${END}`];

// ---------- ACTIONS: things a legitimate institution would never ask for ----------
export const ACTIONS = {
  share_otp: {
    label: { en: 'share a one-time code (OTP)', ar: 'مشاركة رمز التحقق (OTP)' },
    objects: rx(OTP), verbs: rx(GIVE),
    direct: rx([
      String.raw`\b(?:read|tell|give|send|forward|text|whatsapp) (?:me|us)\b${W}{0,25}\b(?:otp|codes?|digits|pin)\b`,
      String.raw`\b(?:read|tell|give|send|forward|text|whatsapp) (?:me|us)\b${W}{0,25}\bnumbers? (?:that |which )?(?:you|u) (?:just )?(?:got|received|get)\b`,
      String.raw`\bwhat(?:'s| is) the (?:otp|code|number|pin)\b${W}{0,20}\b(?:got|received|get)\b`,
      String.raw`\b(?:i|we|someone) (?:\w+ ){0,2}(?:sent|send) (?:you |a |my |the )?(?:\w+ ){0,3}code\b${W}{0,30}\b(?:mistake|accident|wrong number|error|mistakenly)\b`,
      String.raw`\bcode (?:by mistake|by accident|mistakenly)\b`,
      String.raw`\b(?:accidentally|mistakenly|wrongly|by mistake|by accident)\b${W}{0,40}\bcode\b`,
      String.raw`\b(?:otp|code) (?:batao|bata do|bhejo|bhej do|de do|bolo|likho|share karo|send karo)\b`,
      String.raw`\b(?:ibigay|ipadala|sabihin) (?:mo )?(?:ang|yung|ung) (?:otp|code)\b`,
      '(?:ما هو|ايش|شو|وش|كم) (?:الرمز|الكود|رمز التحقق)',
      'ارسلت (?:لك |لرقمك )?(?:رمز|كود)[^.\\n]{0,30}(?:بالخطا|بالغلط|خطا)',
      '(?:اعطني|عطني|اعطيني|زودني|ابعث لي|ارسل لي|ابعتلي|قول لي|قولي|اقرا لي|اقرالي) (?:الرمز|الكود|رمز التحقق|رمز otp|otp)'
    ])
  },
  share_pin: { label: { en: 'share your card PIN', ar: 'مشاركة الرقم السري (PIN)' }, objects: rx(PIN), verbs: rx(GIVE_OR_ENTER) },
  share_cvv: { label: { en: "share your card's CVV", ar: 'مشاركة رمز الأمان CVV' }, objects: rx(CVV), verbs: rx(GIVE_OR_ENTER) },
  share_card: {
    label: { en: 'share your full card number or expiry date', ar: 'مشاركة رقم البطاقة أو تاريخ انتهائها' }, objects: rx(CARD), verbs: rx(GIVE_OR_ENTER),
    // Banks DO legitimately ask you to confirm the last 4 digits on calls you started, not a violation.
    except: rx([String.raw`\blast (?:4|four) digits\b`, String.raw`\bending (?:in|with)\b`, 'اخر (?:4|اربعة|اربع) ارقام'], 'iu')
  },
  share_password: { label: { en: 'share your online-banking password', ar: 'مشاركة كلمة مرور الخدمات المصرفية' }, objects: rx(PASSWORD), verbs: rx(GIVE_OR_ENTER) },
  share_eid: {
    label: { en: 'send a photo or number of your Emirates ID / passport', ar: 'إرسال صورة أو رقم الهوية أو الجواز' },
    objects: rx(EID), verbs: rx(SEND_DOC)
  },
  approve_app_prompt: {
    label: { en: 'approve a request in your banking app', ar: 'الموافقة على طلب في تطبيق البنك' },
    direct: rx([
      String.raw`\b(?:approve|accept|confirm|allow|authori[sz]e|press (?:yes|approve|accept|confirm)|tap (?:yes|approve|accept|confirm)|click (?:yes|approve|accept|confirm))\b${W}{0,40}\b(?:notification|request|prompt|pop[\s-]?up|push|transaction|login)\b${W}{0,30}\b(?:app|application)\b`,
      String.raw`\b(?:approve|accept|confirm) (?:it|this|that) (?:in|on|from|through) (?:your|the) (?:banking |bank |mobile )?app\b`,
      String.raw`(?:وافق|اقبل) علي (?:الطلب|الاشعار)${W}{0,45}(?:نوقف|نلغي|نمنع) (?:دخول|عملية|محاولة)`,
      '(?:وافق|اضغط على موافق|اضغط موافق|اقبل|اكد)[^.\\n]{0,30}(?:الاشعار|الطلب|التنبيه)[^.\\n]{0,25}التطبيق'
    ])
  },
  approve_uaepass: {
    label: { en: 'approve a UAE PASS request or share its code', ar: 'الموافقة على طلب UAE PASS أو مشاركة رمزه' },
    objects: rx([String.raw`\buae ?pass\b`, String.raw`\buaepass\b`, 'يو اي اي باس', 'الهوية الرقمية', 'uae باس']),
    verbs: rx([
      String.raw`\b(?:approve|accept|confirm|allow|press|tap|click|sign|share|give|tell|read|forward)\b(?! you\b)`,
      String.raw`(?<!(?:\bwe|\bwill|\bbeen|\bbe)\s)\bsend (?:me|us|it|the|that|this)\b`,
      `${SEP}(?:وافق|اقبل|اضغط|ارسل|اعطني|شارك|اقرا|ابعث|زودني|اكد)(?:ه|ها|ي|لي)?${END}`,
      AR_NOUN_REQUEST
    ])
  },
  install_remote: {
    label: { en: 'install a remote-control app (e.g. AnyDesk)', ar: 'تثبيت تطبيق تحكم عن بُعد (مثل AnyDesk)' },
    objects: rx([
      String.raw`\bany ?desk\b`, String.raw`\bteam ?viewer\b`, String.raw`\brust ?desk\b`, String.raw`\bquick ?support\b`,
      String.raw`\bair ?droid\b`, String.raw`\bultra ?viewer\b`, String.raw`\bzoho assist\b`, String.raw`\bsupremo\b`,
      String.raw`\bsplashtop\b`, String.raw`\bscreen ?connect\b`, String.raw`\bconnectwise\b`,
      String.raw`\bremote[\s-]?(?:access|control|desktop|support|assistance)(?: app| application| software| tool| program)?\b`,
      'تطبيق (?:تحكم|التحكم) عن بعد', 'برنامج (?:تحكم|التحكم) عن بعد', 'اني ?ديسك', 'تيم ?فيور', 'تيم ?فيوير'
    ]),
    verbs: rx(INSTALL)
  },
  share_screen: {
    label: { en: 'share your screen', ar: 'مشاركة الشاشة' },
    direct: rx([String.raw`\bshare (?:your |the )?(?:phone |mobile )?screen\b`, String.raw`\bscreen[\s-]?shar(?:e|ing)\b`, 'مشاركة الشاشة', 'شارك (?:الشاشة|شاشتك)'])
  },
  install_apk: {
    label: { en: 'install an app from a link instead of the official store', ar: 'تثبيت تطبيق من رابط بدلاً من المتجر الرسمي' },
    direct: rx([
      String.raw`${DOT}apk\b`, String.raw`\bapk\b`,
      String.raw`\b(?:install|download) (?:this |the |our )?(?:new |updated |secure |latest )?(?:app|application|version)\b${W}{0,30}\b(?:link|below|here|url)\b`,
      '(?:حمل|نزل|ثبت) التطبيق (?:من|عبر) الرابط', 'تحميل التطبيق (?:من|عبر) الرابط'
    ])
  },
  click_update_link: {
    label: { en: 'update or "verify" your details through a link', ar: 'تحديث بياناتك أو «تأكيدها» عبر رابط' },
    direct: rx([
      String.raw`\b(?:click|tap|visit|open|follow|go to|press|use (?:the|this) link)\b${W}{0,40}\bto (?:update|verify|confirm|reactivate|unblock|unlock|restore|validate|avoid|claim|pay|redeliver|reschedule|activate|receive|collect|release|cancel|stop)\b`,
      String.raw`\b(?:update|verify|confirm|validate|reactivate|unblock|unlock|restore|complete)\b (?:your )?(?:details|information|info|account|kyc|emirates id|eid|card|profile|data|identity|records?|address)\b${W}{0,40}(?:link|here|below|https?:|www\.|via|through|at )`,
      String.raw`\b(?:log ?in|sign ?in)\b${W}{0,25}(?:https?:|www[.·]|\bhere\b|\blink\b|\bbelow\b|[a-z0-9-]+[.·][a-z]{2,})`,
      String.raw`\b(?:verify|confirm|validate|review|check)\b${W}{0,30}\b(?:payment|transaction|activity|delivery|settlement|address|identity|information|info|details|item|order|parcel|package)\b${W}{0,40}(?:https?:|www[.·]|\blink\b|\bhere\b|\bbelow\b|[a-z0-9-]+[.·][a-z]{2,}\/)`,
      String.raw`\bverification (?:form|page|link)\b`, String.raw`\b(?:follow|open|use|click)\b${W}{0,10}\b(?:link|url|form)\b`,
      '(?:اضغط|انقر|ادخل) على الرابط', '(?:عبر|من خلال) الرابط', 'الرابط (?:التالي|ادناه|المرفق)'
    ])
  },
  pay_fee: {
    label: { en: 'pay a fee to release a parcel, prize, job or account', ar: 'دفع رسوم للإفراج عن طرد أو جائزة أو وظيفة أو حساب' },
    objects: rx([
      String.raw`\b(?:redelivery|re-delivery|delivery|customs|clearance|release|processing|registration|activation|unlock(?:ing)?|unfreez(?:e|ing)|handling|verification|admin(?:istration)?|insurance|shipping|reschedul(?:e|ing)|visa processing|agent)\s?(?:fee|fees|charge|charges|cost|payment)\b`,
      String.raw`\b(?:fee|charge) of (?:aed|dhs?|usd|\$)`,
      'رسوم (?:التوصيل|الجمارك|التخليص|الشحن|الاستلام|التفعيل|المعالجة|المعاملة|الغاء البلاغ|الافراج|التسجيل|اعادة التوصيل|الفيزا)'
    ]),
    verbs: rx(PAY)
  },
  transfer_safe_account: {
    label: { en: 'move your money to a "safe" account', ar: 'نقل أموالك إلى «حساب آمن»' },
    objects: rx([
      String.raw`\b(?:safe|secure|secured|protected|temporary|holding|verification|government|central bank|escrow|investigation|clean|safety)\s(?:bank\s)?account\b`,
      'حساب (?:امن|امان|مؤقت|حكومي|التحقيق|الحماية)'
    ]),
    verbs: rx(MOVE_MONEY)
  },
  add_beneficiary: {
    label: { en: 'add a new beneficiary because someone told you to', ar: 'إضافة مستفيد جديد بطلب من شخص آخر' },
    direct: rx([
      String.raw`\b(?:please |kindly |you (?:need|have) to |you must |i need you to |we need you to |just )add (?:a |the |this |my |our |him |me )?(?:new )?(?:beneficiary|payee)\b`,
      String.raw`\badd (?:him|me|us|this (?:account|person|number)) as (?:a )?(?:beneficiary|payee)\b`,
      '(?:اضف|ضيف|سجل)[^.\\n]{0,15}(?:كمستفيد|مستفيد)'
    ])
  },
  pay_giftcard: {
    label: { en: 'pay with gift cards or vouchers', ar: 'الدفع ببطاقات الهدايا أو القسائم' },
    direct: rx([
      String.raw`\b(?:pay|settle|clear)\b${W}{0,40}\b(?:with|using|via|in|through|by)\b${W}{0,20}(?:gift ?cards?|vouchers?|itunes|google play|steam|razer)`,
      String.raw`\b(?:buy|purchase|get)\b${W}{0,30}(?:gift ?cards?|itunes cards?|google play cards?|steam cards?|razer gold)${W}{0,60}\b(?:send|share|scratch|give|text|whatsapp|read)\b`,
      String.raw`\b(?:send|share|give|read|text|whatsapp) (?:me|us) (?:the )?(?:gift ?card|card|voucher) (?:codes?|numbers?|pins?)\b`,
      '(?:ادفع|سدد)[^.\\n]{0,30}(?:ببطاقات? هدايا|بطاقة جوجل|بطاقات ايتونز|قسائم)',
      '(?:اشتر|اشتري)[^.\\n]{0,30}بطاقات? (?:هدايا|جوجل بلاي|ايتونز)'
    ])
  },
  pay_crypto: {
    label: { en: 'pay or deposit in cryptocurrency', ar: 'الدفع أو الإيداع بالعملات المشفرة' },
    direct: rx([
      String.raw`\b(?:pay|deposit|send|transfer|top[\s-]?up|recharge|invest|fund)\b${W}{0,40}\b(?:usdt|tether|bitcoin|btc|eth|ethereum|crypto(?:currency)?|binance|trc[\s-]?20|erc[\s-]?20|bep[\s-]?20|wallet address)\b`,
      String.raw`\b(?:usdt|btc|bitcoin)\b${W}{0,20}\b(?:deposit|payment|transfer)\b`,
      '(?:ادفع|اودع|حول|ارسل|استثمر)[^.\\n]{0,40}(?:usdt|بيتكوين|عملات? رقمية|عملة مشفرة|كريبتو|بينانس)'
    ])
  },
  keep_secret: {
    label: { en: 'keep it secret from your bank or family', ar: 'إخفاء الأمر عن البنك أو العائلة' },
    noNegationCheck: true,
    direct: rx([
      String.raw`\b(?:don'?t|do not|never|dont)\s(?:tell|inform|let|mention (?:this |it )?to|involve|discuss (?:this |it )?with)\b${W}{0,20}\b(?:anyone|anybody|your (?:family|bank|husband|wife|dad|mom|mum|mother|father|friends?|relatives|branch|manager|son|daughter)|the bank|bank staff|police|dad|mum|mom|mama|papa)\b(?!${W}{0,30}(?:otp|pin|password|code|cvv|card|details|رمز))`,
      String.raw`\bkeep (?:this|it|everything|the matter|our conversation) (?:a )?(?:secret|confidential|private|between us)\b`,
      String.raw`\b(?:this|the) (?:call|conversation|matter|case|investigation) is (?:strictly )?(?:confidential|secret|classified)\b`,
      '(?:لا|ما) (?:تخبر|تقل|تبلغ|تقول|تعلم|تعلّم)[^.\\n]{0,15}(?:احد|البنك|عائلتك|اهلك|زوجك|زوجتك|الشرطة|ابوك|امك)',
      '(?:خلي|اجعل) (?:الموضوع|الامر|الكلام) (?:سر|سري|بيننا)', 'سري للغاية', 'المكالمة سرية'
    ])
  },
  move_channel: {
    label: { en: 'move the chat to WhatsApp or Telegram', ar: 'نقل المحادثة إلى واتساب أو تيليجرام' },
    direct: rx([
      String.raw`\b(?:contact|message|text|chat|reach|add|join|dm)\b${W}{0,25}\b(?:on|via|through|at|in)\b${W}{0,10}\b(?:whatsapp|telegram|signal|wechat)\b`,
      String.raw`\bwa${DOT}me\/`, String.raw`\bt${DOT}me\/`, String.raw`\bchat${DOT}whatsapp${DOT}com\b`, String.raw`\btelegram (?:group|channel)\b`,
      '(?:تواصل|راسل|كلمنا|اضفنا|انضم)[^.\\n]{0,25}(?:واتساب|واتس|تيليجرام|تلغرام|تليجرام)'
    ])
  },
  send_money_urgent: {
    label: { en: 'send money to them', ar: 'إرسال المال إليهم' },
    direct: rx([
      String.raw`\b(?:send|transfer|lend|wire|give) (?:me|us)\b${W}{0,30}(?:money|cash|funds|amount|aed|dhs?|dirhams?|usd|\$|\d)`,
      String.raw`\bi (?:urgently |really )?need (?:some )?(?:money|cash|aed ?\d|dhs? ?\d|\d)`,
      String.raw`\bi need you to (?:send|transfer|pay|wire)\b`,
      String.raw`\b(?:send|transfer|wire|pay) (?:aed |dhs? |\$)?\d[\d,]*(?:\.\d+)? ?(?:aed|dhs?|dirhams?)? (?:to|into) (?:my|this|the following|his|her|our)\b`,
      '(?:حول|ارسل|ابعث|ابعت) (?:لي|لنا)[^.\\n]{0,30}(?:فلوس|مبلغ|درهم|\\d)', 'سلفني', 'محتاج فلوس', 'احتاج مبلغ'
    ])
  }
};

// Phrases that show a legitimate "if this wasn't you" safety instruction.
export const SAFETY_PHRASES = rx([
  String.raw`\bif (?:you )?(?:did ?n[o']?t|didn't|have not|haven't|never) (?:request|initiate|start|make|attempt|try)`,
  String.raw`\bif this (?:was ?n[o']?t|wasn't|is not|isn't) you\b`, String.raw`\breject (?:it|this|the request)\b`,
  'اذا لم تقم', 'اذا لم يكن انت', 'ارفض الطلب'
]);

// ---------- TACTICS: how the message pressures you ----------
export const TACTICS = {
  urgency: {
    label: { en: 'Creates urgency', ar: 'يستعجلك' },
    re: rx([
      String.raw`\burgent(?:ly)?\b`, String.raw`\bimmediately\b`, String.raw`\bright now\b`, String.raw`\basap\b`,
      String.raw`\bwithin (?:the next )?\d+ ?(?:hours?|hrs?|minutes?|mins?)\b`, String.raw`\btoday only\b`, String.raw`\blast chance\b`,
      String.raw`\bfinal (?:notice|warning|reminder)\b`, String.raw`\bexpires? (?:today|tonight|soon|in \d+)\b`, String.raw`\bact now\b`,
      String.raw`\bbefore midnight\b`, String.raw`\bjaldi\b`, 'عاجل', 'فورا', 'حالا', 'خلال \\d+ ساع', 'اليوم فقط', 'اخر فرصة', 'تنبيه نهائي', 'بسرعة'
    ])
  },
  threat_block: {
    label: { en: 'Threatens to block your account or card', ar: 'يهدد بإيقاف حسابك أو بطاقتك' },
    re: rx([
      String.raw`\b(?:account|card|line|sim|number|service|wallet|emirates id|visa|uae ?pass|profile|access|internet)s?\b${W}{0,20}\b(?:will be|has been|have been|is|was|got|are|being)\b${W}{0,16}\b(?:blocked|suspended|frozen|closed|deactivated|terminated|locked|restricted|cancell?ed|disabled|on hold|barred|cut|disconnected)\b`,
      String.raw`\b(?:access|account)[\s-]?(?:locked|restricted|limited|suspended|disabled|on hold)\b`, String.raw`\brestricted account\b`,
      String.raw`\b(?:we will|we'll|we have to|we had to)\s(?:close|lock|suspend|block|restrict|disable)\w*${W}{0,15}\baccount\b`,
      String.raw`\bpayment (?:failed|declined|unsuccessful)\b`,
      String.raw`\bblock ho jayega\b`, String.raw`\bband ho jayega\b`,
      '(?:سيتم|تم|سوف يتم)[^.\\n]{0,10}(?:ايقاف|تجميد|اغلاق|تعطيل|الغاء|حظر|تعليق)'
    ])
  },
  threat_legal: {
    label: { en: 'Threatens arrest, court or deportation', ar: 'يهدد بالقبض أو المحكمة أو الترحيل' },
    re: rx([
      String.raw`\barrest(?:ed)?\b`, String.raw`\bwarrant\b`, String.raw`\blegal action\b`, String.raw`\b(?:police|criminal) case\b`,
      String.raw`\bcourt (?:case|summons|order)\b`, String.raw`\bmoney laundering\b`, String.raw`\bdeport(?:ed|ation)?\b`,
      String.raw`\btravel ban\b`, String.raw`\bprosecution\b`, String.raw`\bjail\b`, String.raw`\bimprison(?:ed|ment)?\b`,
      String.raw`\bblack ?list(?:ed)?\b`, 'غسيل اموال', 'غسل الاموال', 'قضية', 'القبض', 'يتم توقيفك', 'سيتم توقيفك', 'منع سفر', 'منع من السفر', 'ترحيل', 'السجن', 'النيابة', 'بلاغ ضدك'
    ])
  },
  prize: {
    label: { en: 'Promises a prize or reward', ar: 'يعدك بجائزة أو مكافأة' },
    re: rx([
      String.raw`\bcongratulations?\b`, String.raw`\bcongrats\b`, String.raw`\byou(?: have|'ve)? won\b`, String.raw`\bwinner\b`,
      String.raw`\blucky (?:draw|winner|number|customer)\b`, String.raw`\bclaim (?:your )?(?:prize|reward|gift|cash|winnings)\b`,
      String.raw`\bselected (?:as|for) (?:a |the )?(?:winner|reward|prize)\b`, String.raw`\braffle\b`, String.raw`\bjackpot\b`,
      String.raw`\bpoints? (?:will )?expire\b`, 'مبروك', 'ربحت', 'فزت', 'جائزة', 'الفائز', 'سحب على', 'نقاطك ستنتهي'
    ])
  },
  too_good: {
    label: { en: 'Promises returns that are too good to be true', ar: 'يعد بأرباح غير منطقية' },
    re: rx([
      String.raw`\bguaranteed (?:profit|returns?|income|earnings?|gains?)\b`, String.raw`\brisk[\s-]?free\b`, String.raw`\bno risk\b`,
      String.raw`\bdouble your (?:money|investment|capital)\b`, String.raw`\b\d+ ?% (?:daily|weekly|monthly|per (?:day|week|month)) (?:returns?|profits?|interest|gains?|income|roi)\b`,
      String.raw`\b(?:daily|weekly|monthly) (?:returns?|profits?) of \d+ ?%`, String.raw`\bpassive income\b`, String.raw`\b100 ?% (?:safe|secure|profit|guaranteed)\b`,
      'ارباح مضمونة', 'عائد مضمون', 'ربح مضمون', 'بدون مخاطرة', 'بدون مخاطر', 'ضعف المبلغ'
    ])
  },
  job_offer: {
    label: { en: 'Unsolicited job offer', ar: 'عرض عمل غير مطلوب' },
    re: rx([
      String.raw`\bpart[\s-]?time\b`, String.raw`\bwork from home\b`, String.raw`\bno experience (?:needed|required)\b`,
      String.raw`\b(?:we are|we're) hiring\b`, String.raw`\bjob offer\b`, String.raw`\boffer letter\b`, String.raw`\b(?:confirm|secure) your (?:position|job|seat)\b`,
      'عمل من المنزل', 'دوام جزئي', 'بدون خبرة', 'عرض عمل', 'عرض وظيفي'
    ])
  },
  job_task: {
    label: { en: 'Paid “tasks”, easy money for likes or reviews', ar: '«مهام» مدفوعة، ربح سهل مقابل الإعجابات أو التقييمات' },
    re: rx([
      String.raw`\bearn (?:up to )?(?:aed|dhs?|usd|\$)? ?\d[\d,\-\s]*(?:aed|dhs?|usd|\$)? ?(?:per|a|each|every) (?:day|hour|task|video)\b`,
      String.raw`\b(?:daily|per day) (?:income|salary|earnings?|pay|profit)\b`, String.raw`\bsimple (?:online )?tasks?\b`,
      String.raw`\b(?:like|liking|follow|following|subscribe|review|reviewing|rate|rating)\b${W}{0,15}\b(?:videos?|products?|hotels?|apps?|youtube|tiktok|posts?|channels?)\b`,
      String.raw`\b(?:complet(?:e|ed|ing)|finish(?:ed)?) (?:your |the )?tasks?\b`, String.raw`\bcommissions?\b`,
      'دخل يومي', 'مهام بسيطة', 'عمولة', 'مقابل كل مهمة', 'الاعجاب بالفيديوهات'
    ])
  },
  family_emergency: {
    label: { en: 'Claims to be family on a "new number"', ar: 'يدّعي أنه قريبك برقم جديد' },
    re: rx([
      String.raw`\b(?:this is|it'?s|its) my new (?:number|phone|whatsapp|no\.?)\b`, String.raw`\bnew number\b`,
      String.raw`\b(?:lost|broke|broken|dropped|changed|damaged) my (?:phone|mobile|sim|number)\b`, String.raw`\bmy phone (?:is )?(?:broken|lost|damaged)\b`,
      String.raw`\bgot a new (?:number|phone)\b`,
      'رقمي (?:الجديد|اليديد)', 'ضاع (?:تلفوني|جوالي|هاتفي)', 'انكسر (?:تلفوني|جوالي|هاتفي)'
    ])
  },
  family_greeting: {
    label: { en: 'Opens like a family member', ar: 'يبدأ كأنه من العائلة' },
    re: rx([String.raw`\b(?:hi|hello|hey|hii) (?:mum|mom|mama|mummy|mommy|dad|daddy|papa|baba|son|bro|sis)\b`, '(?:مرحبا|هلا|السلام عليكم) (?:ماما|بابا|يمه|يبه|امي|ابوي)'])
  },
  delivery_pretext: {
    label: { en: 'Parcel "problem" story', ar: 'قصة «مشكلة» في الطرد' },
    re: rx([
      String.raw`\b(?:parcel|package|shipment|item|delivery|courier)\b${W}{0,40}\b(?:on hold|held|could not be (?:delivered|shipped)|will not be shipped|unpaid|needs? your attention|lined up|redeliver\w*|incomplete address|customs)\b`,
      String.raw`\bconfirm (?:the )?(?:delivery|settlement|address|shipping)\b`,
      'طرد(?:ك)? (?:معلق|محتجز)', 'شحنتك معلقة', 'تعذر توصيل'
    ])
  },
  refund_bait: {
    label: { en: 'Offers a refund or compensation', ar: 'يعرض استرداد مبلغ أو تعويض' },
    re: rx([String.raw`\brefund\b`, String.raw`\boverpaid\b`, String.raw`\bovercharged\b`, String.raw`\bcompensation\b`, String.raw`\beligible for (?:a )?(?:refund|cashback|compensation)\b`, 'استرداد', 'تعويض', 'مبلغ مسترد'])
  },
  account_alert: {
    label: { en: 'Claims "suspicious activity" on your account', ar: 'يدّعي وجود «نشاط مشبوه» على حسابك' },
    re: rx([String.raw`\bunusual (?:activity|transaction|login|sign[\s-]?in|payment|charge)\b`, String.raw`\bsuspicious (?:activity|transaction|login|attempt|payment|charge|purchase)\b`, String.raw`\bunauthori[sz]ed (?:transaction|access|login|attempt|payment)\b`, 'عملية مشبوهة', 'نشاط غير معتاد', 'عملية غير مصرح'])
  },
  verification_pretext: {
    label: { en: 'Asks you to "verify" or "update" your details', ar: 'يطلب منك «تأكيد» أو «تحديث» بياناتك' },
    re: rx([
      String.raw`\b(?:verify|confirm|validate) (?:your )?(?:identity|account|details|information)\b`, String.raw`\bkyc\b`,
      String.raw`\b(?:update|complete) (?:your )?(?:details|information|kyc|profile|records?|emirates id)\b`,
      'تحديث (?:البيانات|بياناتك|الهوية)', 'تاكيد (?:هويتك|بياناتك)'
    ])
  },
  caller_pressure: {
    label: { en: 'Tells you not to hang up', ar: 'يطلب منك عدم إنهاء المكالمة' },
    re: rx([String.raw`\b(?:don'?t|do not) (?:hang up|disconnect|end the call|cut the call|put the phone down)\b`, String.raw`\bstay on the line\b`, 'لا تغلق الخط', 'لا تسكر', 'ابق على الخط', 'خليك معي على الخط'])
  },
  // ---- softer scams: no blunt "send the OTP", but a known script (20 Nov 2026) ----
  advance_fee: {
    label: { en: 'Inheritance / “unclaimed millions” story (advance-fee scam)', ar: 'قصة ميراث أو «ملايين غير مُطالب بها» (احتيال الرسوم المسبقة)' },
    re: rx([
      String.raw`\bnext of kin\b`, String.raw`\bunclaimed (?:funds?|deposits?|inheritance|estate|sum|money)\b`,
      String.raw`\b(?:inheritance|estate|fund|sum) of (?:us\$|usd|\$|£|€|gbp|eur)?\s?\d[\d,.]*\s?(?:million|m)\b`,
      String.raw`\b\d[\d,.]*\s?million (?:dollars|usd|us dollars|pounds|euros)\b`,
      String.raw`\b(?:consignment|trunk|diplomatic) box\b`, String.raw`\bdiplomatic (?:courier|agent)\b`,
      String.raw`\bdeceased (?:client|customer|business ?man|father|husband)\b`, String.raw`\bnigerian? prince\b`,
      String.raw`\b(?:un|united nations|world bank|imf) compensation\b`, String.raw`\bcompensation fund\b`,
      String.raw`\bbeneficiary of (?:the|this|a|his|her) (?:fund|funds|sum|estate|will|inheritance)\b`,
      String.raw`\b(?:atm|visa) card (?:worth|loaded with|containing)\b`,
      'اقرب الاقارب', 'ميراث (?:بقيمة|بمبلغ)', 'اموال غير مطالب بها', 'صندوق دبلوماسي', 'مليون دولار (?:باسمك|لك)', 'تعويض الامم المتحدة'
    ])
  },
  romance_story: {
    label: { en: 'Online “relationship” story that leads to money', ar: 'قصة «علاقة» عبر الإنترنت تنتهي بطلب مال' },
    re: rx([
      String.raw`\b(?:i am|i'm|im) (?:a |an )?(?:us |american |british |un |united nations )?(?:soldier|army (?:officer|doctor|general)|marine|doctor|surgeon|engineer|contractor) (?:on|in|with|at) (?:a |an |the )?(?:peace ?keeping|un |united nations |oil rig|offshore|mission|deployment|syria|yemen|afghanistan|iraq)\b`,
      String.raw`\boil rig\b`, String.raw`\bpeace ?keeping mission\b`,
      String.raw`\bi (?:have )?fall?en (?:in love )?(?:in love )?with you\b`, String.raw`\bi (?:think|feel) i(?:'m| am) falling (?:in love )?(?:for|with) you\b`,
      String.raw`\b(?:my|our) future (?:together|wife|husband)\b`,
      String.raw`\bmoney for (?:my |the )?(?:flight|ticket|visa|customs|clearance|leave papers|hospital bill)\b`,
      String.raw`\bwrong number\b[\s\S]{0,120}?\b(?:be friends|make friends|keep (?:in touch|chatting)|nice to meet you|get to know (?:you|each other))\b`,
      'وقعت في حبك', 'احببتك من', 'منصة نفطية', 'بعثة حفظ السلام', 'مستقبلنا معا'
    ])
  },
  rental_deposit: {
    label: { en: 'Deposit before you can see the property', ar: 'دفعة مقدمة قبل معاينة العقار' },
    re: rx([
      String.raw`\b(?:pay|send|transfer)\b${W}{0,30}?\b(?:deposit|booking (?:fee|amount)|advance rent|reservation fee)\b${W}{0,60}\b(?:before (?:viewing|you see|the viewing)|to (?:reserve|hold|book|secure) (?:it|the (?:flat|apartment|villa|unit|room|chalet|property)))\b`,
      String.raw`\bthe (?:owner|landlord) is (?:currently )?(?:abroad|overseas|outside the (?:country|uae)|out of the country)\b`,
      String.raw`\b(?:i am|i'm|im|the owner is) (?:currently )?(?:abroad|outside the (?:country|uae)|out of the country|overseas)${W}{0,60}\b(?:keys?|viewing|show|visit)\b`,
      String.raw`\bkeys? (?:by|via|through) (?:courier|post|dhl|aramex|delivery)\b`, String.raw`\b(?:send|courier) (?:you )?the keys\b`,
      String.raw`\bno viewing (?:needed|required|possible)\b`,
      'عربون (?:للحجز|قبل)', 'دفعة مقدمة (?:لحجز|قبل المعاينة)', 'المفتاح (?:بالبريد|عن طريق المندوب|مع المندوب)', 'المالك (?:مسافر|خارج الدولة)'
    ])
  },
  marketplace_buyer: {
    label: { en: '“Buyer” sends a payment link or a courier for your item', ar: '«مشترٍ» يرسل رابط دفع أو مندوباً لاستلام غرضك' },
    re: rx([
      String.raw`\b(?:click|open|use|press) (?:the |this )?(?:link|button)${W}{0,30}\b(?:receive|collect|claim|accept|get) (?:the |your )?(?:payment|money|funds)\b`,
      String.raw`\b(?:receive|collect|claim|accept) (?:the |your )?(?:payment|money|funds) (?:via|through|from|on) (?:the |this )?(?:link|website|page)\b`,
      String.raw`\bi(?:'ve| have)? (?:already )?(?:paid|sent (?:the )?(?:money|payment))${W}{0,40}\b(?:link|confirm (?:your )?card|enter your card)\b`,
      String.raw`\b(?:i will|i'll) send (?:my |a )?(?:courier|driver|delivery (?:guy|boy|agent))${W}{0,40}\b(?:pick|collect)\b`,
      String.raw`\b(?:over ?paid|sent (?:you )?(?:too much|extra))${W}{0,40}\b(?:refund|return|send back) the (?:difference|extra|balance)\b`,
      'استلام (?:المبلغ|الدفعة) (?:عبر|من خلال) الرابط', 'اضغط على الرابط (?:لاستلام|لاستقبال) (?:المبلغ|الدفعة)', 'ارسلت مبلغا زائدا', 'ارجع الفرق'
    ])
  },
  loan_fee: {
    label: { en: 'Loan that needs a fee first', ar: 'قرض يتطلب دفع رسوم أولاً' },
    re: rx([
      String.raw`\b(?:instant|urgent|easy|quick|personal) loans?\b${W}{0,60}\b(?:without|no) (?:salary certificate|documents?|guarantor|credit check|bank statement|aecb)\b`,
      String.raw`\bloans? (?:is |has been )?(?:approved|pre-?approved|sanctioned)${W}{0,60}\b(?:pay|send|transfer)\b${W}{0,30}\b(?:fee|charges?|insurance|stamp|registration|processing)\b`,
      String.raw`\b(?:processing|insurance|registration|stamp|file) (?:fee|charges?) (?:for|to (?:release|disburse|process)) (?:the |your )?loan\b`,
      'قرض (?:فوري|سريع|شخصي)[^.\\n]{0,40}(?:بدون|من غير) (?:تحويل راتب|كفيل|شهادة راتب|مستندات)', 'رسوم (?:معالجة|تامين|فتح ملف) (?:القرض|لصرف القرض)'
    ])
  },
  recovery_scam: {
    label: { en: 'Offers to “recover” money you lost to a scam', ar: 'يعرض «استرجاع» أموال خسرتها في احتيال' },
    re: rx([
      String.raw`\b(?:recover|get back|retrieve|reclaim) (?:your |all your |the )?(?:lost|stolen|scammed|missing) (?:funds?|money|crypto|bitcoin|investments?|savings)\b`,
      String.raw`\b(?:funds?|crypto|asset) recovery (?:agent|agency|service|expert|team|company|specialist)\b`,
      String.raw`\bwe (?:can|will) (?:get|bring) (?:your|all your) money back\b`,
      'استرجاع (?:اموالك|الاموال) (?:المسروقة|المفقودة)', 'استرداد (?:اموالك|المبلغ) (?:المسروق|المفقود)', 'شركة استرداد'
    ])
  },
  blackmail: {
    label: { en: 'Threatens to leak private photos or videos (blackmail)', ar: 'يهدّد بنشر صور أو فيديوهات خاصة (ابتزاز)' },
    re: rx([
      String.raw`\bi (?:have|got|recorded|captured|saved) (?:a |your |some )?(?:private |intimate |nude |naked )?(?:video|videos|photos?|pictures?|recording) of you\b`,
      String.raw`\bi (?:have )?(?:hacked|accessed|got into) your (?:camera|webcam|phone|device|account|computer)\b`,
      String.raw`\b(?:or|otherwise) (?:i will|i'll) (?:send|share|post|leak|upload|publish|forward) (?:it|them|the (?:video|photos?|pictures?))\b`,
      String.raw`\byour (?:family|friends|contacts|wife|husband|colleagues|boss) will (?:see|receive|get)\b`,
      'لدي فيديو لك', 'عندي صور(?:ك| لك)', 'سانشر (?:الفيديو|الصور)', 'ساشهر بك', 'سارسل (?:الفيديو|الصور) (?:لاهلك|لعائلتك|لاصدقائك)', 'فضيحتك'
    ])
  },
  visa_job_fee: {
    label: { en: 'Job or visa offer that asks you to pay', ar: 'عرض عمل أو تأشيرة يطلب منك الدفع' },
    re: rx([
      String.raw`\b(?:visa|work permit|employment visa|medical|processing|registration|training|onboarding|uniform) (?:fee|fees|charges?|cost|deposit)\b${W}{0,60}\b(?:job|position|offer|employment|hiring|joining)\b`,
      String.raw`\b(?:job|offer|position|employment)\b${W}{0,60}\b(?:pay|send|transfer|deposit)\b${W}{0,30}\b(?:visa|work permit|medical|processing|registration|training) (?:fee|fees|charges?|cost)\b`,
      String.raw`\bguaranteed (?:job|visa|employment)\b`,
      'رسوم (?:التاشيرة|الفيزا|تصريح العمل|الفحص الطبي|التسجيل)[^.\\n]{0,40}(?:وظيفة|عمل|التوظيف)', 'وظيفة مضمونة', 'تاشيرة مضمونة'
    ])
  }
};

// ---------- negation ----------
const NEG = rx([
  String.raw`\bdo not\b`, String.raw`\bdon'?t\b`, String.raw`\bdont\b`, String.raw`\bnever\b`, String.raw`\bnot\b`,
  String.raw`\bno one\b`, String.raw`\bnobody\b`, String.raw`\bwon'?t\b`, String.raw`\bwill not\b`, String.raw`\bshould ?n[o']?t\b`,
  String.raw`\bmust not\b`, String.raw`\bcannot\b`, String.raw`\bcan'?t\b`, String.raw`\bavoid\b`, String.raw`\bnahi[n]?\b`,
  String.raw`\bkabhi\b`, String.raw`\bhuwag\b`, `${SEP}لا${END}`, `${SEP}لن${END}`, 'ابدا', 'عدم', 'اياك', 'يحذر', 'تحذر', 'احذر',
  // warning context: the sentence DESCRIBES what scammers do ("Fraudsters may ask you to install AnyDesk")
  String.raw`\b(?:fraudsters?|scammers?|criminals?|thieves|attackers?|hackers?|impostors?|imposters?)\b`, String.raw`\bbeware\b`,
  String.raw`\bwarns?\b`, String.raw`\bwarning (?:against|about)\b`, 'المحتال', 'النصاب', 'المجرم'
], 'iu');
const NOT_REALLY_NEG = rx([
  String.raw`\bdon'?t (?:worry|panic|be (?:afraid|scared|worried))\b`, String.raw`\bdo not (?:worry|panic)\b`, String.raw`\bno (?:problem|worries)\b`,
  String.raw`\bnot a problem\b`, String.raw`\bif (?:you|u)\b[^,.!?\n]{0,25}\b(?:do not|don'?t|dont|not)\b`, 'لا تقلق', 'لا تخاف', 'لا تشيل هم', 'لا تتصل (?:فيني|بي|علي)\\s*,'
]);

export function sentenceStart(text, idx) {
  const re = /[.!?\n]/g;
  let start = 0;
  const head = text.slice(0, idx);
  let m;
  while ((m = re.exec(head))) start = m.index + 1;
  return start;
}
export function sentenceEnd(text, idx) {
  const m = /[.!?\n]/.exec(text.slice(idx));
  return m ? idx + m.index : text.length;
}

export function isNegatedBefore(text, idx) {
  const s = Math.max(sentenceStart(text, idx), idx - 45);
  const window = text.slice(s, idx).replace(NOT_REALLY_NEG, ' ');
  return NEG.test(window);
}
