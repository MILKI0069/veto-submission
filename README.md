<p align="center"><img src="assets/veto-logo.jpg" alt="Veto.ai" width="380"></p>

# Veto.ai: the scam guard that watches for you

**ScamShield AI hackathon · Abu Dhabi Police × 42 Abu Dhabi · Team veto.ai: Sarah Bawazir, Firaol Tesfaye, Milki Teshome · November 2026**

> Most scam checkers wait for you to copy a suspicious message, open an app, paste it and ask "is this fake?".
> By then the victim has usually already tapped.
> **Veto.ai never waits to be asked.** It sits on top of the phone's messages and the computer's browser, checks every
> SMS, WhatsApp message, e-mail, link and website **the moment it arrives**, and warns inside the app the person is
> already using, in Arabic and English, with the reason and what to do next.

| | |
|---|---|
| **Police dashboard** | **[Open the live police dashboard](https://vetoai.mubadara.app/police)** · Officer code required. [Walk through a case](#police-dashboard). |
| **Live site** | **https://milki0069.github.io/veto-submission/** · download the Android app, open the web app, get the extension |
| **Resident app (no install)** | https://milki0069.github.io/veto-submission/app/ · the same Veto screens in any browser |
| **Test it in the browser** | https://milki0069.github.io/veto-submission/check/ · paste a message, a link or a whole list of links; same engine |
| **Demo video (1 minute)** | [watch on Google Drive](https://drive.google.com/file/d/1m2Z7aZArLyuuMnj-L3TL_YaR12q4Xx1p/view?usp=sharing); the source and the real screenshots it uses are in [`tools/video-render.js`](tools/video-render.js) and [`docs/img/demo/`](docs/img/demo/) |
| **Android app** | [download veto.apk](https://github.com/MILKI0069/veto-submission/releases/latest/download/veto.apk) (also [`release/veto.apk`](release/veto.apk); source in [`android/`](android/)) |
| **Browser extension (Chrome, Edge)** | [`release/veto-extension.zip`](release/veto-extension.zip) · load unpacked; source in [`extension/`](extension/) |
| **Every number in this README** | traced to a file in [`docs/CLAIMS_LEDGER.md`](docs/CLAIMS_LEDGER.md); every test protocol written before it ran in [`docs/RESEARCH_LOG.md`](docs/RESEARCH_LOG.md) |
| **Build and run** | [How to build and run](#how-to-build-and-run): `npm install`, `npm test`, `npm start` |

---

## The problem and our solution

**The problem.** In a 2024 survey, 56 % of UAE residents reported at least one fraud attempt a month (UAE Cyber Security Council × TRENDS study,
[Emirates News Agency](https://www.wam.ae/en/article/b6f93te-2024-state-scams-uae-survey-reveals-65-scam)).
The scams copy everything a victim trusts: the logo, the sender name, the website, even the voice on the phone. Blocklists only
know a fake site after someone has been hurt, and most checkers only help people who already suspect something and stop to paste it.

**Our solution.** Veto.ai checks every message, link and website the moment it arrives, on the phone and in the browser, and
compares it with what 77 UAE banks, police forces and government bodies have publicly said they will **never** ask you to do.
A scammer can fake a logo; he cannot fake the institution's own rules. Veto explains every verdict in Arabic and English, gives the
real number to call, watches new certificates and newly registered domains for look-alikes of UAE institutions before the first
victim, and packs police-ready evidence for a takedown. It works fully offline, so nothing leaves the phone.

## Works fully offline: the benchmark

Every check in Veto runs **on the device, with no internet connection, no account and no server**. The numbers below were all
measured in offline mode: nothing was looked up online to reach them.

| Offline benchmark | Result |
|---|---|
| Links judged per second on an ordinary laptop, offline | **about 1,000** (about 1 ms per link) |
| Accuracy offline, 33,766 held-out links | **98.3 % precision, 94.5 % recall** |
| Scam SMS caught offline, on-device model | **96.9 %** (2.4 % false alarms) |
| Data that leaves the phone during a check | **none** |
| Size of the whole engine with its models | about **2 MB** in the browser extension, about **1.2 MB** for the Android app |

A scam that arrives in a basement car park, on roaming, or in a country with blocked services is caught the same way.
The online layer (following redirects, domain age, phishing feeds) and the AI second opinion are optional extras on top.

---

## Results at a glance

| What we measured | Result | Evidence |
|---|---|---|
| Phishing and legitimate links, held out by time and by domain | **98.3 % precision, 94.5 % recall** on **33,766** URLs | [`data/judge-report.json`](data/judge-report.json) |
| Phishing on domains the model never saw | **98.0 % precision, 95.0 % recall** (7,667 phishing URLs) | same report |
| Official UAE government and bank pages wrongly flagged | **0 of 2,231** | same report |
| A second phishing feed, domains never in training | **89.0 %** of 292,437 URLs caught | [`data/unseen-report.json`](data/unseen-report.json) |
| Scam SMS, 881 labelled texts, nested cross-validation | **96.9 %** caught (251 of 259), **2.4 %** false alarms | [`data/sms-cv-report.json`](data/sms-cv-report.json) |
| Look-alikes of UAE brands (ADNOC, Emaar, Property Finder ...) | **65.0 %** caught, up from 20.1 % after the UAE brand watchlist, with no rise in false alarms beyond 0.05 points | [`data/uae-watch-B.json`](data/uae-watch-B.json) |
| New certificates read live from 50 public certificate logs | **1,190 per second**, a median **17 s** after logging | [`data/ct-history/ct-watch-report-run4.json`](data/ct-history/ct-watch-report-run4.json) |
| Speed | about **1 ms per link**, offline; 20,000 links in one run | [`docs/RUN_LOG.md`](docs/RUN_LOG.md) |
| Automated tests | **153 of 153** pass, plus 9 of 9 browser checks of the extension | `npm test`, `npm run test:extension` |

The training data is public and dated: **472,582** URLs (OpenPhish history, Phishing.Database, PhiUSIIL and crawled
legitimate deep links), the **Tranco top 100,000** sites, **881** labelled SMS texts, the published rules and phone
numbers of **77 UAE institutions** and **34 UAE brands**. Tests use data that came **after** the training data, split so
that no domain is in both.

---

## Every judging criterion, at a glance

| Criterion (weight) | What Veto delivers | Proof |
|---|---|---|
| **Detection accuracy (30 %)** | **98.3 % precision, 94.5 % recall** on **33,766** held-out links; **96.9 %** of scam SMS caught at **2.4 %** false alarms; **0 of 2,231** official UAE pages wrongly flagged | [`data/judge-report.json`](data/judge-report.json), [`data/sms-cv-report.json`](data/sms-cv-report.json) |
| **Early detection and coverage (25 %)** | new fake sites seen in public certificate logs a median **17 s** after they appear; a live look-alike hunt found **568** registered look-alike domains of UAE institutions, **248** of them live; **about 70,000** new domains screened a day; SMS, WhatsApp, Telegram, calls, links, e-mail, websites, QR codes, search and Maps; any language | [`data/ct-history/ct-watch-report-run4.json`](data/ct-history/ct-watch-report-run4.json) |
| **Explainability and actionability (20 %)** | every warning names the rule the scam breaks, in the institution's own words, gives the real number and offers Report, Warn family and the police number; Kiki shows how serious it is at a glance | [Every feature](#every-feature), [Kiki](#kiki-a-warning-anyone-can-read) |
| **UAE relevance and innovation (15 %)** | the published rules of **77 UAE institutions**, **34 UAE brands** watched for look-alikes, Arabic and English; it reads messages by itself, with no copying or pasting | [What sets Veto apart](#what-sets-veto-apart) |
| **Feasibility and presentation (10 %)** | live today: Android app, browser extension, web app and link check, one shared engine, **fully offline**, **153** automated tests, no paid service needed | [live site](https://milki0069.github.io/veto-submission/) |

Full detail per criterion: [How Veto meets each judging criterion](#how-veto-meets-each-judging-criterion).

## Beyond the rubric: advanced methods, not keyword lists

Simple scam checkers match keywords or look a link up in a blocklist. Veto combines methods that each answer a harder
question, and every one of them is measured:

| Method | What it does | Why it matters |
|---|---|---|
| **Rulebook contradiction reasoning** | turns what 77 UAE institutions have publicly said they will *never* ask for into machine-readable rules, and checks each message, call and link against the rules of the institution it claims to be | catches brand-new scams with no known link, and the warning cites the institution's own words |
| **Full-URL machine-learning model** | logistic regression over **2^20 hashed features** of the whole address (host, path, query, scheme, popularity bucket), trained on **472,582** dated URLs | held out **by time and by domain**, so the score reflects scams it has never seen |
| **On-device SMS model with nested cross-validation** | hashed text features of **881** labelled texts, the threshold chosen only inside the inner folds; **1,000,000** generated texts tested as extra training data and rejected because real texts did better | an honest score, no tuning on the test data |
| **Live Certificate Transparency streaming** | reads **50** public certificate logs as they grow, parses each certificate directly from its binary form, **736,333** certificates in 10 minutes | fake sites are flagged before the first scam SMS is sent |
| **Look-alike hunting at scale** | look-alike letters, punycode, swapped neighbouring letters, brand names glued to other words; stress-tested on **917,396** look-alike domains of **92,732** brands against **100,000** real sites | measured on a scale far beyond the UAE list it protects |
| **Link X-ray in a sealed browser** | opens the page in a throw-away headless browser, types **fake** details and watches where they go (a Telegram bot, a webhook, a hidden spreadsheet), blocking every send | proves what a page steals instead of guessing |
| **Phone-context contradictions** | compares what a message claims with what the phone knows: the saved contact, the number's country, an active call, a bank app opening | catches "Hi Mum, new number" and coached calls that contain no link at all |
| **Live scam-script tracking on calls** | follows the stages of a scam script (authority, problem, pressure, the ask) and warns before the ask arrives | protects during the call, not after the money is gone |
| **Privacy-first AI layer** | personal data is removed before any AI sees the text; the AI translates other languages and can add a warning but never remove one | the AI makes Veto stronger without making it less safe |
| **Pre-registered tests and a claims ledger** | each test was written down before it ran, and every number in this README is traced to a file; **66,533** links re-judged after each engine change with identical verdicts | the numbers can be checked, not just trusted |

---

## What sets Veto apart

1. **No copy, no paste. It watches.** On Android, Veto reads each new SMS and WhatsApp notification as it arrives and
   draws its warning **on top of the messaging app**: a banner ("Veto: this message looks like a scam · Why?") and a
   highlight around the exact message. In the browser it labels messages inside WhatsApp Web, Google Messages,
   Telegram, Gmail and Outlook, and stops scam websites with a full-screen warning before anything is typed.
2. **Works offline, private by design.** The check runs on the device, with no internet needed. Veto looks for scam *patterns* (who a message claims to be,
   what it asks for, how it pressures, where its links really go); nothing is uploaded. An optional AI second opinion
   receives text only after card numbers, codes, phone numbers and e-mails are removed.
3. **It stays with the whole conversation.** Scammers groom first and send the link later. Every new message is
   checked when it appears, so a link slipped in on the tenth message is caught on the tenth message.
4. **It reads the rulebook, not just the text.** For each of 77 UAE banks, police forces and government bodies, Veto
   knows what that institution has publicly said it will **never** ask for (an OTP, a PIN, a remote-control app, a
   transfer to a "safe account") and its real domains and phone numbers. A message that claims to be Dubai Police but
   links to `cutt.ly` contradicts Dubai Police's own rules, and Veto says exactly that.
5. **It sees scam sites before the messages go out.** Veto reads the public certificate logs live and the daily lists of
   newly registered domains, and flags names that imitate UAE institutions and brands, often before the first SMS is
   sent.
6. **Any language.** Arabic and English are read by the rules. Urdu, Hindi, Tagalog, Malayalam, Russian and other
   languages common in the UAE are translated and checked by the AI layer, which can add a warning but never remove one.

---

## The app reads by itself: what to know before installing

The Android app is the full product. It reads only the **sender and text of new notifications** (WhatsApp, SMS,
Telegram) on the phone; trusted family chats are skipped and nothing is uploaded. It stays current by refreshing public
phishing feeds, the day's newly registered domains and new look-alike certificates; a scam reported through Veto goes to
the police with an evidence pack.

**Inside the app, without installing it.** Two real screenshots from the full app on our phone. You switch on each guard
once and the permissions do the work from then on: notification access reads new messages, the caller-ID role checks
unknown numbers before they ring, the overlay lets Kiki warn you on top of WhatsApp or the dialer. You choose exactly
which apps Veto reads, and online checks stay off until you switch them on.

| The guards, 5 / 5 on | Settings and the apps Veto reads |
|---|---|
| <img src="docs/img/app/guards.webp" width="300" alt="Veto app: Guarding, 5 of 5 guards on"> | <img src="docs/img/app/settings.webp" width="300" alt="Veto app: settings and the apps Veto reads"> |

**Why it is not on Google Play yet.** Reading SMS, notifications and calls are powers Google grants only after it
reviews an app on Google Play, and Android blocks or limits them for apps installed from anywhere else. Veto is a
hackathon build that has not been through that review yet, so a phone may refuse it. Once it is on Google Play it
installs like any other app: switch on the guards and Veto watches by itself. The phone in the demo video had it
installed directly over a cable, the way test builds are installed. To try it on another phone today:

1. Download [`veto.apk`](https://github.com/MILKI0069/veto-submission/releases/latest/download/veto.apk) and allow
   installs from your browser if Android asks.
2. If Play Protect blocks it: Play Store, your profile, Play Protect, the settings gear, switch off "Scan apps with Play
   Protect", install Veto, then switch it back on.
3. To turn on message reading: Settings, Apps, Veto, the ⋮ menu, "Allow restricted settings", then switch on each guard.

If it will not install, the **[web app](https://milki0069.github.io/veto-submission/app/)** has the same checks in any
browser (message check, live call guard on speaker, listing check, QR codes, the scam quiz), without the automatic
watching, because a browser cannot read notifications or calls. The **browser extension** and the
**[link check](https://milki0069.github.io/veto-submission/check/)** work on any computer.

---

## Kiki: a warning anyone can read

Kiki is Veto's guard. Its face and colour show how serious a situation is before a single word is read, which makes
Veto easy to use for elderly people and children. Kiki stays hidden and only appears when something needs you.

| <img src="docs/img/kiki/idle.png" width="80"> | <img src="docs/img/kiki/listening.png" width="80"> | <img src="docs/img/kiki/investigating.png" width="80"> | <img src="docs/img/kiki/thinking.png" width="80"> | <img src="docs/img/kiki/advising.png" width="80"> | <img src="docs/img/kiki/caution.png" width="80"> | <img src="docs/img/kiki/stop.png" width="80"> | <img src="docs/img/kiki/verified.png" width="80"> |
|---|---|---|---|---|---|---|---|
| On guard | Watching (on a call) | Checking a link | Thinking | Advice (the real number) | Caution | STOP! (a scam) | Verified (the real institution) |

| Kiki on a call | Kiki on the X-ray |
|---|---|
| <img src="docs/img/demo/call-t9.png" width="300" alt="Live call guard: HANG UP NOW"> | <img src="docs/img/demo/xray-view.png" width="300" alt="Kiki explains what a page wants"> |
| On speaker, Veto listens and says HANG UP NOW with the rule the caller broke. | The X-ray typed fake details into a scam page and caught it sending them to a hidden Google spreadsheet; Kiki says what the page really wants. |

---

## Technical choices, tools, APIs and data

| Area | What we use, and why |
|---|---|
| **Engine** | Node.js with no web framework. A rulebook of what 77 UAE institutions never ask for, plus a logistic URL model over 2^20 hashed features of the whole address. Rules make every verdict explainable and citable; the model catches what no rule names. |
| **Phone** | A native Android app in Java that runs the same engine, with an on-device SMS model. Offline by design, so no message leaves the phone. |
| **Browser** | A Chrome and Edge extension (Manifest V3) running the same engine; the web app and the [link check](https://milki0069.github.io/veto-submission/check/) run it in the browser. |
| **Link X-ray** | Microsoft Edge in headless mode, in a sealed session, to see what a suspicious page asks for and where it sends data. |
| **Early warning** | Public Certificate Transparency logs read directly, and the daily list of newly registered domains (WhoisDS). |
| **Optional APIs (off by default)** | Anthropic Claude API or Groq for the AI second opinion and translation (it can add a warning, never remove one); abuse.ch and IPQualityScore look-ups; SerpApi, Brave Search and Google Places connectors for search, ads and Maps, built and tested offline, awaiting a key for a live run. |
| **Data** | Dated phishing from the OpenPhish community feed history (research use) and Phishing.Database; PhiUSIIL (UCI, CC BY 4.0); the Tranco list of popular sites; official pages of the 77 institutions; SmishX for an external SMS test. Held-out sets are split by time and by domain. |

## How we built and tested it

Every test was planned in writing before it ran ([`docs/RESEARCH_LOG.md`](docs/RESEARCH_LOG.md)), used data from after
the training data, and every number is traced to a file ([`docs/CLAIMS_LEDGER.md`](docs/CLAIMS_LEDGER.md)).

| Data | Volume | What it showed |
|---|---|---|
| Dated public URLs used to train the link model | **472,582** | OpenPhish history, Phishing.Database, PhiUSIIL and real websites |
| Held-out links, later in time, unseen domains | **33,766** | 98.3 % precision, 94.5 % recall, 0.59 % false alarms |
| Phishing from a second feed, domains never in training | **292,437** | 89.0 % caught |
| Labelled SMS, nested 5-fold cross-validation | **881** | 96.9 % of scams caught, 2.4 % false alarms |
| Generated SMS tested as extra training data | **1,000,000** | measured, and not needed: real texts alone did better |
| Look-alike domains in a brand stress test | **917,396** (92,732 brands) | with **100,000** real sites as controls |
| Live certificates read in one 10-minute run | **736,333** from 50 logs | 1,190 a second, median 17 s to alert |
| Newly registered domains read per day | **about 70,000** | look-alikes of UAE institutions flagged |
| Official UAE government and bank pages | **2,231** | 0 wrongly flagged |
| Links re-judged after every engine change | **66,533** | identical verdicts after moving the engine into the browser |
| Automated tests | **153** | plus browser tests of the extension (9 of 9) and the phone engine (4 of 4) |

---

## How we came to the idea, and what is new

Scammers can fake a caller ID, a logo, a website, even a voice. **They cannot fake the institution's own rules.**
Every UAE bank, police force and government body has said in public what it will never ask you to do: share an OTP or
PIN, install a remote-control app, move money to a "safe account", pay a fine through a link. We turned those
statements into a machine-readable rulebook, and built every check around one question: *does this message, link or
call contradict what the institution it claims to be has promised?* The answer cites the institution's own words.

On top of that rulebook, Veto adds what we believe is new in one pipeline:

1. **Self-citing verdicts.** Each warning quotes the rule the scam breaks and gives the institution's real number and website.
2. **It watches instead of waiting.** Notifications, links and calls are checked as they arrive, and the warning is drawn
   over the app in use. Nobody has to copy, paste or open anything.
3. **Scam-in-progress fusion.** A one-time code that arrives while someone claiming to be your bank is on the phone is
   linked to that caller: *"They are asking for the code you received 1 minute ago. It adds a NEW beneficiary."*
4. **Predictive script tracking.** On a call, Veto follows the scam script (authority, problem, pressure, the ask) and warns
   before the ask arrives.
5. **Phone-context contradictions.** What a message claims is compared with what the phone knows: the saved contact, the
   number's country, the chat history, an active call. "Hi Mum, new number" is checked against the Mum you saved.
6. **A link X-ray that answers "where does my data go?"** A sealed browser types fake details into the page and names the
   channel the criminals use (a Telegram bot, a webhook, a hidden spreadsheet), blocking every send.
7. **Early warning built for the UAE.** Certificate logs, newly registered domains and look-alike hunts focused on UAE
   institutions and brands, joined into campaigns by the infrastructure criminals reuse.
8. **Protection at the moment of dialling.** If you call a number from a scam message, Veto holds the call and offers the
   institution's real number.
9. **Measured honestly.** Every number comes from a test planned in writing before it ran, on data that came after the
   training data.

---

## Every feature

| Feature | What it does | Where it runs |
|---|---|---|
| **Kiki, the Android guard** | A small companion that stays hidden until something needs you. Reads new WhatsApp, SMS and Telegram notifications (trusted family chats are skipped) and pops up over the app with "This is a scam" or "Be careful", the reasons, and Report, Warn family, I know them and Got it. | Android, on the phone |
| **Message check** | Finds who a message claims to be, what it asks for and how it pressures you, and checks it against the rulebook of 77 UAE institutions. Arabic and English. | phone, extension, web |
| **On-device SMS model** | A model trained on 881 labelled texts that recognises how scam texts are worded, even with no link or brand name: 96.9 % caught. | phone, extension, web |
| **URL Judge** | One verdict, one score and plain reasons for any link: official sites, look-alike letters, brands glued to other words, punycode, "@" tricks, short links, open redirects, cheap endings, a full-URL model trained on 472,582 URLs, and a popularity guard. | everywhere, about 1 ms per link |
| **Link X-ray** | Opens a suspicious link in a sealed, throw-away browser, shows a picture of the page and says in one sentence what it wants. A fake-data trap shows where stolen data would go. Unmasks fake "virus detected" pages and pages that hide from scanners. Reads a pushed app file without installing it and names banking-trojan powers. | server |
| **Link Shield** | Checks every link you tap on the phone before the browser opens it. | Android |
| **Caller check** | Before you answer: the number's country, one-ring scam ranges, hidden numbers, and whether it is really the institution's published number. | Android, web |
| **Call watch** | During a call with an unknown number, catches the footprints of a coached scam: a bank code arriving, your bank app, UAE PASS or AnyDesk opening, an app being installed. A sharp beep and a red STOP card say why. | Android |
| **Live call guard** | Put a suspicious call on speaker: Veto follows the scam script live and flashes HANG UP NOW with the reason the moment the caller asks for something a real institution never would. | web console |
| **OTP Guard** | Explains in plain words what a one-time code unlocks ("adding your card to someone's Apple Pay") and never to share it. | phone, web |
| **Fake-number interceptor** | Holds an outgoing call to a number from a scam message, or a fake contact saved under a bank's name, and offers the real number. | Android |
| **Contacts audit** | Finds contacts saved under an institution's name with a number it does not publish. | Android |
| **Listing check** | Checks a Maps, search or ad listing field by field ("Emirates NBD Customer Care 24/7") against the institution's published numbers and websites. | phone, web |
| **Browser extension** | Full-screen warning on scam websites, labels on risky messages in WhatsApp Web, Google Messages, Telegram, Gmail and Outlook, right-click check, red, orange and green badges. | Chrome, Edge |
| **AI second opinion** | Translates and checks messages in other languages (Urdu, Hindi, Tagalog ...) and messages where the parts disagree; it can add a warning, never remove one. Personal data is removed first. | optional |
| **Live certificate watch** | Reads 50 public certificate logs live and flags new sites that use UAE institution and brand names, a median 17 s after they are logged; alerts are enriched and linked. | server |
| **New-domain watch and Sentinel** | Reads the day's newly registered domains (about 70,000) and hunts about 10,000 look-alike names per institution; visits the live ones and separates armed pages from parked names. | police console |
| **Campaign linking** | Joins scam sites by what criminals reuse: Telegram bot IDs, analytics IDs, wallets, WhatsApp numbers, the same server, a bulk registration. | police console |
| **Evidence and takedown packs** | A ZIP with screenshots, the page, the registrar and abuse contact and a SHA-256 manifest; STIX 2.1 export for threat-intelligence platforms. | police console |
| **Test yourself** | A short "scam or safe?" quiz that teaches the patterns. | web |

---

## Real messages, real warnings

A real screen recording on a Samsung Galaxy S25: a fake RTA parking fine arrives on Telegram and Kiki, Veto's guard,
pops up at once with the reasons, Report, Warn family and the police number. Nobody pasted anything.

<img src="docs/img/demo/phone-kiki.png" width="300" alt="Kiki warning over a fake RTA parking fine on Telegram">

These are real SMS messages a team member received, with Veto's warnings drawn over Google Messages on a Samsung
Galaxy S25.

| Fake Dubai Police fine | Fake toll bill |
|---|---|
| <img src="docs/img/demo/sms-police.jpg" width="300" alt="Veto warning over a fake Dubai Police SMS"> | <img src="docs/img/demo/sms-toll.jpg" width="300" alt="Veto warning over a fake toll SMS"> |

In the browser, the extension labels each step of a job-task scam as it appears, and stops a fake bank site:

<img src="docs/img/demo/pc-whatsapp.png" width="860" alt="Veto labels on a WhatsApp Web conversation">

<img src="docs/img/demo/pc-scam-site.png" width="860" alt="Veto full-screen warning on a fake bank site">

---

## The scams Veto covers

| Channel | Scam | How Veto catches it |
|---|---|---|
| SMS | Fake fines, tolls, parcel fees, bank "account blocked" | the claimed sender's rules, the link's real owner, short links, cheap domain endings, the SMS model |
| SMS | One-time codes | explains what the code unlocks and warns never to share it; a code request in a message is flagged |
| WhatsApp, Telegram | Job and task scams, investment, romance, "family emergency" | grooming and pressure tactics, money and code requests, links judged as they appear |
| WhatsApp | Account takeover ("send me the 6-digit code") | code requests, Emirates ID requests |
| E-mail | Fake invoices, shared documents, login pages | the URL Judge on every link, files on public cloud buckets, victim e-mail addresses inside links |
| Web | Look-alike bank, police, government and brand sites | look-alike letters, brand names glued to other words, punycode, "@" tricks, the URL model, the popularity guard |
| Search and Maps | Fake customer-care numbers and listings | the listing check compares a listing's number and website with the institution's published ones |
| Calls | Calls followed by UAE PASS or authenticator approvals | the call watch warns when an approval app opens after an unknown call; the interceptor holds a call to a number from a scam message and offers the real one |

---

## How Veto meets each judging criterion

### Detection accuracy (30 %)
* **98.3 % precision and 94.5 % recall** on 33,766 held-out URLs; counting "suspicious" as flagged, recall 96.19 %.
* **0 of 2,231** official UAE pages flagged. The official allowlist and the gov.ae registry rule mean a real bank or
  government site is never called a scam.
* Resists evasion: short links, open redirects on trusted sites, defanged links (`hxxps://x[.]com`), punycode,
  "@" tricks and redirects are unwrapped and judged; the online mode follows each link to where it really lands.
* Every verdict comes with a score from 0 to 1 and the reasons, so a test set can be scored at any threshold
  (`npm run judge -- your-list.csv` prints precision, recall and F1).

| URL Judge, offline | URLs | Precision | Recall | F1 | False alarms |
|---|---|---|---|---|---|
| All held-out URLs | 33,766 (9,039 phishing, 24,727 legitimate) | 98.3 % | 94.5 % | 96.4 % | 0.59 % |
| Phishing on domains never seen in training | 7,667 phishing | 98.0 % | 95.0 % | 96.5 % | 0.59 % |

### Early detection and coverage (25 %)
* **Live certificate watch:** 50 public certificate logs (33 of the new tiled kind, where Let's Encrypt and Google now
  publish), 1,190 certificates checked per second, a median 17 seconds from logging to alert, alerts enriched with DNS
  and hosting network and linked into groups when they share an address.
* **Newly registered domains:** about 70,000 a day read in about 20 seconds; look-alikes of UAE institutions flagged.
* **Sentinel hunt:** about 10,000 look-alike names per hunt built from the official domains; the first live hunt
  found 568 registered look-alikes, 248 of them live.
* **Search, ads and Maps:** connectors for search results, paid ads and Maps listings, with the listing check for fake
  customer-care numbers.
* **Coverage of channels:** SMS, WhatsApp, Telegram, e-mail, websites, calls, search and Maps.

### Explainability and actionability (20 %)
* Every reason says where it came from (rule, model, official list, popularity, online check, feed or AI) and is
  written in plain English and Arabic.
* Every warning ends with what to do: do not reply or pay, call the institution's real number (shown), block the card
  if details were typed, and report to Abu Dhabi Police Aman 800 2626 or Dubai Police ecrime.ae.
* Evidence packs for takedown requests: a ZIP with a SHA-256 manifest, STIX 2.1 export, the registrar and abuse contact.

### UAE relevance and innovation (15 %)
* Built on the UAE's own rulebook: 77 institutions, their published phone numbers, domains and "we will never ask"
  statements; 34 more UAE brands on the look-alike watchlist.
* Arabic first-class: every verdict, reason and next step in Arabic and English; Arabic SMS and mixed Arabic-English
  messages are read by the rules.
* Innovation: the passive overlay (no pasting), the rulebook contradiction check, a live certificate watch tuned to UAE
  names, network linking of scam sites, and an AI layer that translates the languages of the UAE's residents.

### Feasibility and presentation (10 %)
* Runs today: an Android app, a Chrome and Edge extension, a web console, a police console and an HTTP API, all on one
  shared engine. No paid service is required; the AI layer is optional.
* Fast and light: about 1 ms per link offline on an ordinary laptop.
* Ready for a pilot: the API judges a whole list (`POST /api/v1/judge`), the police console runs hunts and exports
  evidence, and the claims ledger lets any reviewer reproduce each number.

---

## Coming next: block once, protect the whole family

Scammers aim at the most trusting person in a family: an elderly parent, a busy relative, a child with a first phone. Veto's next step turns one person's caution into everyone's protection.

- **Confirm once, blocked everywhere.** When you confirm a scam, Veto blocks that link and that phone number on every device you link: your phone, your laptop with the extension, and the phones and tablets of the family members you add.
- **Made for children and elderly parents.** A parent looks after a child's device: a scam blocked for the parent is blocked for the child too, and Kiki shows the child a simple STOP instead of the link.
- **Fast community protection.** With consent, a confirmed scam (only the link or the number, never the message or who received it) joins the offline blocklist every Veto device carries, so one report can protect thousands of people.
- **Built on what ships today:** Warn family, Report to Aman (800 2626), Link Shield and the on-device blocklist.

Status: designed, not built yet. It needs opt-in family linking, and a review of community reports so that nobody can get a real number blocked with false reports.

## Police dashboard

1. Open the [live police dashboard](https://vetoai.mubadara.app/police) and enter the officer code provided by the team. The workspace supports English and Arabic.
2. In **Overview**, select **Review** beside a case under **Needs an officer**. Inspect the risk score, the reasons for the flag and the available screenshot.
3. Select **Evidence ZIP** to download the case report and its integrity manifest. Downloading the evidence leaves the officer’s decision pending until an officer records one.

The deployed watchlist includes 34 additional UAE brands. The separate brand stress test covered 46 UAE brands across 452 generated look-alikes ([research log](docs/RESEARCH_LOG.md)).

**Officer sign-off.** Veto collects and explains; it never sends a takedown request by itself. An officer opens a
case, reads the evidence and records *approve*, *reject* or *needs more information* with a name and a note. Every
decision is appended to a hash-chained log (`var/audit.jsonl`): each entry carries the SHA-256 of the entry before
it, so a changed or removed line shows. The takedown pack and the evidence ZIP carry the decision.

**Keeping the case file across restarts.** Cases, X-ray pictures, the sign-off log and the hunt state are written
to `var/`. On a host whose disk is wiped at every restart, set `VETO_STORE_URL`, `VETO_STORE_KEY` and
`VETO_STORE_SECRET` (see `.env.example`) and run `db/store.sql` once in a Postgres project with a REST API
(Supabase). Every write is then also sent to the database, and `var/` is rebuilt from it at start-up
(`server/store.js`). The tables are not exposed by the API: the only way in is five functions that check the
secret, and a sign-off entry can be inserted once and never changed. `GET /api/store` says which mode is active.

**Access.** On the Veto server itself (localhost) the dashboard is open. When Veto is hosted, set
`VETO_CONSOLE_TOKEN` to an access code of 8 characters or more: officers sign in with it and get a 12-hour, signed,
HttpOnly session cookie; sign-in attempts are rate limited. This is a pilot gate. A police deployment would sit
behind the force's own single sign-on.

**Hosting.** The `Dockerfile` runs the whole app (with the browser for the Link X-ray). Health check: `/healthz`.
Every setting is listed in `.env.example`. Live Search and Maps hunts need one key: `SERPER_API_KEY`, or Brave plus
Google Places, or SerpApi (the only one that also returns paid ads).

## How to build and run

```bash
npm install
npm test                                   # 169 tests
npm run judge -- your-list.csv             # judge a list of URLs offline; add a label column for precision and recall
npm start                                  # the web app on http://localhost:8787 (police dashboard)
npm run build:extension                    # then load build/extension unpacked in edge://extensions or chrome://extensions
npm run android                            # builds the Android app (release/veto.apk is prebuilt)
```

The URL list can be one URL per line or a CSV with a `url` column and an optional `label` column (`1/0`,
`phishing/legitimate`). The web page is `/judge.html`; the API is `POST /api/v1/judge`.

## Repository map

| Folder | What is in it |
|---|---|
| `engine/` | the shared engine: rules, URL Judge core, URL model, SMS model, message check, language scope, AI prompt |
| `server/` | the HTTP server, online checks, X-ray, Sentinel, evidence packs |
| `extension/` | the browser extension |
| `android/` | the Android app (notification and SMS checks, overlays, call watch, interceptor) |
| `web/`, `web-demo/` | the web console and the public live check |
| `data/` | the rulebook, the models and every measured report |
| `tools/` | training, evaluation, the certificate watch, builds and the demo video |
| `tests/` | 169 automated tests |
| `docs/` | the research log, the claims ledger, the technical report and the run log |

Full methodology, every experiment and its protocol: [`docs/TECHNICAL_REPORT.md`](docs/TECHNICAL_REPORT.md) and
[`docs/RESEARCH_LOG.md`](docs/RESEARCH_LOG.md).
