# Research log

Every experiment we ran on the URL Judge, including the ones we rejected, and the papers we checked.
Numbers come from the held-out split in the README (time split, 25 Oct to 24 Nov 2026) unless stated otherwise.
Reproduce with `npm run eval:judge -- --data <dataset folder>` and `node tools/train-url-model2.js` (see TECHNICAL.md, section 1b2).

## Experiments (24 Nov 2026)

| # | Change | Result | Decision |
|---|---|---|---|
| 1 | Official UAE pages as legitimate training data (split by domain, flag `--official-as-legit`) | Held-out UAE domains (192 URLs): 1 flagged before and after. Test false alarms rose from 0.62 % to 0.71 %; recall moved from 93.9 % to 94.1 %. | Rejected. The shipped model is the previous one. |
| 2 | Popularity guard (top 10,000 scaled to 0.25, top 100,000 to 0.6, hosting platforms exempt) | Long-tail legitimate false alarms 0.83 %, popular 0.28 %. Phishing on popular domains caught 57.2 % (232 of 402). | Kept. The trade-off is disclosed. Next: a separate test for hacked popular sites. |
| 3 | Brand words that are also ordinary words abroad (centralbank, police, emirates, finance, post, customs, courts, tax, bank, gov) count only with the model | Removed false alarms on real central banks such as centralbank.cy and centralbank.org.sz | Kept |
| 4 | Google Sites, Docs, Forms and Firebase storage are no longer treated as official | A phishing page on sites.google.com had been passed as an official Google page | Kept, in the engine, the judge and the phone build |
| 5 | Sampling for the online check used a comparator-based sort, which is biased (14 phishing in a sample of 300) | The earlier online figures (P 99.1 %, R 91.3 %, FPR 0.54 %) came from that biased sample | Withdrawn. Replaced by a Fisher-Yates shuffle with a fixed seed: P 94.7 %, R 94.7 %, FPR 1.79 % on 300 URLs (76 phishing) |
| 6 | URLhaus download as a phishing feed | HTTP 410: the endpoint is retired | Removed. OpenPhish and Phishing.Database are kept. |
| 7 | Newly registered domains (WhoisDS free daily list, two days read) | About 70,000 domains per day. Four look-alikes of UAE institutions among them (salilk.net, salio.in, palik.tech, alik.info). | Kept as a Sentinel source. Names are withheld from public material until they are reported. |

## Literature checked (search results, 24 Nov 2026)

Read the full papers before quoting any number. Figures marked "their own" are the authors' claims.

| Work | What it shows | What we take from it |
|---|---|---|
| Lin et al., Phishpedia, USENIX Security 2021 | A hybrid deep-learning system that finds brand logos in screenshots, without phishing training samples. The authors report that a CertStream deployment surfaced 1,704 new phishing sites in 30 days (their own figure). | Next step for our copied-logo module: match page screenshots against the official logo references |
| PhishIntention, USENIX Security 2022 | Adds a check of what a page asks for to reference matching. Reports a false positive on a benign page with a similar logo. | Use the intent idea: check what a page asks for, not only how it looks |
| Reference-based phishing detection without a pre-defined reference list, USENIX Security 2024 | Reference matching that does not need a fixed brand list | Our UAE brand list is incomplete. This is the way to scale it |
| Oest et al., PhishFarm, IEEE S&P 2019 | 2,380 live, innocuous phishing sites tested against six request filters (user agent, geolocation, JavaScript, .htaccess). Cloaking weakened browser blocklists. | Our cloaking test varies only the user agent. Add geolocation and JavaScript variants. Verify page numbers and DOI 10.1109/SP.2019.00049 before citing. |
| Le et al., URLNet, arXiv 2018 | Character and word CNNs learn a URL representation directly from the string | A challenger model to compare with our logistic regression |
| Huang et al., Pinning Down Abuse on Google Maps, WWW 2017 (UC San Diego and Google) | More than 100,000 fraudulent listings analysed; about 40 % were contractor scams. Google reports a 70 % fall after tighter checks, and 85 % of fake listings caught before they appear (their own figures). | Focus the listing check on categories scammers use most (helplines, contractors) |
| TU Delft 2025 master's thesis, Exploring Malvertising Driven by Brand Impersonation in Search Engine Ads | About 52,000 ads from 605 brands over 24 days; 7.9 % abusive (4,160). Most of the abuse (3,781 ads) is affiliate brand bidding, not look-alike domains. Not peer reviewed. | The ads check should flag brand-name bidding that lands on a non-brand domain, not only look-alike domains |
| Agarwal and Vasek, Examining Newly Registered Phishing Domains at Scale, WEIS 2025 | 15,126 new domains over eleven months; about 26 % used Cloudflare to evade detection; phishing sites lived about 8.6 days on average | A registration watch has a real window before the attack |
| Lim et al., Registration, Detection and Deregistration: Analyzing DNS Abuse for Phishing Attacks, arXiv 2025 | Malicious registrations were flagged in a median of 16.3 days, compromised sites in 86 days | Registration monitoring is an earlier signal than blocklists |
| Seweryn et al., BadDomains: Early Detection of Phishing Domains Registration, Sensors 2026 (DOI 10.3390/s26031041) | Registration-based early detection, live at CERT.PL from 29 Nov 2024 to 28 Jul 2025 | The closest deployed analogue to our newly registered domains source |
| Vendor reports: Forescout, Netcraft, KnowBe4, Netlas (2025) | Telegram bots are the stolen-data channel in many phishing kits. Netcraft reports more than 500 separate tokens in credential-theft kits in one month. Forescout reports about 9,100 domains and 4,145 distinct tokens. Netlas says tokens recur across several domains. | Shared bot tokens link campaigns (our campaign keys). The 28 % token-reuse figure is NOT verified against the primary Forescout report and is not used. |

**Could not verify:** arXiv 2608.07451, cited earlier as "Telegram bot tokens in 42.9 % of 732 live phishing kits". It did not appear in any search, so the claim has been removed from the README.

## Novelty, stated carefully

Newly registered domain monitoring and reference-based phishing detection are established research. What appears new in our set is the combination in one pipeline: a daily free registration feed, UAE institution rules as evidence, a three-vantage cloaking test, a fake-data trap that shows where data goes, and a call hold on Android.

## Experiments (24 Nov, audit pass 2: challenge run on our own code)

Scripts, results and the run log are in the handoff package under audit/. Each number below comes from the same script run before and after the fix.

| # | Change | Result | Decision |
|---|---|---|---|
| 9 | Open redirects on trusted hosts: a link such as google.com/url?q=<address>, or a bank /redirect?url=<address>, passed because the host itself is trusted | Synthetic test (400 caught phishing, three redirect forms): 400 of 400 passed before, 0 of 400 after. The judge now judges the address inside the link and reports the worse verdict. Held-out test split unchanged. | Kept. A trusted host no longer gets a free pass. |
| 10 | Trailing dot on the host (metamzklogi.gitbook.io.) | 5 of 400 passed before, 0 after. The first attempt did nothing because a regular expression lost its backslash; the test caught it. | Kept, in the URL parser every caller uses. |
| 11 | Letter n-gram explanations ("the letters ...") shown to readers | Fragments with no meaning for a reader | Not shown. Scores unchanged. |
| 12 | Campaign linking merged sites on any shared trace (same-day registrations, common icons, shared hosting addresses) | Only high and medium traces now merge; low traces stay in the record. Each campaign states its confidence. The existing campaign test still passes; a new test covers weak traces. | Kept. Sites that share only weak traces are no longer put in one campaign. |

### Results, before and after (same scripts, same data)

| Measure | Before | After |
|---|---|---|
| Red team: open redirect via Google (400 base) | 400 pass (100 %) | 0 pass |
| Red team: open redirect via a bank domain | 400 pass | 0 pass |
| Red team: open redirect via a UAE university domain | 400 pass | 0 pass |
| Red team: trailing dot on the host | 5 pass (1.25 %) | 0 pass |
| Red team: the other 9 transforms (homoglyph, path decoy, percent encoding, userinfo, subdomain brand, query noise, upper case, port, www) | none pass; 0 to 0.75 % downgraded to suspicious | unchanged |
| UAE: phishing that names a rulebook institution (324 URLs, 25 Oct to 24 Nov) | recall 95.7 % (strict) | unchanged |
| UAE: the part whose institution has an .ae domain (103 URLs) | recall 90.3 % | unchanged |
| UAE: the rest (221 URLs) | recall 98.2 % | unchanged |
| UAE: hand-listed open sites (21) | 1 flagged (suspicious, model only) | unchanged |
| New-domain watch, all 77 institutions, two days | 68 candidates, 14 institutions | unchanged; precision not measured |
| Held-out test split (33,766 URLs) | strict P 98.2 / R 93.9 / FPR 0.62 %; cautious P 96.9 / R 95.2 / FPR 1.11 % | identical |
| Official UAE pages, model alone (2,231) | 62 flagged (2.78 %) | identical |
| Unit tests | 54 of 54 | 59 of 59 |

### Still open (found, not fixed)

- Public file hosts: 10 of the 12 misses among the UAE-named URLs sit on S3 or Backblaze B2 buckets (the first pass said 9; corrected). A bucket layer followed (section below). Still open: a labelled benign bucket sample, and typo-tolerant brand matching.
- A famous brand glued to words on a foreign domain (amazonprime-network.fr) is missed when the model is unsure, because the brand rule only counts next to a model that already leans phishing.
- New-domain watch: 68 candidates in two days, most imitating global brands (WhatsApp 26, Apple 18, Amazon 6). The four Salik look-alikes match the earlier count. Precision is unknown until a sample is checked by hand, without visiting the sites.
- Trusted-site redirects: real prevalence unknown. The 57,892 OpenPhish rows we hold contain none.
- Latency: the same test split gave 0.28 and 0.92 ms per URL in two runs. Quote a range, measured on a stated machine.

## Literature checked in audit pass 2 (search snippets; read the full pages before quoting)

Every row below came from a search result in this pass. None of the figures has been checked against the full paper or report.

| Source | What it shows (snippet) | What we take from it |
|---|---|---|
| Silent Push, "Powerful Pivots: Hunting with Infrastructure Fingerprints" (silentpush.com/?p=16741) | A JARM value plus an HTTP hash pulls every domain on matching servers; it can link one operator's campaigns, but it also groups unrelated large providers | Pivot on JARM only together with a second key |
| Intel Insights, "Gone Phishing" (intelinsights.substack.com/p/gone-phishing) | In a Rhadamanthys infrastructure write-up, JARM ranked below banner and certificate-hash pivots | Use certificate and banner pivots first |
| Botnet fingerprint study, 2023 (zenodo.org/records/8421241) | Fingerprints need frequent updates; legitimate hosts increasingly match malicious ones | Treat a fingerprint match as a lead, not as proof |
| MITRE ATT&CK T1656, Impersonation (attack.mitre.org/techniques/T1656) | Mirrors list it under Defense Evasion with no sub-techniques; a newer "Social Engineering: Impersonation" page (T1684.001) also appears | Check the current matrix on attack.mitre.org before mapping brand impersonation |
| ATT&CK T1566 sub-techniques (IntechOpen chapter, secondary source) | Lists T1566.001 (attachment), T1566.002 (link), T1566.003 (service); T1566.004 (voice) comes from the summary's background knowledge | Map URL lures to T1566.002 once confirmed on attack.mitre.org |
| Himdi and Alhayan, Journal of Engineering Research, Sep 2025 (DOI 10.1016/j.jer.2025.08.013) | Arabic phishing-email collection with ensemble detectors and a cross-domain check | Arabic lure text is a data source for the copied-lure check |
| Salloum et al., ACM TALLIP 2023 (DOI 10.1145/3606031) | 1,258 English and Arabic emails; the authors report about 96.8 % (Arabic) and 94.6 % (English) accuracy (their own figures) | A benchmark for email text only, not for URLs |
| ASLC-448 Arabic scam-call dataset (data.mendeley.com/datasets/p384bgyzz3) | 448 annotated Arabic call conversations, nine dialects, paired synthetic audio | For the call-scam module. Licence not confirmed: do not ingest before checking |
| SoK on LLM-generated phishing, arXiv 2508.21457 | Nine stages in which attackers get around LLM guardrails | Expect fluent lures; URL-only checks will miss more |
| PhishDebate, arXiv 2506.15656 | Several LLM agents debate whether a site is phishing | An option for the explanation layer; cost and latency not measured |
| Small language models for phishing websites, arXiv 2511.15434 | Compares 15 models of up to 70B parameters | Locally run small models are a realistic choice for the optional AI layer |
| arXiv 2408.05667 (search summary calls it PhishLang; the search titles differ) | Lightweight LLM with page context and explanation text | Check the title before citing |
| Phishing pages written by LLMs, par.nsf.gov 10514634 | Reports 96 % (website prompts) and 94 % (email prompts); the metric is not shown | Check the metric before quoting |
| Drichel et al., "Finding Phish in a Haystack", ARES 2021 (arXiv 2106.12343) | Real-time phishing classification on certificate transparency logs; criticises earlier work that skipped real logs | A certificate feed is a missing early-warning source for us |
| Scheitle et al., "The Rise of Certificate Transparency", IMC 2018 (arXiv 1809.08325) | CT logs help spot phishing domains; attackers can read the same logs | Certificates can appear before a campaign: a lead time to measure |
| US patent 11546377 B2 | CT monitoring with passive DNS and lexical features; performance claims are self-reported | CT-based early detection is already patented: do not claim it as new |
| SANS ISC diary, 6 Apr 2026 (isc.sans.edu/diary.html?date=2026-04-06) | Analysts still see open redirects in phishing lures in 2026 | Trusted-redirect handling is current |
| SANS ISC diary, May 2025 (isc.sans.edu/diary/31950) | Phishing waves abusing google.com redirects | Same pattern as our redirect test |
| KnowBe4, "Make-Shift Brand Impersonation" (blog.knowbe4.com/make-shift-brand-impersonation-abusing-trusted-domains-with-open-redirects) | Multi-payload campaign; open redirect (CWE-601) as the main technique, per the search summary | Matches the fix we shipped |
| Microsoft, "Widespread credential phishing campaign abuses open redirector links" (2021) | A 2021 campaign that abused open redirectors | Background only |

**Could not verify:** a claim that 350-plus domains used one open-redirect campaign (Microsoft OAuth post; date not shown); the NSF paper's metric; the exact ATT&CK sub-technique list (check attack.mitre.org).

**Novelty note, updated:** certificate-transparency monitoring for phishing is covered by a granted patent (US 11546377 B2) and by academic work. Our claim is narrower: the registration feed, UAE rulebook evidence, cloaking test, and call hold in one pipeline. Do not claim CT monitoring as new.

## Experiments (24 Nov, bucket layer)

| # | Change | Result | Decision |
|---|---|---|---|
| 13 | Public file buckets (S3, Backblaze B2, Azure Blob, Google Storage, Cloudflare R2, DigitalOcean Spaces): the verdict uses the bucket name, the path and the query. A victim's e-mail in the link (raw or base64) is strong evidence; a famous name with lure words is strong; two lure words, or a famous name alone, is suspicious. | Validation (30,528 URLs): strict recall 91.77 to 91.61 %, cautious 93.13 to 93.34 %, strict false alarms 199 to 198. Test (33,766 URLs): strict 93.92 to 93.93 %, cautious 95.24 to 95.35 % (+10 caught), false alarms unchanged. Named UAE phishing: strict 95.7 to 96.3 %; legitimate verdicts 12 to 4. | Kept. |
| 14 | Bucket cap: a bucket file with no victim e-mail and no famous name with lure words is capped at suspicious | Probe: reports-2025.s3.amazonaws.com/annual.html scored 1.00 before any bucket evidence, because the model reads bucket hostnames as phishing-like. Bucket rows, validation: 27 phishing without the cap, 5 with it (24 suspicious); cautious unchanged. Test: 14 without, 5 with (9 suspicious); cautious unchanged. | Kept. Chosen from the probe and the design rule before the split numbers were computed. It costs strict recall on bucket phishing with no content evidence. |
| 15 | Two lure words give suspicious, not phishing | The first version gave phishing at three lure words; reduced to two words at suspicious | Kept. Lure words are weak alone. |

**The model's hostname prior.** Our training data holds almost no legitimate bucket URLs (one in validation, one in test), so the URL model learned bucket hostnames as phishing-like. The probe shows it. The model is not retrained in this pass; the cap limits its effect. A labelled benign bucket sample is the P0 fix.

**Process note.** tools/eval-judge.js writes data/judge-report.json only for the test split. A validation run leaves the test report in place, so a copy taken after a validation run is stale. The validation numbers above come from its console output and from an ablation (same code, bucket layer off), not from a copied JSON.

**Unit tests:** 61 of 61 after the bucket layer.

## Prior art and the UAE test protocol (24 Nov, night, written before the first run)

### What others do (searched 24 Nov; from search results, to be checked against the originals before quoting)

| Source | What it reports | What we do about it |
|---|---|---|
| PhreshPhish, arXiv 2507.10854 (https://arxiv.org/html/2507.10854v2) | Time-based splits and pruning of near-duplicates; older phishing datasets had leakage and unrealistic phishing rates | Phishing is split by time and legitimate sites by domain. We do not yet screen near-duplicates, so diagnostic D1 measures infrastructure reuse instead |
| arXiv 2005.08454 (https://arxiv.org/pdf/2005.08454) | URL classifiers flag legitimate sites of frequently targeted brands (for example Netflix, PayPal) and mislabel URLs that contain "login" | Diagnostic D2 measures false alarms on legitimate URLs with UAE brand tokens and on URLs containing "login" |
| Know Your Phish, arXiv 1510.06501 (https://arxiv.org/pdf/1510.06501) | Brand-based methods miss phishing aimed at brands that were absent from earlier attacks | The UAE set is the easier case, and it is reported as such. We also report which catches come from the rulebook and which from the model |
| arXiv 2411.09813 (https://ar5iv.labs.arxiv.org/html/2411.09813) | URL features may not transfer between datasets | Stated limit: one data family (the OpenPhish history). No transfer claim is made |
| Springer chapter, doi 10.1007/978-3-031-84371-6_16 (2025; abstract only, not read in full), and Hussain and Shabaan 2015 (https://repository.mdx.ac.uk/item/89z14) | The chapter is a design-science detection tool for UAE critical infrastructure; the 2015 paper is an impact study for UAE online banking | No public labelled UAE bank phishing set was found, so our UAE set is constructed and labelled as such |
| OpenPhish academic use (https://openphish.com/academic_use.html) | An academic track for accredited research bodies; non-commercial use; OpenPhish must be named with its URL in outputs | Cite OpenPhish with its URL. The submission repository does not contain the OpenPhish history. The sources disagree on whether the free Community feed is free or paid, so check openphish.com before any external release |
| ADCB StaySafe (https://www.adcb.com/en/consumer-education-awareness/fraud-awareness/phishing-scam) | A bank already points customers to a tool that cross-references sources to flag scam sites | Make a pitch comparison only after checking how StaySafe works |

### Protocol (fixed before the first run; no rule below may change to fit a result)

1. **Phishing:** unique URLs in `data_raw/urlv2/openphish_history.tsv` first seen 25 Oct to 24 Nov 2026 (the test window), whose lowercase text contains a UAE brand token from `data/brands.js` (the UAE block, tokens of 4 or more characters). The script checks that all of them are label 1 in `split_test.tsv`.
2. **Legitimate:** `split_uae.tsv`, the official UAE institution pages, which the shipped model never trained on.
3. **Judge:** `judgeOffline` only, with no network and no page visits. Strict = phishing verdict; cautious = phishing or suspicious. **Model alone:** `mlUrlScore2` flags when `p >= threshold`.
4. **Metrics:** recall on phishing, false-alarm rate on legitimate pages, and precision on the combined set (this depends on the mix, so it is not comparable with the test split). 95% bootstrap intervals, 1,000 resamples, seed 20261124.
5. **Breakdown:** UAE phishing caught by a rule only, by the model only, by both, or by neither.
6. **Diagnostics (not headline; they change no threshold):**
   - D1: the share of UAE phishing whose hostname or registrable domain also appears in phishing first seen before 4 Oct, and recall on the subset with no such overlap.
   - D2: false alarms on validation-split legitimate URLs that contain a UAE brand token or the word "login", compared with all validation-split legitimate URLs.
7. **Honesty:** the test window has been measured after each change, so this set is not blind. Every result is logged here, including weak ones. No threshold or rule changes on the basis of this test.
8. **Privacy:** any phishing URL in output is defanged (hxxp, [.]).



### Result (run once, 24 Nov night; numbers from data/uae-report.json)

| Measure | Value | 95% interval | Note |
|---|---|---|---|
| UAE phishing URLs, n | 14 | | Test window, UAE brand token of 4+ characters, label 1 in split_test |
| Judge, strict recall | 85.7% (12 of 14) | 64.3% to 100% bootstrap; 60.1% to 96.0% Wilson | Wide because n is small |
| Judge, cautious recall | 92.9% (13 of 14) | 78.6% to 100% bootstrap | |
| Model alone, recall | 85.7% (12 of 14) | 64.3% to 100% bootstrap | The same 12 as the judge |
| Official UAE pages, n | 2,231 | | split_uae: pages of the 77 listed institutions |
| Judge, strict false alarms | 0% | | Allowlist by design, so not a finding |
| Model alone, false alarms | 2.78% (62 of 2,231) | 2.11% to 3.50% bootstrap | The honest measure on official pages |
| Precision, combined | 100% | | Trivial with 14 positives and the allowlist, so not a finding |

Breakdown of the 14: caught by both judge and model 12; judge only 0; model only 0; neither 2. Judge catches that carry at least one rule reason: 12.

Diagnostics (not headline):
- D1, infrastructure reuse: no host was seen in phishing before 4 Oct; 2 of 14 registrable domains were. On the 12 with an unseen registrable domain, recall is 83.3% (10 of 12).
- D2, validation split: over all legitimate URLs the judge's strict false alarm rate is 0.72% and the model's is 0.75%. Legitimate URLs with a UAE brand token: 0 false alarms of 31. Legitimate URLs containing the word login: 9 of 43 (21%).
- Post-hoc sensitivity, added after the run and NOT the headline: the substring rule admits spurious matches. Both misses matched the token eand inside a longer word on one unrelated domain, so they are not UAE-branded. With whole-label matches only, 5 of 5 are caught (Wilson 95%: 56.5% to 100%; the bootstrap collapses to 100% at n = 5).
- Login-word cap, measured on validation only and NOT applied: capping login-only strict verdicts at suspicious would remove 7 of 175 false alarms (0.72% to 0.69%) and lose 32 of 6,127 phishing verdicts (recall 92.8% to 92.3%). Not worth it.

Interpretation:
- What the result supports: the judge catches 12 of 14 UAE brand-named phishing URLs in the held-out window, and the model alone catches the same 12. The sample is too small for a firm claim; the interval runs from about 60% to 100%.
- What it does not support: real-world UAE performance. The set is built from brand names, which makes it easier than real life, as the protocol says.
- Known weakness to disclose: legitimate URLs containing the word login are flagged about 1 time in 5 on a small validation sample. The fix belongs to the model work after the submission (more labelled legitimate login pages).
- The judge's 0% on official pages comes from the allowlist and is not evidence. The model alone (2.8%) is the honest figure.
- The test window has been measured after each change, so this set is not blind.

Correction: the 2.8% model-alone figure is for the official pages of the 77 listed institutions (split_uae). It is not a figure for institutions outside the list. Open item 13 in 01_INVENTORY_AND_STATUS.md and any other place that says otherwise must be corrected.

Next step for a stronger, blind UAE result: a fresh set of UAE-brand phishing first seen after 24 Nov, with whole-label matching fixed in advance. That needs new data (an OpenPhish feed download), which needs explicit permission and a licence check first.

## Unseen-data tests (24 Nov, late; written before the first run)

Why: the judges will test on data we have not used. Two tests use data that the model and the rules never saw.

### Test A: Phishing.Database, unseen by domain

1. **Population:** data_raw/urlv2/pdb_active.txt (Phishing.Database active list, undated, 789,051 lines). It is a second source, independent of OpenPhish.
2. **Exclusion:** remove every URL whose registrable domain (the training script's rule) appears in any of these sets: (a) the phishing domains of the training set, rebuilt exactly: OpenPhish rows dated before 4 Oct, plus the Phishing.Database sample that tools/train-url-model2.js draws with seed 7 (160,000 draws, same skip rule); (b) every PhiUSIIL phishing row (a superset of what training used, so the exclusion is conservative); (c) the OpenPhish validation and test windows (from 4 Oct).
3. **Judge:** judgeOffline only, with no network. Strict = phishing verdict; cautious = phishing or suspicious. Recall with a 95% bootstrap interval (1,000 resamples, seed 20261124).
4. **Not measured here:** the false-alarm rate on unseen legitimate sites. The held-out figure (0.58 %) stands, and the limit is stated.
5. **Limit:** Phishing.Database has no dates, so this is a domain-disjoint test, not a time-disjoint one.

### Test B: new domains, early detection

1. **Population:** the raw new-domain lists of 22 and 23 Nov 2026 (data_raw/nrd, one registrable domain per line). Local only: no name is published; only counts and medians are written.
2. **Judge:** judgeOffline on https://NAME/ at the list date, with no network.
3. **Confirmation:** a name is confirmed if OpenPhish has any URL on its registrable domain dated on or after its list date, up to 24 Nov.
4. **Report:** how many names the judge flags (strict and cautious); how many flagged names are confirmed (precision); the base rate of confirmation over all names; recall (confirmed and flagged, over all confirmed); and the lead time in days (median and range) for confirmed names.
5. **Limit:** the window after each list is only one to two days, so the confirmed count will be small. Report it as small-n, with its interval.

### Rules for both tests

No threshold or rule changes on the basis of these tests. If a defect is found and fixed, it is logged separately, and the fixed code is run once more on the same test. Every result is logged, including weak ones.

### Test C: the new-domain watch on its own output (early detection)

Why: Test B applied the URL judge to every new domain, which is not how the watch works. The watch looks only for names that imitate one of the 77 rulebook institutions. Test C measures the watch itself.

1. **Population:** the watch's suspects on the raw lists of 22 and 23 Nov, computed by the production function suspectsIn in server/nrd.js with the production thresholds (look-alike letters or a brand token, risk at least 0.6, weak tokens only as look-alikes). Local only; no name is written.
2. **Confirmation and lead time:** as in Test B. A suspect is confirmed if OpenPhish has a URL on its registrable domain dated on or after its list date, up to 24 Nov.
3. **Report:** suspects per list; precision (confirmed suspects over suspects); base rate (confirmed names over all names in the same list); lift (precision over base rate); recall on confirmed names; lead time in days (median and range).
4. **Limit:** the confirmation window is one to two days, so the counts are small. Lead time is claimed only for confirmed cases.
5. **Rule:** no threshold or rule changes on the basis of this test.

## Results of the unseen-data tests (24 Nov, late; each run once; numbers in data/unseen-report.json and data/watch-report.json)

**Test A, Phishing.Database, unseen by domain**
- Population 789,052 lines. Excluded 496,615, because their registrable domain was seen in training, validation or test. Unseen: 292,437.
- Recall, strict: 88.96 % (95 % interval 88.85 % to 89.08 %). Cautious: 93.12 % (93.03 % to 93.22 %).
- Limits: domain-disjoint, not time-disjoint. No unseen legitimate sites, so no false-alarm figure here.

**Test B, new domains through the judge (not the watch)**
- 140,000 names (22 and 23 Nov). Flagged strict: 24,025 (17.2 %). Flagged phishing or suspicious: 31,881 (22.8 %).
- Confirmed later in OpenPhish within one to two days: 330 names (0.24 %). Precision of strict flags: 0.49 %, about twice the base rate.
- Reading: the judge is built for URLs with paths and for messages, not for bare lists of new domains. The population is unlabelled, so these flags are not accuracy evidence and must not be presented as accuracy.

**Test C, the new-domain watch on its own output**
- 68 suspects (25 on 22 Nov, 43 on 23 Nov).
- Confirmed: 1 suspect, on the same day (lead 0 days). Precision 1.5 %, base rate 0.24 %, lift about 6 on one event. Recall on the 330 confirmed names: 0.3 %.
- Reading: the watch sees only look-alikes of the 77 institutions, so it cannot see most phishing. The sample is too small to measure precision or lead time. Lead time is not claimed.

**No-error tests (five new, run in npm test)**
- 3,000 seeded random inputs through the judge; 1,500 through the model and the analyser; 30 hostile edge cases; a messy list file; a 20,000-URL list.
- One expectation was corrected, not the code: an input that is not a web address carries score null by design.
- Full suite: 99 of 99 pass (re-run 24 Nov, late; exit 0).

**Code change, behaviour unchanged:** server/nrd.js. The per-list check moved into suspectsIn, so Test C runs the production code. It reproduces the 68 suspects.

## Attack-style robustness test (24 Nov, night; written before the first run)

Why: judges will try attack styles against the judge. We test each style on real held-out URLs, both phishing and legitimate, so that we see whether a style breaks detection or creates false alarms.

1. **Base URLs:** a seeded sample of 2,000 phishing and 2,000 legitimate URLs from the held-out test split. Real URLs, real labels.
2. **Transforms (18):** identity; uppercase host; percent-encoded host; credentials before the host; subdomain stuffing; open-redirect wrapper (google.com/url); IP-address host; Cyrillic homoglyph; cheap TLD swap; hyphen words inserted; base64 redirect parameter; long path padding; short-link wrapper (bit.ly style, destination unknown); plain http; defanged form; tracking parameters; unicode full stop; encoded path. Each transform keeps the label of the base URL.
3. **Judge:** judgeOffline only. Strict and cautious recall on phishing; strict and cautious false alarms on the transformed legitimate URLs.
4. **Labelled synthetic set (reported separately, never an accuracy claim):** generated here from 40 UAE brand tokens and 25 attack patterns. Labelled synthetic in every output. It tests coverage of patterns, not real-world accuracy.
5. **Third-party set (reported separately):** cheap, real look-alike domains named in public news and third-party scanner reports. Each is labelled phishing by its source; the source is recorded in the workspace audit folder, not in the repository.
6. **Rules:** no threshold or rule changes on the basis of this test. Any defect found is logged separately and re-run once.

## Synthetic-augmented candidate model (24 Nov, night; decision rule written before training)

Why: judges will send URL styles we have not seen. A candidate model is trained with labelled SYNTHETIC phishing added to the training set. The shipped model is kept unless the candidate is better on REAL data.

1. **Synthetic data:** 30,000 phishing URLs from tools/gen-synthetic-phishing.js (seed 20261124), labelled synthetic in every row. They are added to the training set only. They never enter validation or test, and none of them equals a real held-out URL (checked).
2. **Untouched:** the validation and test splits, the Phishing.Database unseen set, and the rulebook. The shipped model file and report are not overwritten; the candidate writes to data/candidate/.
3. **Decision rule (fixed before training):** the candidate replaces the shipped model only if all of these hold on REAL data: (a) strict recall on the held-out test falls by no more than 0.5 points; (b) strict false alarms on the held-out test stay at or below 0.8 %; (c) the unseen Phishing.Database recall rises by at least 1 point, or the attack test shows real improvement on at least three transforms; (d) the false-alarm rates on plain-http and cheap-TLD legitimate URLs do not rise. Otherwise the shipped model stays.
4. **Reporting:** both models are reported side by side, whichever one ships. The synthetic data is never reported as accuracy.

## Zero-shot LLM second opinion on SmishX (24 Nov, late; written before the first run)

Why: our rules caught 6.6 % of SMS phishing on SmishX when run blind, and 32 % only after fixes made while looking at that data. An LLM second opinion is the method several teams use. This run measures one, on the same dataset, without tuning.

1. **Data:** data_raw/smishx/dataset.csv (SmishX, public, MIT). Positives are the 259 messages labelled smishing (called phishing here); negatives are the 622 labelled legitimate. Spam messages are excluded, as in tests/bench-smishx.js.
2. **Model and call:** a hosted, non-Claude model through the Groq API (default llama-3.3-70b-versatile), one zero-shot call per message, temperature 0, maximum 5 output tokens. The system prompt is fixed in tools/eval-llm-smishx.js and is not changed after seeing results.
3. **Scoring:** an answer containing PHISHING is a flag. Recall on phishing and false alarms on legitimate messages, with 95 % Wilson intervals. Unparseable answers are counted and reported.
4. **Key handling:** the API key is read only from the environment (GROQ_API_KEY). It is not written to any file, not printed, and not committed.
5. **Limits:** this is a different model from the product's AI layer, which uses Claude. The result says what a hosted LLM does zero-shot; it is not a Claude result. A Claude run needs the team's Anthropic key.
6. **Rule:** this result is reported whatever it shows. It does not change the rules engine or any threshold.

## Results: attack-style test, unseen-miss diagnosis, labelled synthetic and third-party sets (24 Nov, night; each run once)

**Attack-style test** (2,000 real held-out phishing and 2,000 legitimate URLs; 18 transforms; judge offline; numbers in data/attacks-report.json)
- Identity baseline: phishing recall 94.15 % strict and 95.85 % cautious; false alarms on legitimate 0.8 % strict and 1.1 % cautious.
- Strict recall stays at 93.7 % or higher in 17 of the 18 rows (identity included). The exception is the short-link wrapper, at 57.0 %. Values: identity 94.15 %; uppercase host, percent-encoded host, defanged form and unicode full stop 94.15 %; open-redirect wrapper 94.25 %; tracking parameters 94.05 %; encoded path 93.7 %; credentials before the host 99.3 %; subdomain stuffing 99.35 %; IP-address host 94.25 %; Cyrillic homoglyph 99.5 %; cheap TLD swap 99.8 %; hyphen words 100 %; base64 redirect parameter 100 % (design caveat below); long path 99.05 %; plain http 99.2 %.
- Short-link wrapper (destination unknown offline): strict recall 57.0 %, cautious 100 %. This matches the documented policy: a short link with an unknown destination is at least suspicious offline.
- Each transform that adds a suspicious feature also raises false alarms on the transformed legitimate URLs. The rates are high for IP hosts (83 %), cheap TLDs (76 %), credentials (80 %), subdomain stuffing (77 %), homoglyphs (94 %), hyphen words (96 %) and long paths (60.5 %). Plain http reaches 56 %, and that matters most for real legitimate sites. The cheap-TLD and plain-http figures are the ones to fix first; see the candidate-model entry below.
- Design caveat: the base64 redirect transform gives every URL the same non-official host, so its 100 % recall and 100 % false alarms say nothing about the judge. It must be redesigned before it is quoted.

**Unseen-miss diagnosis** (Phishing.Database unseen by domain; 292,437 URLs; 32,290 misses; data/unseen-misses-report.json)
- 73 % of the misses (23,584) are ordinary-looking domains with no brand token, no lure words, a domain outside the top 100,000 and an ordinary top-level domain. Without page content these look like small legitimate sites, so an offline URL judge cannot separate them.
- Public file hosts: 4,937 of 4,983 are missed by the strict verdict. The bucket layer caps files without a victim e-mail or lure words to suspicious, so this part is by design. The cautious figure for these files is not yet measured.
- Free hosting and site builders: 82,353 of 82,354 caught. IP hosts: all caught. Cheap TLDs: 98.6 %. Brand tokens: 97.0 %. Lure words: 97.0 %. Popular domains (top 100,000): 48.3 %, on 704 URLs.
- Reading: the 89 % is not one weakness. It is the limit of a URL-only offline judge. Page content and the online checks would address most of the misses, and the offline judge does not use them.

**Labelled synthetic set** (975 URLs, labelled SYNTHETIC in every output; a coverage check only, not an accuracy claim): caught 100 % strict and cautious. The patterns are the ones the rules already cover, so this result is circular and says nothing about real accuracy.

**Third-party set** (six real look-alike or phishing domains named by public sources; names and sources kept in the workspace audit folder): caught 5 of 6 strict and cautious.

**Provenance** (code change, verdicts unchanged): every reason now carries its source (rule, model, allowlist, popularity, bucket layer, online check, feed, input or AI). Tests in tests/provenance.test.js pass. Regression on the 33,634 held-out test URLs: verdicts, scores and reason IDs are identical before and after the change (0 differences); 31,314 reasons are tagged and none is untagged.


**Amendment before the run (24 Nov, late; a technical change, not a result).** The pre-registered model llama-3.3-70b-versatile is not available on this account (HTTP 404, model_not_found, checked 24 Nov). The first attempt made 881 requests, all failed, and produced no result. Nothing from that attempt is reported as an accuracy figure. The substitute is qwen/qwen3.8-27b, chosen because it returns a clean one-word answer within the same five-token budget. Tested once each on one SMS: allam-2-7b returns the word but is cut off by the budget, and openai/gpt-oss-120b returns no content within the budget because its reasoning uses it. The prompt, the data, the temperature, the budget and the decision rules are unchanged.

## Result: synthetic-augmented candidate against the shipped model (24 Nov, late; each model run once)

Set-up. The control and the candidate use the same pipeline and the same test split (33,634 URLs: 9,039 phishing, 24,595 legitimate). The control has no synthetic rows; the candidate adds 30,000 labelled SYNTHETIC rows to training only. The shipped model was measured earlier on its own test split (33,766 URLs, 9,039 phishing), so its legitimate counts differ slightly.

| Measure | Shipped | Control (no synthetic) | Candidate (+30,000 synthetic) |
|---|---|---|---|
| Training rows | | 473,919 | 503,919 |
| Threshold in the model file | 0.825 | 0.785 | 0.72 |
| Test recall, strict | 94.47 % | 94.68 % | 95.35 % |
| Test precision, strict | 98.35 % | 98.20 % | 97.85 % |
| Test false alarms, strict | 0.58 % | 0.64 % | 0.77 % |
| Test recall, cautious | 96.19 % | 96.34 % | 96.65 % |
| Test false alarms, cautious | 1.05 % | 1.31 % | 1.55 % |
| Crawled legitimate pages, false alarms, strict | 1.75 % | 1.98 % | 2.45 % |
| Official UAE pages (2,231), model alone, false alarms | 2.78 % | 3.18 % | 4.53 % |
| Attack test, legitimate URLs with plain http, false alarms (strict) | 56.25 % | 55.00 % | 56.25 % |
| Attack test, legitimate URLs with a cheap TLD, false alarms (strict) | 76.00 % | 76.20 % | 83.05 % |
| Third-party look-alike domains caught (of 6) | 5 | 5 | 6 |
| Labelled synthetic set caught (of 975; circular, not an accuracy claim) | 975 | 975 | 975 |

Pre-registered rule (fixed before training; all four must hold on real data):

- (a) Test strict recall falls by no more than 0.5 points against the shipped model: met. The candidate is 0.88 points higher.
- (b) Test strict false alarms at or below 0.8 %: met, with little room (0.77 %).
- (c) Unseen Phishing.Database recall up by at least 1 point, or real attack-test improvement on at least three transforms: the attack test shows recall at least 1 point higher than the control on three transforms (IP-address host, short-link wrapper, tracking parameters). Two of these came with much higher false alarms (IP-address host 66.20 % to 82.85 %; short-link wrapper 13.00 % to 45.05 %), so they are not counted as real improvements. On the unseen set the rule is met: Phishing.Database recall is 90.06 % against 88.96 % for the shipped model (+1.10 points; see the entry below).
- (d) False alarms on plain-http and cheap-TLD legitimate URLs do not rise: NOT met. Cheap-TLD false alarms rise from 76.00 % (shipped) and 76.20 % (control) to 83.05 %. Plain-http false alarms rise from 55.00 % to 56.25 % against the control.

Decision: the candidate does not replace the shipped model. Rule (d) fails, and the rule needs all four. Nothing in the product changes: data/judge-report.json is byte-identical to the copy taken before the run. The control and the candidate stay in project/data/candidate/ as documented results.

Reading outside the rule (recorded, not used for the decision): the candidate gains 0.67 points of phishing recall over the control and pays 0.13 points more false alarms on the test split. Its false alarms also rise on crawled legitimate pages (1.98 % to 2.45 %) and on official UAE pages (3.18 % to 4.53 %). The judge's allowlist hides the official-page figure for the 77 listed institutions, but not for institutions outside the list. The trainer chose a threshold of 0.72 for the candidate (0.785 for the control), so part of the trade-off comes from the threshold, not only from the patterns. The 975 synthetic URLs are caught by all three models, which is circular and says nothing about real accuracy.

## Result: unseen-data comparison, candidate and control (24 Nov, late; each run once; numbers in project/data/candidate/unseen-*.json)

Population: 292,437 Phishing.Database URLs whose domain is not in the training domains, the same count for all three models. Test B is the new-domain judge over 140,000 names (not the watch). It is reported as small n and is not accuracy evidence, because the population has no labels.

| Measure | Shipped | Control (no synthetic) | Candidate (+30,000 synthetic) |
|---|---|---|---|
| Phishing.Database unseen by domain, recall, strict (95 % interval) | 88.96 % (88.85 to 89.08) | 89.19 % (89.08 to 89.31) | 90.06 % (89.95 to 90.17) |
| Same set, recall, cautious | 93.12 % | 93.24 % | 93.87 % |
| New-domain judge, names flagged strict (of 140,000) | 24,025 | 23,803 | 27,011 |
| Names confirmed later within 1 to 2 days (of 330): precision, strict | 0.49 % | 0.47 % | 0.48 % |
| Recall of the judge on the 330 confirmed names, strict | 35.45 % | 33.94 % | 39.70 % |

Reading. On real unseen data the candidate is the best of the three. Its recall is 1.10 points above the shipped model, and the intervals do not overlap, so rule (c) is met on this set. Its precision on new domains does not rise (0.48 % against 0.49 %), and it flags more names (27,011 against 24,025). The gain is real on this set. It comes with the false alarms recorded above, and those fail rule (d). The rule therefore still says keep the shipped model.

Caveats. The set is domain-disjoint, not time-disjoint. The training data of the two pipelines differ slightly through the date-split drift already recorded. The test window has now been used to decide this question. Any future candidate needs a new pre-registration and a fresh held-out window, not a re-tuning on this split.

## Impersonation test: digits, words, punctuation and letter changes (24 Nov, late; written before the run)

Why. Judges and scammers use look-alike domains: a digit, a word, a punctuation mark or a changed letter added to a real name (microsoft1.com, microsoft-hub.com). The judge must catch them and must say what was changed.

Reference names. The 77 listed institutions in data/institutions.js, using their first official domain when it has two labels (domains with three labels, such as x.gov.ae, are counted and excluded).

Development categories (the rules and the explanation text were written with these in view):
- D1: digit added at the end (name1.com).
- D2: digit in place of a letter (l to 1, o to 0, e to 3, s to 5, t to 7, a to 4).
- D3: one letter dropped.
- D4: one letter doubled.
- D5: two neighbouring letters swapped.

Held-out categories (defined before the run; not used in any rule. Before the run the script checks that none of the held-out words appears in engine/url.js, and it stops if one does):
- H1: country word with a hyphen (saudi, qatar, kuwait). Note: uae, dubai and abudhabi are in the affix list, so they are not held-out.
- H3: exact name on a cheap TLD (xyz, top, shop, online, site, icu).
- H4: exact name on another TLD (net, co, org, info).
- H5: a word with a hyphen (hub, members, home, zone, club). Note: portal, mobile, care, help and center are in the rules, so they are not held-out.
- H6: two reference names joined (name-othername.com).
- H7: "-com" inserted before the TLD (name-com.net).
- H8: underscore in place of the hyphen (name_hub.com).
- H9: "www" glued to the name (wwwname.com).
Year suffixes are not held-out: a digits-only suffix is already covered by an existing rule.

Sample. Three variants per reference name per category, generated with seed 20261124. Each variant is run once.

Legitimate controls (not labelled; used for false alarms only):
- L1: Tranco top 10,000 domains whose name contains a reference name of 5 or more letters. Expected legitimate (popularity guard).
- L2: 10,000 random Tranco domains from ranks 200,001 to 210,000. Assumed legitimate by rank; this is an estimate, not a label.

Metrics. Detection, strict (verdict phishing) and cautious (phishing or suspicious), with Wilson 95 % intervals, per category; also for reference names of 5 or more letters. False-alarm rates on L1 and L2, strict and cautious.

Rules. No rule, threshold or list is changed on the basis of this run. Misses are reported as they are. A fix is developed and tested on a fresh set with another seed before it is reported.

Limits. The variants are generated, not real attacks: they test coverage of the change types, not real-world rates. The labels on L2 are assumed. The explanation text (what was changed) is tested by unit tests and is not part of the verdict; the verdicts are compared with the snapshot taken before the explanation change.

**Amendment before the run (24 Nov, late; no result seen).** The guard in tools/eval-impersonation.js stopped the test because "zone" and "club" appear in engine/url.js, in the list of medium-risk top-level domains. They are removed from the held-out words. H5 and H8 now use hub, members and home only. Two further notes, recorded before the run: the cheap TLDs in H3 (xyz, top, shop, online, site, icu) and "info" in H4 already appear in the existing risk-TLD lists, so H3 and H4 test a combination (an exact brand name on a risky TLD), not a TLD rule designed for this test. No other part of the protocol is changed.

## Results (24 Nov, late; each run once): scale check, impersonation categories, zero-shot second opinion, explanation change

### Scale check: 1,000,000 URLs through the offline judge (data/scale-report.json)
- Input: 500,000 URLs from the Phishing.Database active list, and 500,000 Tranco top-list domains as https addresses.
- Result: 0 errors; 627 s on this laptop; 0.63 ms per URL; peak memory 496 MB; no network.
- Verdicts, all: phishing 471,581; suspicious 20,528; legitimate 507,887; invalid 4.
- Reading. This is a speed and stability test. Its counts are not accuracy. The Phishing.Database half overlaps our training sample, so its 91.4 % phishing share is not a held-out estimate. The popular half is not labelled: 14,668 of 500,000 domains (2.9 %) got a phishing verdict and 4,931 (1.0 %) got a suspicious verdict. Those flags need labels before any false-alarm figure is stated.

### Impersonation categories: 60 listed names, three variants each, seed 20261124 (data/impersonation-report.json)
Development categories (rules and explanation written with these in view). Held-out categories (not in any rule; words checked before the run).

| Category | Variants | Strict | Cautious | Names of 5+ letters, strict |
|---|---|---|---|---|
| D1 digit added at the end | 180 | 63.3 % | 63.3 % | 100.0 % |
| D2 digit in place of a letter | 165 | 85.5 % | 85.5 % | 100.0 % |
| D3 one letter dropped | 114 | 100.0 % | 100.0 % | 100.0 % |
| D4 one letter doubled | 180 | 63.3 % | 63.3 % | 100.0 % |
| D5 two neighbouring letters swapped | 177 | 64.4 % | 64.4 % | 100.0 % |
| H1 country word with a hyphen | 180 | 63.3 % | 63.3 % | 97.4 % |
| H3 exact name on a cheap TLD | 180 | 83.9 % | 86.1 % | 96.5 % |
| H4 exact name on another TLD | 180 | 56.7 % | 56.7 % | 89.5 % |
| H5 a word with a hyphen | 180 | 66.1 % | 70.0 % | 97.4 % |
| H6 two reference names joined | 180 | 91.1 % | 93.3 % | 99.1 % |
| H7 "-com" inserted before the TLD | 180 | 63.3 % | 65.0 % | 97.4 % |
| H8 underscore in place of the hyphen | 180 | 60.0 % | 60.0 % | 94.7 % |
| H9 "www" glued to the name | 180 | 35.0 % | 43.3 % | 55.3 % |

Controls (not labelled; false-alarm rates only).
- L1, popular domains containing a listed name of 5+ letters (199 domains): 0 flagged, strict or cautious.
- L2, 10,000 Tranco domains sampled from ranks 200,001 to 210,000: 2.73 % strict (273), 4.01 % cautious (401). Unlabelled; assumed legitimate by rank.

Reading.
- On names of five or more letters, the digit, letter and swap changes (D1 to D5) are caught in every generated case.
- Every miss in the development categories is a name of fewer than five letters (for example dib, cbd, sca). The look-alike rule does not cover those names.
- Held-out gaps: "www" glued to a name (55 % on names of five or more letters) and the same name on another TLD (89.5 % on five or more; none of the short names is caught). These are reported as gaps. No rule was changed on the basis of this run.
- The 2.73 % on L2 is the same order as the 2.9 % in the scale run. Both populations are unlabelled, so the figures show how often the judge gives a phishing verdict on those domains, not how often it is wrong.
- Limits. The variants are generated, not real attacks. 60 of the 77 listed names were used: 17 have three-label domains (for example x.gov.ae) and were excluded. The held-out words were checked against the rule code before the run.

### Zero-shot second opinion on SmishX: qwen/qwen3.8-27b through Groq, not Claude (data/llm-smishx-report.json)
- Positives (smishing) 259; negatives (legitimate) 622.
- Recall 93.8 % (95 % interval 90.2 to 96.2 %). False alarms 7.6 % (5.7 to 9.9 %).
- 9 requests failed and 10 answers could not be read. Both count as "not flagged", as the protocol says.
- Reading. A hosted open model, without any tuning, finds far more of these messages than our rules did blind on the same data (6.6 %). Its false-alarm rate is too high to use alone. This is a research result. The product's AI layer is Claude, optional and off by default, and it was not tested in this run.

### Explanation change for look-alike domains (no verdict change)
- Verdicts, scores and reason IDs: 0 changes on the 33,634 held-out test URLs. The reason text changed on 7 URLs that carry a look-alike reason.
- The reason now names the change (for example "adds the digit 1 to the real name", "uses the digit 0 in place of the letter o", "drops the letter t", "swaps two neighbouring letters"), in English and Arabic.
- Unit tests: tests/impersonation.test.js (5 tests). Full suite: 99 of 99 pass.

## SMS second opinion, held-out split (24 Nov, evening; written before any run)

Why. The SMS channel is the weakest one: our rules catch 6.6 % of the 259 smishing texts when run blind, and the rules were tuned on this set after that run. A cloud second opinion (a zero-shot model through Groq, the research prompt P1) reached 93.8 % recall and 7.6 % false alarms on the whole set, but that prompt was not tested on a held-out half. This protocol gives a clean estimate.

Data. data_raw/smishx/dataset.csv: the 259 smishing and 622 legitimate messages (spam excluded). The split is stratified and seeded (20261125): half of the smishing messages and half of the legitimate ones form the dev set; the other halves form the test set.

Prompts. P1 is the research prompt, unchanged. P2 is P1 plus one sentence listing the cues that often appear in scam texts (a link to act on, a deadline or threat, a request for a code, a payment or personal details, a parcel, a prize or refund, a locked or suspended account). Both are fixed here, before any dev run.

Procedure. (1) Run P1 and P2 on the dev set. (2) Choose the prompt with the higher dev recall, if it keeps the dev false-alarm rate within 3 points of P1's; otherwise keep P1. Pre-registered. (3) Run the chosen prompt once on the test set. Report test recall and false alarms with 95 % Wilson intervals. The test set is not used for any choice.

Policy in the app (pre-registered). The cloud answer never turns a message red. A PHISHING answer on a message the rules did not flag shows as a caution card. Red stays with the rules.

Limits. The model is a hosted open model, not Claude; the product's AI layer is Claude and it is optional. The rules part is not blind (tuned on this set), so the blind figure for the cloud layer is the test-set figure. One run per phase; no retries of a failed item except the built-in retry on rate limits.

## Brand scale test (24 Nov, late; written before the run)

Why. The UAE test was small (14 positives) and all of its brands were in our rulebook. The judges need a larger test on brands the rulebook does not list, big and small, UAE and global, government and commercial.

Data. (1) Brands: the public domains in the Tranco top list, ranks 1 to 100,000, names of four letters or more (Tranco is a public ranking). The UAE brands are the .ae domains in that list. (2) Variants: for each brand, ten generated look-alikes, one per category (digit, leet, dropped letter, doubled letter, swapped letters, country word with a hyphen, cheap TLD, word with a hyphen, "-com", "www"). These are synthetic phishing and are labelled SYNTHETIC in every output. (3) Own domains: each brand's own domain, judged on its own. A flag is a false alarm, because it is a real site (popular sites are protected by the popularity guard, small ones are not). (4) Assumed-legitimate controls: 100,000 domains from Tranco ranks 500,001 to 600,000, assumed legitimate by rank (an estimate).

Metrics. Detection (strict and cautious) per category, per brand rank band (1 to 1,000; 1,001 to 10,000; 10,001 to 100,000), for names of five letters or more, for the UAE brands, and for brands outside the rulebook. False alarms on own domains and on the assumed-legitimate controls, with 95 % Wilson intervals.

Rules. The rulebook, the thresholds and the rules are not changed by this run. A miss is a miss. Any change that follows is tested on a fresh sample (another seed).

Limits. The variants are generated, not real attacks. The Tranco list is a ranking, not a list of verified legitimate sites, so the own-domain and control false alarms are upper bounds for small brands.

## Amendment to the brand scale test (24 Nov, late; logged before the re-run)

The first run counted as cautious every verdict other than "legitimate". judge.js returns four verdicts: phishing, suspicious, legitimate, and invalid (input that is not a URL). Counting invalid as a flag was not intended. The script now counts cautious as phishing or suspicious, the same definition judge.js uses for its own cautious rate. The strict count (phishing only) is unchanged. The first run was stopped after about five minutes, before it wrote any output, so no number from it was read. The re-run uses the same seed, brands and controls.

## Live CT watch (24 Nov, late; written before the run)

Why. The radar asks crt.sh on demand for a fixed list of names, so it cannot say how long after issuance we would see a certificate. That gap is the reason Early detection scored 4: no continuous watch and no measured lead time. This protocol reads the public logs directly and measures the delay.

Data. The published v3 log list from Google. Logs read: state usable, production, and not ended on the day of the run. Logs not read are listed in the report with their state (readonly, retired or ended). Certificates are the public entries of those logs. No name is stored.

Method. Each log is polled for its tree head every 5 seconds. The watch starts at the head it finds, and every entry added after that is fetched in batches of 32. For each certificate the DNS names (up to 100) are judged offline with judgeOffline. A name is flagged when the verdict is phishing or suspicious.

Metrics. Coverage (entries fetched / entries sequenced in the window). Latency with the 50th, 90th and 99th percentiles: issuance to log (log time minus not-before), log to watch (our time minus log time), and issuance to watch (our time minus not-before), for all certificates, for flagged certificates, and for flagged certificates with a UAE institution token in a name (approximate). A flagged name whose registrable domain is in the Tranco top 100,000 is counted as a likely false alarm; this is a lower bound on false alarms, because a flagged name outside the top list can still be a real site. Counts by log and by issuer.

Rules. The report keeps counts and times only; no domain is written. A flag is a judgement of the offline judge, not a confirmed scam. The first run is 10 minutes; a longer run follows the same procedure.

Limits. The judge is not labelled on live certificates, so there is no precision figure. In the list, the current Google shards are readonly and the current Let's Encrypt shard is retired, so certificates they would have carried are seen only through the logs still accepting entries. That is measured in the report, not assumed.

## Amendment to the live CT watch (24 Nov, late; logged before the measured run)

A one-minute smoke test (11,653 certificates from 17 logs) showed three faults. This amendment corrects them before any measured run. The smoke output is not reported as a result.

(1) Coverage was 30 %. Batches of 32 entries per request were too small to keep up, and 21,045 entries were skipped. The batch is now 256 entries per request. A log may return fewer than it was asked for; the watch takes what it gets and advances by that count. The probe showed the logs return up to about 200 to 255 entries per request.

(2) The generic judge flagged 27 % of raw certificate names as phishing or suspicious, most of them random names on shared hosting. Judging every name that way does not give a usable alert. The alert rule is now a brand gate. A name is judged when its registrable domain carries a UAE institution token (the 60 rulebook names, matched approximately: whole hyphen-separated part, or a prefix or suffix of the domain name). An alert is a brand-gated name judged phishing or suspicious on a registrable domain outside the Tranco top 100,000. A seeded 2 % sample of the other names is judged as well, so the generic rate is measured with an interval.

(3) The latency is split. Log to watch is measured for every entry. Only precertificate entries (logged before issuance) give an issuance time, so the issuance measures use them only, and only where the not-before is within two days of the log time (older certificates are sometimes added to a log much later). The smoke median of about 3,600 s from not-before to log suggests that not-before is backdated by a CA; the report shows that offset and does not correct it.

The measured run is 10 minutes with this procedure. It is run once. Any later change is logged before it is run.

## Amendment to the brand scale test: a reporting bug (24 Nov, late; logged before the re-run)

The first full run shared one tally for the outside-rulebook figures between the synthetic variants and the brands' own domains, so the two were added together. The report's "outside the rulebook" line therefore mixed them, and that figure is withdrawn. The script now keeps two tallies. The rules, the thresholds, the seed (20261126), the brands and the controls are unchanged. The corrected run is repeated once with the same seed. Its other figures should match the first run; any difference is reported as is.

## SMS local model, held-out split (24 Nov, late; written before the run)

Why. The cloud second opinion cannot be measured today. The Groq key's daily request allowance (1,000 requests) is used up, and the reset is 24 hours away. Both dev runs (P1 and P2) were stopped when this was confirmed. Neither wrote a result, and the test phase was not run. No cloud number from those runs is reported. The earlier zero-shot figures on the whole set (93.8 % recall, 7.6 % false alarms) are not held-out and stay labelled as such. The rules catch 6.6 % of the smishing texts when run blind, so the SMS score needs a measured alternative that does not send text to a cloud service.

Data. The same dataset and split as the cloud protocol: 259 smishing and 622 legitimate messages, stratified and seeded (20261125), dev half and test half.

Model. A multinomial Naive Bayes model with Laplace smoothing (alpha 1). Features: word unigrams, word pairs, and three cues (a link, a number of four or more digits, Arabic script). It runs on the device, so the text does not leave the phone. It is trained on the dev half only.

Threshold. Chosen on the dev half only: the threshold with the highest dev recall whose dev false-alarm rate is at most 2 %. If no threshold meets that, the report says so and nothing is tested.

Test. The chosen threshold is applied once to the test half. Report recall and false alarms with 95 % Wilson intervals. The test half is not used for any choice.

Limits. One dataset, mostly English with some Arabic; the result is not a claim about every SMS. The model has no URL judgement. The app does not use it until the phone test. Any later change needs a fresh seed and a new log entry before it runs.

## Result: SMS local model, held-out split (24 Nov, late; run once)

Dev half (440 messages: 129 smishing, 311 legitimate). The threshold 11.36 gives dev recall 100 % and dev false alarms 0 %. The dev half separates almost perfectly, which is why the chosen threshold is high.

Test half (441 messages: 130 smishing, 311 legitimate), applied once. Recall 65.4 % (85 of 130; 95 % interval 56.9 to 73.0 %). False alarms 0 % (0 of 311; 95 % interval 0 to 1.2 %).

Reference. The rules, run blind on all 259 smishing texts, caught 6.6 %. The test half is 130 of those 259 texts, so the comparison is rough, but the direction is clear.

Note on the threshold. The protocol said to take the highest dev recall with dev false alarms at most 2 %, and did not say how to break a tie. The code took the higher threshold among the ties. The choice was fixed before the test ran and was not changed afterwards.

Result. The on-device model is a measured improvement with no false alarms on the test half. It is not at the target. The cloud second opinion is still not measured: its dev runs stopped on the daily request limit, and its held-out test needs the next day under its own protocol.

Limits. The model is trained on 440 messages, and the dataset is small. The app does not use it yet; it needs a phone test before any claim about the phone.

## Result: brand scale test (24 Nov, late; run once with the reporting fix, same seed)

Brands: 92,732 of the top 100,000 Tranco ranks (names of four letters or more, with a registrable domain). UAE brands: 46 (11 are in the rulebook). Synthetic variants: 917,396, all labelled SYNTHETIC. Strict = judged phishing; cautious = phishing or suspicious. Intervals are 95 % Wilson intervals where given.

By category (strict, cautious): digit 3.8 %, 7.0 %; leet 3.2 %, 5.7 %; dropped letter 1.9 %, 2.8 %; doubled letter 2.1 %, 3.3 %; swapped letters 1.9 %, 2.8 %; country word 3.0 %, 5.1 %; cheap TLD 58.9 %, 71.9 %; word with hyphen 4.3 %, 7.7 %; "-com" on .net 0.9 %, 1.9 %; "www" 5.3 %, 10.3 %.

By brand rank (strict): top 1,000: 12.4 %; 1,001 to 10,000: 9.1 %; 10,001 to 100,000: 8.5 %.

By name length (strict): five letters or more, 8.5 % (73,013 of 858,030); four letters, 9.8 % (5,842 of 59,366).

UAE brands (strict): 21.2 % (96 of 452; 95 % interval 17.7 to 25.2 %). Thirty-five of the 46 UAE brands are not in the rulebook.

Outside the rulebook (strict): variants 8.3 % (76,239 of 914,431; 95 % interval 8.3 to 8.4 %).

False alarms. The fair figure is the control set, assumed legitimate by rank (ranks 500,001 to 600,000; an estimate): 2.67 % strict (2,670 of 100,000; 95 % interval 2.57 to 2.77 %), cautious 3.6 %. The brands' own domains give 0.04 % strict (39 of 92,434 outside the rulebook), but that is not a fair test: the same Tranco list feeds the popularity guard, so most of those domains are protected by design.

Reading. Detection is high only for what the rulebook knows. The largest gap is the cheap-TLD clone (58.9 %). For UAE brands, the gap is coverage: 35 of the 46 are not in the rulebook. Adding them needs verified official domains, phone numbers and rules, which were not done here. No rule was changed in this run. A rule change would be tested on a fresh seed, as the protocol says.

## Result: live CT watch, run 1 (24 to 25 Nov; 10.5 minutes; the measured run as amended, run once)

Coverage. 853,786 entries were sequenced in the window and 282,523 were fetched: 33.1 % (the rest were skipped when a log fell more than 5,000 entries behind). Five high-volume shards were skipped most: Cloudflare Nimbus2026 (3 %), DigiCert Wyvern2027h1 (43 %), DigiCert Sphinx2027h1 (46 %), Sectigo Elephant2027h1 (18 %), Sectigo Tiger2027h1 (19 %). The fetch rate was 449 entries per second.

Certificates. 282,523 certificates: 135,762 precertificates and 146,761 final certificates. 390,641 DNS names seen, no parse errors.

Brand gate (names with a UAE institution token). 36,193 names judged: 27,068 phishing, 640 suspicious, 8,485 legitimate. 27,628 of the flagged names were on Tranco top-100,000 domains, which is why the judge's "phishing" count is not an alert count. Alerts (flagged and not on a popular domain): 80.

Generic sample (2 % of other names): 8,285 judged, 1,824 phishing or suspicious: 22.0 % (95 % interval 21.1 to 22.9 %). The judge flags raw names too often to be used as an alert on its own.

Latency. Log to watch, all certificates: median 76.7 s, 90th percentile 238.8 s, 99th percentile 1,143.5 s. Log to watch, alerts: median 27.3 s, 90th percentile 163.0 s, 99th percentile 285.6 s (n = 80). Not-before offset for precertificates (log time minus not-before, within two days): median 3,603 s, about an hour, which is consistent with certificate authorities backdating not-before. Issuance to watch for precertificates: median 3,633 s; for alerts (n = 41): median 3,620 s.

Reading. The watch did not keep up on the busy shards, so run 1 does not show the lead time. The brand gate is too wide. The alerts are a candidate list, not a precision figure: no labels exist for live certificates.

## Amendment to the live CT watch, before run 2 (24 to 25 Nov; logged before the run)

Run 1 (the measured run above) reached 33 % coverage. The cause is in the fetch loop: each log's batches were requested one after another, so the busy shards fell behind and 570,491 entries were skipped. Run 2 fetches up to four batches of 256 entries at once per log. The batches are processed in order, and a short batch restarts the next round from where the log actually stopped. The skip rule (5,000 entries) is unchanged. Only the rate of fetching changes; no judgement changes.

The brand gate in run 1 matched generic words that the offline judge already treats as generic (bank, post, police, finance, emirates, customs, courts, tax, centralbank, gov). Most of the 27,628 flagged brand-gated names were on popular domains, so those words add noise. Run 2 excludes the same generic words the judge excludes. The UAE institution tokens that remain are the names the rulebook keeps.

Run 2 is 10 minutes, run once, with the same sample rate and the same alert rule. Its report is kept next to run 1's report and reported beside it; run 1 is not replaced.

## Amendment to the live CT watch, before run 3 (25 Nov; logged before the run)

Run 2 reached 38.5 % coverage, with a median of 34 s from log to watch. The loss is in the busiest shards: Sectigo Elephant 2027h1 and Tiger 2027h1 at 15 to 16 %, DigiCert Wyvern and Sphinx 2027h1 at 49 to 53 %, TrustAsia HETU2027 at 25 %. These logs return fewer entries than asked: about 142 of 256 on Elephant in the probe. Batches of 256 at fixed offsets therefore lose most of their results, because the cursor only moves by the short length.

Run 3 sizes each batch to the number of entries the log returned last time (the stride). Starting at 256, the stride drops to the length of a short batch and returns to 256 after a full one. The parallel batches then stay contiguous and all of them are kept. The skip rule (5,000 entries) is unchanged.

Nothing else changes: the same logs, brand gate, alert rule and sample. Run 3 is 10 minutes, run once. Its report is kept beside runs 1 and 2.

## Result: live CT watch, run 2 (25 Nov; 10.2 minutes; run once, after amendment 2)

Coverage. 257,999 of 670,545 entries fetched: 38.5 %. Four batches of 256 per log, per round. The busiest shards were still short: Sectigo Elephant 2027h1 16 %, Tiger 2027h1 15 %, DigiCert Wyvern 2027h1 49 %, Sphinx 2027h1 53 %, TrustAsia HETU2027 25 %.

Certificates. 257,999: 129,257 precertificates and 128,742 final certificates; 352,763 DNS names seen; no parse errors.

Brand gate (generic words excluded). 25,961 names judged: 17,070 phishing, 600 suspicious, 8,291 legitimate. 17,547 of the flagged names were on Tranco top-100,000 domains. Alerts (flagged and not on a popular domain): 123.

Generic sample (2 % of other names): 7,544 judged, 1,894 flagged: 25.1 % (95 % interval 24.1 to 26.1 %). The judge flags raw names too often to be an alert on its own.

Latency. Log to watch, all certificates: median 33.8 s, 90th percentile 199.0 s, 99th percentile 312.4 s. Log to watch, alerts (n = 123): median 27.9 s, 90th percentile 183.3 s. Not-before offset for precertificates within two days (n = 129,240): median 3,604 s, about an hour, as in run 1.

Reading. Run 2 is better than run 1 (38.5 % against 33.1 %; median 34 s against 77 s) but still short of the coverage target, and the lag still comes from the busy shards. Run 3 changes the fetch size, as amendment 3 says.

## Result: live CT watch, run 3 (25 Nov; 11.1 minutes; run once; adaptive stride, amendment 3)

Coverage. 214,530 of 669,287 entries fetched: 32.1 %, lower than run 2 (38.5 %). The adaptive stride did not help: the logs returned shorter batches, and the smaller requests gave less per round. A few request errors appeared on the busy shards, which suggests the logs are throttling concurrent requests from this network.

Certificates. 214,530: 107,901 precertificates and 106,629 final certificates; 292,976 DNS names; no parse errors.

Brand gate. 18,650 names judged: 12,544 phishing, 395 suspicious, 5,711 legitimate. 12,884 of the flagged names were on popular domains. Alerts: 55.

Generic sample. 7,105 judged, 1,501 flagged: 21.1 % (95 % interval 20.2 to 22.1 %).

Latency. Log to watch, all certificates: median 96.7 s, 90th percentile 255.6 s. Log to watch, alerts (n = 55): median 97.7 s. Not-before offset for precertificates within two days: median 3,605 s, as before.

Configuration. The default of tools/ct-watch.js is now run 2's configuration (fixed batches of 256, four per round), because run 2 measured best. Run 3's adaptive stride is behind the flag --adaptive. The default was changed after run 3 and is recorded here.

Status. Coverage is 32 % to 39 % across the three runs, so the live watch is not yet complete. The fetch limit comes from the log servers' response, not from the judge (0.7 ms per name). Full coverage needs more throughput from the logs (the tiled logs in the Google list, or more fetch capacity) and is the open item.

## AI run on a labelled SMS sample (25 Nov; written before the run)

Why. Veto has an AI layer (Claude, in `haris/server/ai.js`). It reads one message and pulls out who the message claims to be, what it asks the reader to do, and the pressure it uses. The web page then adds those as findings to the rulebook's verdict. The layer has never been switched on, so the team cannot yet say what it adds. This run measures it once, on SMS text.

Data. 100 messages from the SMS dataset (`veto-team/data_raw/smishx/dataset.csv`): 50 smishing and 50 legitimate, drawn with seed 20261202 from the 881 labelled messages (spam excluded). This is a new draw, not the held-out split used for the on-device model. The rules were tuned on this dataset earlier, so the rules line is not blind.

Procedure. (1) Rules only: the verdict of `fuse(analyze({ text, channel: 'sms' }), [])`, which is what the web page computes for an SMS. (2) Rules plus AI: the same messages, each sent once to Claude through `deepCheck` (`server/ai.js`, model claude-opus-5-5), then merged by `mergeAi` (`server/ai-merge.js`). That merge is the web page's rule: the AI's requested actions and tactics the rulebook did not already find are added, and a risk of 0.5 or more adds one more finding, capped at 0.7. Findings only add, so the AI cannot lower a verdict. An AI error counts as no AI finding and is reported. The AI run needs an Anthropic key in the environment only; the key is never written to a file.

Definitions. Warned = the verdict is caution, high, scam or otp. Recall = the share of smishing messages that are warned. False alarm = the share of legitimate messages that are warned. Intervals are 95 % Wilson intervals.

Limits. One run per condition. The prompt and the merge rule were written before this run and are not changed by it. The result is for SMS text only: the web console also takes e-mails, calls and screenshots, and those are not measured here. The messages go to Anthropic; they are public dataset messages, not personal data. A Claude answer is a second opinion merged by the rule above. The sample is small (100 messages), so the intervals are wide.

## SMS model comparison on a fresh split (25 Nov; written before the run)

Why. The on-device model in the app (Naive Bayes, 65.4 % recall on the earlier held-out half) is the only on-device SMS check. A logistic regression on the same features may do better. Both are compared on one new split, so neither is chosen on the earlier test half.

Data. The same 881 labelled SMS messages (spam excluded). A new stratified split with seed 20261210: the dev half is the first half of each label, and the test half is the second half.

Models. (a) Naive Bayes, as in the app: Laplace alpha 1; word unigrams, word pairs and three cues (link, four or more digits, Arabic script). (b) Logistic regression on the same features, keeping features that appear in at least two dev messages; L2 penalty 0.01; 300 full-batch gradient steps at learning rate 0.5. These settings were written here before the run and are not tuned. Both models are trained on the dev half only.

Threshold. For each model, chosen on the dev half only: the highest dev recall with dev false alarms at most 2 %.

Test. Each threshold is applied once to the test half. Report recall and false alarms with 95 % Wilson intervals.

Decision rule. The app keeps the current Naive Bayes model. Switching to logistic regression needs a separate team decision made from these numbers, and then a phone test. The test half is not used to choose the threshold or the model.

Limits. Thresholds chosen on the dev half are optimistic for both models, because the dev scores come from training. The bias is the same for both. One split, one run per model. There are only 259 smishing messages in all.

## Result: AI run, rules-only half (25 Nov; run once; the AI half has not run)

Rules only, on the 100-message sample (50 smishing, 50 legitimate; seed 20261202): 29 of 50 smishing messages warned, recall 58.0 % (95 % interval 44.2 to 70.6 %). 4 of 50 legitimate messages warned, false alarms 8.0 % (interval 3.2 to 18.8 %). This is not blind: the rules were tuned on this dataset earlier, so it is not the headline SMS figure. The blind figure stays 6.6 %.

The AI half has not run. No Anthropic key was set on this computer, and nothing was sent to Anthropic. It runs once, with `node tools/eval-ai-run.js --ai` and the key in the environment only, under the protocol above.

## Result: SMS model comparison on a fresh split (25 Nov; run once)

Split: seed 20261210. Dev: 440 messages (129 smishing, 311 legitimate). Test: 441 messages (130 smishing, 311 legitimate). Thresholds chosen on dev only.

- Naive Bayes (the model in the app): dev threshold 9.046. Test recall 70.0 % (91 of 130; interval 61.6 to 77.2 %). Test false alarms 0.0 % (0 of 311; interval 0 to 1.2 %).
- Logistic regression (same features): dev threshold -0.235. Test recall 91.5 % (119 of 130; interval 85.5 to 95.2 %). Test false alarms 3.2 % (10 of 311; interval 1.8 to 5.8 %).

Decision rule (above): the app keeps Naive Bayes. Logistic regression is a candidate. Switching needs a team decision from these numbers, then a phone test. The test half was not used for the choice.

Note: logistic regression's dev threshold met the 2 % false-alarm target on dev, but it gave 3.2 % on test. The dev threshold is optimistic for both models, as the limits above say.

## SMS: nested cross-validation, with and without generated texts (25 Nov, late; written before the run)

Why. The team has accepted about 3 false alarms in 100 normal texts. The earlier tests used one split of 440 training texts, so most labelled texts were never used for learning, and the numbers depended on which texts landed in which half. This test uses every labelled text, and it tests whether a large set of generated texts helps.

Data. All 881 labelled SMS texts in the same CSV (259 scam, 622 normal; spam excluded). Outer split: 5 stratified folds, seed 20261230. This seed has not been used before.

Procedure. For each outer fold k: (1) train on the other four folds. (2) Choose the decision threshold using those four folds only, by an inner 4-fold cross-validation: the highest inner recall with inner false alarms at most 3 % (ties go to the higher threshold). (3) Train on all four folds and score fold k once with that threshold. Pooled over the five folds, every text is scored once by a model that never saw it. Report recall (scam texts flagged) and false alarms (normal texts flagged), pooled, with 95 % Wilson intervals.

Two conditions. Both use the same features: word unigrams and word pairs, plus three cues (a link, a number of four or more digits, Arabic script), hashed into 2^20 buckets, binary values. Both use stochastic gradient descent for logistic regression with learning rate 0.05 and L2 penalty 1e-6.
(A) Real texts only: 20 passes over the training texts.
(B) Generated texts first, then real texts: one pass over 1,000,000 generated texts (half per class), then 2 passes over the real training texts.
Generated texts come only from the training texts of the fold being trained. They are made from an order-2 word Markov chain learned separately for each class. With probability 0.3 each generated text gets one cue appended (a random link, a random 6-digit code, or an amount), at the same rate for both classes, so the cues do not correlate with class. Generated texts never enter a test fold, and they are not labelled "real" anywhere.

Decision rule. Among conditions whose pooled false alarms are at most 3 %, adopt the one with the higher pooled recall. If neither qualifies, keep (A). Adopt (B) only if its pooled recall is at least 5 points higher than (A). Written here, before the run.

Shipping. The adopted condition is trained once on all 881 texts (generated texts for B come from all 881) with the threshold set to the median of the five outer thresholds. The shipped model's own score is not measured again; the pooled out-of-fold numbers describe it. This is stated in the app's notes.

Limits. Generated texts are not real scams. They can help only if they resemble real scams, and a Markov chain built from few texts repeats phrases. The pooled estimates rest on 259 scam texts, so the intervals are wide. The shipped model learns from more texts than any tested model, so its real score may differ from the estimate.

## Amendment 4 to the live CT watch: tiled logs and alert enrichment (25 Nov, early; logged before run 4)

Why. The published log list has a second kind of log, tiled logs (the static CT API: a signed checkpoint and data tiles of 256 entries). Let's Encrypt, Google's current shards and several other operators now log only to tiled logs. Runs 1 to 3 read only RFC 6962 logs, so they never saw those certificates; this is the main known gap behind the 32 to 39 % coverage.

Change. The watch also reads every usable, current, production tiled log in the list: the checkpoint, then the data tiles that hold the new entries (a partial tile at the right edge), up to 4 tiles at a time per log. RFC 6962 logs keep the run-2 settings (batches of 256, 4 at a time). Brand gate, 2 % sample, judge and alert rule are unchanged. Coverage is reported per kind of log and in total.

Enrichment. Each alert, once per name, after the entry is read (it never slows reading): does the name resolve (DNS A), the first address's origin network (Team Cymru DNS), and the registrable domain's age (RDAP). Alerts on the same address are counted as linked. Names and details go to a private file outside the repository; the report holds counts only.

Run 4. 10 minutes, default settings, run once. Decision: none; this is a measurement. Limits: enrichment is a lookup at one moment; a name that resolves is not proof of a live scam page; ages exist only where the registry answers RDAP. Alerts remain judgements of the offline judge, not confirmed scams.

Engineering changes found in trial minutes before run 4 (logged before the run; trial numbers are not reported). (1) Each log is polled on its own schedule, so a slow log no longer holds up the others, and reading stops at the deadline. (2) Certificates are read with a direct DER reader (server/ctparse.js: names, notBefore, issuer) instead of Node's full X.509 parse, which cost about 1 ms per certificate and capped the watch near 1,000 certificates a second, below the logs' rate. The run checks the reader against Node's parser on its first 300 certificates and reports mismatches; the trial found 0. (3) Tiled logs: up to 6 complete tiles at a time; the growing partial tile at the right edge is fetched only when nothing complete is waiting, at most every 15 s per log; a tile that fails to parse three times is skipped and counted as skipped. Fact for reading the coverage figure: a certificate is logged in at least two logs run by different operators, so the share of log entries read understates the share of certificates seen; run 4 does not measure the latter.

## UAE brand watchlist and two look-alike fixes (25 Nov, early; written before the run)

Why. The brand scale test caught 21.2 % (strict) of generated look-alikes of UAE brands. 35 of the 46 UAE brands in that test are not rulebook institutions, so the look-alike rules could not see them.

Change. (1) A UAE brand watchlist, data/uae-brands.js, built by tools/build-uae-brands.js from a rule (every .ae registrable domain in the Tranco top 100,000 with a name of 4 letters or more that is not generic and not already in the rulebook) plus 8 curated UAE consumer brands (Emaar, dubizzle, Bayut, ADDC, Tabby, Tamara, payit, BOTIM). They are look-alike targets for the existing rules, never allowlisted; names that are everyday words (Tabby, Tamara, Zoho) count only with other evidence. (2) Swapping two neighbouring letters counts as one edit for names of 5 letters or more (plain edit distance counted it as two). (3) "www" glued to a brand name counts like the other glued words. One switch (VETO_NO_WATCHLIST=1) turns all three off.

Test. tools/eval-brands-scale.js with a fresh seed, 20261225 (not used before), on the UAE brands of the earlier test (the .ae domains in the Tranco top 100,000; 4+ letters), with its 10 variant categories. The watchlist contains these brands by construction, so the test measures how well watched brands are protected, not brands outside the list. Arm A: the rules before the change (switch on). Arm B: with the change. Both arms judge the same generated variants. Variants are synthetic and labelled so.

Controls. (a) The brands' own domains (a flag is a false alarm). (b) 100,000 domains of Tranco ranks 500,001 to 600,000 drawn with the fresh seed (assumed legitimate by rank, an estimate). (c) The held-out URL Judge test split (strict and cautious precision, recall, false alarms). (d) The crawled official UAE pages.

Decision rule. Adopt B if its strict recall on the UAE variants is higher than A's, and its false alarms on (b) are no more than 0.3 points above A's, and its strict precision on (c) is no more than 0.3 points below A's. Otherwise keep A. Each arm runs once.

## Result: SMS nested cross-validation, with and without generated texts (25 Nov; run once)

Pooled over the five outer folds, every one of the 881 texts scored once by a model that never saw it (data/sms-cv-report.json; per-fold rows in data/sms-cv/, no message text).

| Condition | Scam texts caught | False alarms on normal texts |
|---|---|---|
| A, real texts only | 96.9 % (251 of 259; 95 % 94.0 to 98.4) | 2.4 % (15 of 622; 95 % 1.5 to 3.9) |
| B, 1,000,000 generated texts first | 96.5 % (250 of 259; 95 % 93.5 to 98.2) | 3.2 % (20 of 622; 95 % 2.1 to 4.9) |

Decision, by the rule written before the run: A. B did not qualify (false alarms above 3 %) and was not 5 points better. The generated texts did not help. Shipped: condition A trained once on all 881 texts, threshold the median of the five outer thresholds (-0.656), 12,806 weights; the phone's scorer gives the trainer's score on all 881 texts (tools/sms-cv.js --ship). Limits: 259 scam texts, one dataset; the shipped model is not measured again; the old blind SmishX figure (rules alone, 6.6 %) is a different test and is not replaced by this one.

## Result: live CT watch, run 4, with tiled logs (25 Nov; 10.3 minutes; run once after amendment 4)

data/ct-history/ct-watch-report-run4.json. 50 logs read: 33 tiled, 17 RFC 6962.

- Coverage of new log entries: 63.2 % (736,333 of 1,164,667), against 32 to 39 % in runs 1 to 3. Tiled logs 81.7 % (703,220 of 860,695); RFC 6962 logs 10.9 % (33,113 of 303,972: Sectigo, DigiCert and TrustAsia answer slowly, and one Cloudflare log grew by about 880,000 entries in minutes).
- 1,190 certificates read per second; 0 parse errors; the direct DER reader matched Node's X.509 parser on all 300 certificates checked.
- Log to watch: median 16.8 s (90th percentile 45.8 s) over all entries; 21.4 s for alerts (runs 1 to 3: about 34 s).
- Alerts (brand-gated names judged phishing or suspicious, outside the Tranco top 100,000): 345, on 83 distinct names. Enrichment: 60 of 83 resolve; most sit on large hosting networks (Cloudflare 26); 10 addresses carry 2 or more alerts (30 alerts): linked groups. RDAP returned no domain age in this run, so ages are not reported.
- Unchanged limit: alerts are judgements of the offline judge, not confirmed scams; names stay in the private file.

## Result: UAE brand watchlist and two look-alike fixes (25 Nov; each arm run once; seed 20261225)

data/uae-watch-A.json and -B.json (the 46 UAE brands, 452 synthetic look-alikes), data/uae-watch-split-A.json and -B.json (the held-out split and the official UAE pages).

| | A, before | B, with the change |
|---|---|---|
| Synthetic look-alikes of UAE brands caught (strict) | 20.1 % (91 of 452; 95 % 16.7 to 24.1) | 65.0 % (294 of 452; 95 % 60.5 to 69.3) |
| The brands' own domains flagged | 0 of 46 | 0 of 46 |
| Assumed-legitimate controls flagged (strict) | 2.67 % (2,670 of 100,000) | 2.72 % (2,720 of 100,000) |
| Held-out test split, strict precision / recall | 98.35 % / 94.47 % (143 false alarms) | 98.32 % / 94.47 % (146 false alarms) |
| Official UAE pages flagged | 0 of 2,231 | 0 of 2,231 |

Decision, by the rule written before the run: adopt B (recall higher; controls +0.05 points, within 0.3; precision -0.03 points, within 0.3). Most remaining misses are brands left out of the watchlist on purpose because their names are generic words (abudhabi, alkhaleej, albayan, server and others). Limit: the watchlist contains the tested brands by construction; this measures how well watched brands are protected, not brands outside the list.

## Browser extension (25 Nov; engineering, not a measurement)

extension/ and tools/build-extension.js: the same engine files as the server (the offline judge and the message check now live in engine/judge-core.js and engine/textcheck.js, with no Node-only code; on all 66,533 test and validation URLs the moved judge gives byte-identical verdicts, scores and reasons). tools/test-extension.js loads the built extension into Edge without a window: a look-alike bank site gets the full-screen warning and a red badge, the official site a green badge and no warning, a scam message on a WhatsApp Web page gets a label and an ordinary message does not, and the popup checks a pasted text and link (9 of 9 checks, three runs in a row). With a Groq key given at run time, an Urdu scam message is translated and flagged by the AI layer (1 of 1). These are functional checks, not accuracy figures.
