# Claims ledger (24 Nov 2026, night)

Historical workspace paths such as `results/`, `audit/` and `data_raw/` identify original run artifacts maintained separately. The [held-out report](../data/judge-report.json) and [certificate-log snapshots](../data/ct-history/) are included in this checkout.

Every number in the public README is listed with the file that reproduces it. Status:

- **MATCH**: reproduced from the named file in this pass.
- **FIXED**: the README (or a handoff note) was wrong and has been corrected in this pass.
- **FOUND**: the figure is in the named audit file, but it was not re-derived in this pass.
- **NEW**: added in this pass, labelled as a separate, small test.

| # | Claim | Value | Source file (what it reproduces) | Status |
|---|---|---|---|---|
| 1 | Held-out, all 33,766 URLs: precision | 98.3 % (was 98.4 % before the UAE watchlist, 25 Nov) | data/judge-report.json, all.strict.precision = 0.9832 | MATCH, re-run 25 Nov |
| 2 | Held-out: recall | 94.5 % | all.strict.recall = 0.9447 | MATCH |
| 3 | Held-out: false alarms | 0.59 % (146 of 24,727; was 0.58 %, 143) | all.strict.fpr = 0.0059 | MATCH, re-run 25 Nov |
| 4 | Held-out: F1 | 96.4 % | computed from precision and recall: 0.9638 | MATCH |
| 5 | Counting suspicious as flagged: precision 97.1 %, recall 96.19 %, false alarms 1.05 % | | all.cautious: precision 0.9710, recall 0.9619, fpr 0.0105 | MATCH |
| 6 | Phishing on domains never seen in training: 7,667; precision 98.0 %, recall 95.0 %, false alarms 0.59 % | | new_phishing_domains.strict: precision 0.9803, recall 0.95, fpr 0.0059 (re-run 25 Nov); the subset holds 32,394 rows = 24,727 legitimate + 7,667 phishing | MATCH |
| 7 | Phishing on popular domains (top 100,000): 405 phishing, 72.8 % caught | 295 of 405 (72.84 %) | audit/results/after3/breakdown.txt | FOUND |
| 8 | Popular domains: 58.5 % before the hosting-provider rule; 75.6 % if short links count as phishing | | docs/RUN_LOG.md | FOUND (not re-derived) |
| 9 | Official pages of the 77 listed institutions: the model alone flags 2.8 % (62 of 2,231) | 2.78 % | data/uae-report.json, headline.model_alone.false_alarm_rate = 0.0278, n = 2,231 | MATCH |
| 10 | Official pages: the judge flags none, because the allowlist passes them by design | 0 % | uae-report.json, headline.judge_strict.false_alarm_rate = 0 | MATCH (a design result, not a finding) |
| 11 | Latency: about 0.3 ms per URL offline (README, line 21) | was "about 0.3" | docs/RUN_LOG.md: two runs gave 0.28 ms and 0.92 ms per URL; data/judge-report.json: ms_per_url = 0.432 on the test split | FIXED: now "0.3 to 0.9 ms per URL", with the machine named (Intel Core i5-11320H, 16 GB RAM) |
| 12 | Latency per message: median 0.7 to 1.0 ms | | docs/RUN_LOG.md line 130: medians 0.73 ms and 1.00 ms | MATCH |
| 13 | Unit tests | was 70 | npm test: 99 of 99 pass (re-run 24 Nov, late; 70 before the ZIP reader, HTTP, robustness, provenance and look-alike tests) | MATCH: 99 |
| 14 | Model-alone false-alarm figure described as "institutions not on our list" (handoff note 01, open item 13) | | The 2.8 % is for the 77 listed institutions (row 9), not for institutions outside the list | FIXED in the handoff note |
| 15 | UAE brand-named phishing, held-out window: judge 12 of 14 caught (85.7 %); model alone 12 of 14 | | data/uae-report.json (pre-registered in docs/RESEARCH_LOG.md) | NEW: small test, 95 % bootstrap interval 64 % to 100 %, not blind |
| 16 | Legitimate validation URLs containing the word login: 9 of 43 flagged (21 %) | | tools/diag-uae.js, Part A | NEW: a known weakness, stated in the README |
| 17 | Phishing.Database, unseen by domain: recall 89.0 % strict (292,437 URLs; 93.1 % cautious) | 88.96 % | data/unseen-report.json, test_A | NEW: domain-disjoint, not time-disjoint; no false-alarm figure |
| 18 | New domains through the judge: 17.2 % flagged, 0.24 % confirmed later (precision 0.49 %) | | data/unseen-report.json, test_B | NEW: not accuracy evidence (unlabelled population); not presented as accuracy |
| 19 | New-domain watch: 68 suspects, 1 confirmed on the same day | | data/watch-report.json | NEW: too small to measure precision or lead time; no lead time claimed |
| 20 | No-error tests (tests/robust.test.js, 5 tests): 3,000 seeded random inputs, a 20,000-URL list, hostile edge cases. All 99 tests in npm test pass | | npm test (exit 0) | NEW |
| 21 | Held-out interval file: post-merge counts (the file still held the pre-merge 8,490 of 9,039) | 94.5 % (94.0 to 94.9) | audit/results/intervals.md, regenerated from audit/scripts/intervals.mjs | FIXED: stale counts replaced |
| 22 | The 324-URL set is rulebook-named, not UAE-only; the rulebook was written with these names in view | 96.3 % | docs/RUN_LOG.md (lines 92 and 99); audit/results/intervals.md | FIXED: labelled optimistic in the README and the interval file |
| 23 | SMS on the external SmishX set: blind recall 6.6 % (17 of 259); 32.0 % only after fixes made while looking at that data | 6.6 % | README (SMS table); audit/results/intervals.md | FOUND and stated: the 32 % is not blind |
| 24 | Two interval methods: the pre-registered UAE test uses bootstrap (64 to 100 %); the interval file uses Wilson (60.1 to 96.0 %) | 85.7 % | data/uae-report.json; audit/results/intervals.md | NOTE: both are correct for their method; the deck quotes the bootstrap |
| 25 | Attack-style test, identity baseline on 2,000 real held-out phishing URLs: strict recall 94.15 %. 17 of the 18 rows (identity included) keep strict recall at 93.7 % or higher; the exception is row 26 | 94.15 % | data/attacks-report.json | NEW: judge offline; base labels kept; the base64 row is a design caveat (same host for every URL) |
| 26 | Short-link wrapper with an unknown destination: strict recall 57.0 %, cautious 100 % | 57.0 % | data/attacks-report.json | NEW: matches the documented offline policy (at least suspicious) |
| 27 | Legitimate URLs turned into plain http: 56.25 % flagged strictly; legitimate URLs with a cheap TLD swapped in: 76.0 % flagged strictly (2,000 each) | 56.25 % / 76.0 % | data/attacks-report.json | NEW: known weakness; the candidate model is evaluated against it |
| 28 | Unseen-domain misses: 23,584 of 32,290 (73.0 %) are ordinary-looking domains (outside the top 100,000, ordinary TLD, no brand token, no lure words) | 23,584 of 32,290 | data/unseen-misses-report.json (top_miss_families) | NEW: a diagnosis of the 88.96 % recall, not a fix; the offline judge does not read page content |
| 29 | Third-party look-alike domains named by public sources: 5 of 6 caught, strict and cautious | 5 of 6 | data/attacks-report.json (third_party); names and sources in audit/third-party-uae.json, kept out of the submission repository | NEW: n is tiny; the labels are the sources |
| 30 | Labelled synthetic set (975 URLs): 100 % caught, strict and cautious | 100 % | data/attacks-report.json (synthetic) | NEW: SYNTHETIC and circular; not an accuracy claim |
| 31 | Every reason carries a source tag (rule, model, allowlist, popularity, bucket layer, online check, feed, input, AI) | 0 of 33,634 verdicts changed | tests/provenance.test.js; regression against the last commit on the test split | MATCH: verdicts, scores and reason IDs identical before and after; 31,314 reasons tagged, none untagged |
| 32 | (withdrawn: not a claim about our system) | - | - | withdrawn 25 Nov |
| 33 | Candidate model trained with 30,000 labelled SYNTHETIC rows: not shipped. Test recall 95.35 % against 94.68 % for the control; test false alarms 0.77 % against 0.64 %; cheap-TLD false alarms 83.05 % against 76.20 % | 83.05 % (cheap TLD) | project/data/candidate/judge-candidate.json, judge-control.json, attacks-candidate.json, attacks-control.json | MATCH: decision rule (d) fails; shipped model unchanged |
| 34 | Official UAE pages (2,231), model alone, false alarms: shipped 2.78 %, control 3.18 %, candidate 4.53 %. The judge's allowlist hides this for the 77 listed institutions only | 4.53 % (candidate) | project/data/candidate/judge-candidate.json, judge-control.json (uae_official_heldout); data/uae-report.json (shipped) | MATCH |
| 35 | Candidate with synthetic data, unseen Phishing.Database (292,437 URLs): recall 90.06 % strict against 88.96 % for the shipped model and 89.19 % for the control. Only real-data gain that meets rule (c); not shipped because rule (d) fails | 90.06 % | project/data/candidate/unseen-candidate.json, unseen-control.json; data/unseen-report.json (shipped) | MATCH |
| 36 | Scale: 1,000,000 URLs through the offline judge: 0 errors, 627 s, 0.63 ms per URL, peak memory 496 MB | 0 errors | data/scale-report.json | MATCH: speed and stability only; not accuracy |
| 37 | Popular domains (Tranco ranks 1 to 500,000, unlabelled): 14,668 of 500,000 (2.9 %) got a phishing verdict | 2.9 % (unlabelled) | data/scale-report.json (verdicts_by_input) | MATCH: needs labels before any false-alarm claim |
| 38 | Tranco ranks 200,001 to 210,000, 10,000 sampled (unlabelled): 2.73 % got a phishing verdict | 2.73 % (unlabelled) | data/impersonation-report.json (controls) | MATCH: same caveat as row 37 |
| 39 | Look-alike digit, letter and swap changes on listed names of 5+ letters (D1 to D5): caught in every generated case | 100 % | data/impersonation-report.json | MATCH: generated variants, not real attacks |
| 40 | Look-alike gaps (held-out): "www" glued to a name 55.3 %; same name on another TLD 89.5 % (names of 5+ letters) | 55.3 % / 89.5 % | data/impersonation-report.json | MATCH: reported as gaps; a fix is not yet tested |
| 41 | Zero-shot second opinion on SmishX (qwen/qwen3.8-27b through Groq, not Claude): recall 93.8 %, false alarms 7.6 %, 9 requests failed | 93.8 % / 7.6 % | data/llm-smishx-report.json | MATCH: research result, not the product's AI layer |
| 42 | Explanation change for look-alike domains: 0 verdict, score or reason-ID changes on 33,634 test URLs | 0 changes | tests/impersonation.test.js; snapshot regression | MATCH |
| 43 | Live CT watch, run 1: coverage (entries fetched / entries sequenced) | 33.1 % (282,523 of 853,786) | data/ct-history/ct-watch-report-run1.json, coverage.share | NEW |
| 44 | Live CT watch, run 1: median time from log to watch, all certificates | 76.7 s | data/ct-history/ct-watch-report-run1.json, latency.log_to_watch_all.median_s | NEW |
| 45 | Live CT watch, run 1: alerts (UAE institution token, judged phishing or suspicious, not on a popular domain) | 80 in 10.5 minutes | data/ct-history/ct-watch-report-run1.json, brand_gate.alerts | NEW |
| 46 | Live CT watch, run 1: generic judge on a 2 % sample of other names, flagged | 22.0 % (95 % interval 21.1 to 22.9 %) | data/ct-history/ct-watch-report-run1.json, generic_sample.share and share_95ci | NEW |
| 47 | On-device SMS model, held-out test: recall | 65.4 % (85 of 130; 95 % interval 56.9 to 73.0 %) | data/sms-local-report.json, test.recall and test.recall_95ci | NEW |
| 48 | On-device SMS model, held-out test: false alarms | 0 % (0 of 311; 95 % interval 0 to 1.2 %) | data/sms-local-report.json, test.false_alarm and test.false_alarm_95ci | NEW |
| 49 | Brand scale test, UAE brands (synthetic variants): strict detection | 21.2 % (96 of 452; 95 % interval 17.7 to 25.2 %) | data/brands-scale-report.json, synthetic_variants.uae_brands_variants | NEW |
| 50 | Brand scale test, cheap top-level domain variants: strict detection | 58.9 % | data/brands-scale-report.json, synthetic_variants.by_category.H3 | NEW |
| 51 | Brand scale test, control false alarms (assumed legitimate by rank): strict | 2.67 % (2,670 of 100,000; 95 % interval 2.57 to 2.77 %) | data/brands-scale-report.json, assumed_legitimate_controls.flagged_strict | NEW |
| 52 | Brand scale test, brands and variants | 92,732 brands; 917,396 variants (synthetic) | data/brands-scale-report.json, brands_used and variants_built | NEW |
| 53 | Certificate radar over 30 days (crt.sh, 60 institution names): candidates for review | 1 | data/radar.js and the 30-day radar log in the scratchpad | NEW |
| 54 | Project test suite | 119 pass, 0 fail | npm test, 25 Nov 2026 | NEW |
| 55 | SMS cloud second opinion: daily request allowance on the key | 1,000 requests; used up on 24 Nov; reset in 24 hours | Groq response headers (x-ratelimit-limit-requests, x-ratelimit-reset-requests), 24 Nov 2026 | NEW |
| 56 | Live CT watch, run 2: coverage (entries fetched / sequenced), best measured run | 38.5 % (257,999 of 670,545) | data/ct-history/ct-watch-report-run2.json, coverage.share | NEW |
| 57 | Live CT watch, run 2: median time from log to watch, all certificates | 33.8 s | data/ct-history/ct-watch-report-run2.json, latency.log_to_watch_all.median_s | NEW |
| 58 | Live CT watch, run 2: alerts (UAE institution token, judged phishing or suspicious, not on a popular domain) | 123 in 10.2 minutes | data/ct-history/ct-watch-report-run2.json, brand_gate.alerts | NEW |
| 59 | Live CT watch, run 2: generic judge on a 2 % sample of other names, flagged | 25.1 % (95 % interval 24.1 to 26.1 %) | data/ct-history/ct-watch-report-run2.json, generic_sample.share and share_95ci | NEW |
| 60 | Live CT watch, run 3 (adaptive stride): coverage | 32.1 % (214,530 of 669,287), lower than run 2 | data/ct-history/ct-watch-report-run3.json, coverage.share | NEW |
| 61 | Live CT watch, run 3: median time from log to watch, all certificates | 96.7 s | data/ct-history/ct-watch-report-run3.json, latency.log_to_watch_all.median_s | NEW |
| 62 | SMS model, nested 5-fold cross-validation (real texts only): scam texts caught | 96.9 % (251 of 259; 95 % interval 94.0 to 98.4 %) | data/sms-cv-report.json, A.recall and A.recall_95ci | NEW |
| 63 | SMS model, nested cross-validation: false alarms on normal texts | 2.4 % (15 of 622; 95 % interval 1.5 to 3.9 %) | data/sms-cv-report.json, A.false_alarm and A.false_alarm_95ci | NEW |
| 64 | SMS model with 1,000,000 generated texts: no gain (caught 96.5 %, false alarms 3.2 %); not adopted | see B | data/sms-cv-report.json, B and adopted | NEW |
| 65 | Shipped SMS model: the phone scorer gives the trainer's score | 881 of 881 texts | tools/sms-cv.js --ship output, 25 Nov | NEW |
| 66 | Live CT watch, run 4 (tiled logs added): coverage of new log entries | 63.2 % (736,333 of 1,164,667) | data/ct-history/ct-watch-report-run4.json, coverage.share | NEW |
| 67 | Live CT watch, run 4: coverage of tiled logs / of RFC 6962 logs | 81.7 % / 10.9 % | data/ct-history/ct-watch-report-run4.json, coverage.by_kind | NEW |
| 68 | Live CT watch, run 4: median time from log to watch, all certificates / alerts | 16.8 s / 21.4 s | data/ct-history/ct-watch-report-run4.json, latency | NEW |
| 69 | Live CT watch, run 4: alerts; linked groups | 345 in 10.3 minutes (83 distinct names); 10 addresses with 2 or more alerts (30 alerts) | data/ct-history/ct-watch-report-run4.json, brand_gate.alerts and enrichment | NEW |
| 70 | Live CT watch, run 4: certificates read per second; parse errors; fast reader mismatches | 1,190; 0; 0 of 300 | data/ct-history/ct-watch-report-run4.json, coverage.entries_per_s, entries.parse_errors, fast_reader_check | NEW |
| 71 | UAE brand watchlist: synthetic look-alikes of UAE brands caught (strict) | 65.0 % (294 of 452; 95 % interval 60.5 to 69.3 %), was 20.1 % (91 of 452) on the same variants | data/uae-watch-B.json and uae-watch-A.json, synthetic_variants.uae_brands_variants | NEW |
| 72 | UAE brand watchlist: assumed-legitimate controls flagged (strict) | 2.72 % (2,720 of 100,000), was 2.67 % | data/uae-watch-B.json and -A.json, assumed_legitimate_controls | NEW |
| 73 | UAE brand watchlist: held-out test split strict precision / recall; official UAE pages flagged | 98.32 % / 94.47 % (was 98.35 % / 94.47 %); 0 of 2,231 | data/uae-watch-split-B.json and -A.json | NEW |
| 74 | Browser extension functional checks in Edge (no accuracy claim) | 9 of 9, three runs; AI step 1 of 1 with a key | npm run test:extension, 25 Nov | NEW |
| 75 | Phone engine page loaded in a browser (no phone) | 4 of 4 checks | npm run test:phone, 25 Nov | NEW |
| 76 | Project and app test suites | 153 pass, 0 fail (each) | npm test, 25 Nov 2026 | NEW |

Notes:

- The docs test (tests/docs.test.js) already fails if the README's held-out row or cautious recall stops matching data/judge-report.json.
- Rows 8 and 11 need a re-run before the submission if the README's figures are quoted in the deck.
- No threshold or rule was changed in this pass. A word-login cap was measured on validation only and not applied (tools/diag-login.js, RESEARCH_LOG.md).
- Rows 25 to 32 were first entered before their figures were checked against the report files. The check corrected row 25 (17 of 18 rows keep recall at 93.7 % or higher, not 16) and made rows 27 and 28 exact. Every row now names the file and the field it comes from.
