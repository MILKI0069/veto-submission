# Audit run log (24 Nov 2026, evening)

Historical workspace paths such as `results/`, `audit/` and `data_raw/` identify original run artifacts maintained separately. The [held-out report](../data/judge-report.json) and [certificate-log snapshots](../data/ct-history/) are included in this checkout.

This is our own challenge run: we tested our URL judge and new-domain watch before the other AI does. Every script here is deterministic (fixed seeds), offline, and never visits a URL or uses a key. Phishing examples are defanged (`hxxps`, `[.]`). New-domain names are masked (first letter and TLD only). The unmasked list stays on the laptop that ran the watch and is not in this package.

## Environment

- Windows 11 Home, 10.0.26300. Node v22.19.0.
- Project: `project/` (the URL judge, the Sentinel, the Android build, the web console).
- Data: `data_raw/urlv2` (OpenPhish history, the held-out split files, legitimate crawl), `data_raw/nrd` (two WhoisDS daily lists, 22 and 23 Nov 2026), `data` (model weights and the institution rulebook).
- Input hashes: `results/before/input-hashes.txt` was taken before the first fix. Files changed after that are listed under "What changed", with the test results.

## How to run

From the package root (PowerShell):

```powershell
node audit\scripts\audit-uae.mjs > audit\results\after2\uae.json
node audit\scripts\audit-redteam.mjs > audit\results\after2\redteam.json
node audit\scripts\audit-nrd77.mjs > audit\results\after2\nrd77.json
```

The scripts find `project/` and `data_raw/` relative to their own location. Override with `VETO_ROOT`, `VETO_DATA` and `VETO_VAR` if needed.

The held-out evaluation (writes `data/judge-report.json` for the test split only):

```powershell
cd project
node tools\eval-judge.js --data ..\data_raw\urlv2 --split test
```

The network-free ablation (bucket layer off) was made by copying `server/judge.js` to a temporary file with two edits: `bucketCap ? Math.min(raw, 0.49) : raw` became `raw`, and `storageEvidence(u, host)` became `{ q: 0, kind: null, reasons: [] }`. Then the measurement ran on both splits. The temporary file was deleted after the run.

## Step 1: baseline, before any fix (`results/before/`)

| Measure | Value |
|---|---|
| Red team, 400 caught phishing, 13 transforms: open redirect via Google, a bank domain, a UAE university domain | 400 of 400 pass each (100 %) |
| Red team: trailing dot on the host | 5 of 400 pass (1.25 %) |
| Red team: the other 9 transforms | none pass; 0 to 0.75 % downgraded to suspicious |
| UAE: phishing that names a rulebook institution (324 URLs, 25 Oct to 24 Nov) | phishing 310, suspicious 2, legitimate 12; strict recall 95.68 % |
| UAE: the part whose institution has an .ae domain (103 URLs) | strict recall 90.29 % |
| UAE: the rest (221 URLs) | strict recall 98.19 % |
| Hand-listed UAE sites, open group (21 of 27) | 1 flagged (suspicious, model only: mubadala.com) |
| New-domain watch, 77 institutions, two days | 68 candidates across 14 institutions (about 70,000 domains read per day) |
| Held-out test, all 33,766 URLs, strict | precision 98.22 %, recall 93.92 %, false alarms 0.62 % |
| Held-out test, cautious | precision 96.92 %, recall 95.24 %, false alarms 1.11 % |
| Official UAE pages, model alone (2,231) | 62 flagged (2.78 %) |
| Unit tests | 54 of 54 |

## Step 2: fixes to the judge and the parsers (`results/after/`)

- Open redirects on trusted hosts: the address inside the link is judged too, and the worse verdict is reported. Red team: 400 of 400 pass before, 0 after, for all three forms.
- Trailing dots are removed in `parseUrl`. Red team: 5 of 400 before, 0 after.
- Letter n-gram explanations are no longer shown.
- Campaign links carry a confidence; only high and medium links join sites into one campaign.
- Held-out test: identical to before (`judge-report-postfix.json` equals `judge-report-prefix.json` on every metric).
- Unit tests: 59 of 59.

The first attempt at the trailing-dot fix did nothing: a regular expression lost its backslash in transit. The test `a trailing dot on the host does not change the verdict` caught it. The fix was then corrected to a character class (`[.]`).

## Step 3: public-bucket layer (`results/after2/`)

The UAE audit's largest gap was phishing on public file buckets (S3 and Backblaze B2). We added evidence from the bucket name, the path and the query: a victim's e-mail address in the link (raw or base64) is strong; a famous name with lure words is strong; two lure words, or a famous name alone, is suspicious. Because the URL model reads bucket hostnames as phishing-like (the probe below), a bucket file with no content evidence is capped at suspicious.

| Measure | Before the layer | After the layer |
|---|---|---|
| UAE named phishing, strict recall (324 URLs) | 95.68 % (310 phishing) | 96.30 % (312 phishing) |
| UAE named, any flag | 96.30 % | 98.77 % |
| UAE named, legitimate verdicts | 12 | 4 |
| UAE, .ae-domain subset (103 URLs) | 90.29 % | 92.23 % |
| UAE, other subset (221 URLs) | 98.19 % | 98.19 % |
| Held-out validation (30,528), strict recall | 91.77 % (TP 5623, FP 199) | 91.61 % (TP 5613, FP 198) |
| Held-out validation, cautious recall | 93.13 % (TP 5706) | 93.34 % (TP 5719) |
| Held-out test (33,766), strict recall | 93.92 % (TP 8489, FP 154) | 93.93 % (TP 8490, FP 154) |
| Held-out test, cautious recall | 95.24 % (TP 8609, FP 274) | 95.35 % (TP 8619, FP 274) |
| Red team | unchanged | unchanged |
| Hand-listed open UAE sites | 1 flagged | 1 flagged |
| New-domain candidates | 68 | 68 |
| Unit tests | 59 | 63 of 63 |

**The cap's effect, bucket rows only.** Validation (71 rows: 71 phishing, 1 legitimate in the bucket subset): with the cap, 5 phishing and 24 suspicious; without the cap, 27 phishing and 2 suspicious. Cautious detection is 29 either way. Test (31 phishing rows, 1 legitimate): with the cap, 5 phishing and 9 suspicious; without, 14 phishing. Cautious detection is 14 either way. The one legitimate bucket row in validation moves from phishing (without the cap) to suspicious (with it).

**The probe that started it.** `https://reports-2025.s3.amazonaws.com/annual.html`, an ordinary-looking file, scored 1.00 as phishing before any bucket evidence: the model reads the bucket hostname as phishing-like. Our training data holds almost no legitimate bucket URLs (one in validation, one in test), so the model learned the hostname. The cap limits its effect. The fix is a labelled benign bucket sample, which we do not have yet.

**The cap was chosen before the split numbers were computed**, from the probe and the design rule. The costs are reported above.

**Process note.** `tools/eval-judge.js` writes `data/judge-report.json` only for the test split. A validation run leaves the older test report in place. Our first validation copy was therefore stale. The validation numbers above come from the console output and the ablation run, not from a copied JSON. `results/after2/judge-report-test.json` is the correct test report after the layer; `results/after2/eval-val.txt` is the correct validation console output.

## Corrections made in this pass

1. The first pass said 9 of the 12 UAE-named misses sat on public buckets. The list has 10 bucket misses. After the layer, 8 of the 10 are flagged and 2 remain.
2. The first pass called the 324 URLs "UAE-named". They match all 77 rulebook institutions, including global brands. They are rulebook-named.
3. The test count was 54, then 59, then 61, now 63. The docs now say 63.
4. The validation report copy used earlier was stale (see the process note).

## What the run does not show

- The red team uses synthetic transformations of phishing that the judge already flags. It shows blind spots, not real attacker success.
- The UAE named set is small for the UAE part (103 URLs with an .ae-domain institution), and the rulebook was written with these names in view, so it is optimistic.
- The hand-listed UAE sites (27, of which 21 are open) are not verified live.
- Benign bucket files are not measured. Our splits contain one or two.
- The new-domain watch gives candidate counts only. Lead time and precision are not measured.
- Latency: two runs gave 0.28 ms and 0.92 ms per URL on the same split. We do not quote a latency number from this run.
- The live connectors (Brave, Google Places, SerpApi) were not run.
- The hidden test set belongs to the organisers. We cannot predict our result on it.

## Reproduction notes

- The new-domain script reads the two days before the day it runs. The package includes the 22 and 23 Nov lists, so it reproduces on 24 Nov 2026. On another day it tries to download the lists.
- `npm install` is needed in a clean copy (the project depends on `@anthropic-ai/sdk` and `playwright-core`). `node_modules` is not in the package.
- The scripts print JSON to stdout. Compare the output with `results/after2/` using a file comparison tool.

## Files

- `scripts/audit-uae.mjs`: Part A (rulebook-named phishing, held-out window) and Part B (hand-listed UAE sites).
- `scripts/audit-redteam.mjs`: 13 synthetic transforms over 400 caught phishing URLs, seeded.
- `scripts/audit-nrd77.mjs`: new-domain watch over 77 institutions, host names masked.
- `results/before/`: baseline before any fix, including the held-out test report before the fixes (`judge-report-prefix.json`) and the input hashes.
- `results/after/`: after the redirect, trailing-dot, explanation and campaign fixes (`judge-report-postfix.json`).
- `results/after2/`: after the bucket layer, with validation and test console output, the test report, and the before-and-after bucket numbers.
- `results/history/`: the first run's outputs (v1 of the UAE and red-team scripts), kept for transparency.
- `../TEST_RESULTS.md`: the unit tests, 63 of 63.

The unmasked new-domain list is not in this package, by design.

## Step 4: second review of the teammate file, and quick wins

The teammate sent a markdown file of ideas and research (kept as received in `10_TEAMMATE_IDEAS_AS_RECEIVED.md`). Each claim was checked against the code, the docs, the guidelines PDF, the Android source, and a few public sources. The review is in `10_REVIEW_OF_TEAMMATE_IDEAS.md`.

- Engine evaluation, run today: all 124 messages, 70 scam and 54 legitimate, 0 errors (`engine-eval/eval-all.txt`). Median latency 0.73 ms. The 45-message holdout, 0 errors, median 1.00 ms; it was used to fix gaps after its blind run (80 % recall), so its 100 % is not a blind result (`engine-eval/eval-holdout.txt`).
- Stale numbers corrected: 98.6 % recall on 124 messages (HANDOFF, LITERATURE) becomes 100 % on the current run; latency in the README and PITCH (0.6 and 0.4 ms) becomes 0.7 to 1.0 ms across runs.
- Error ranges, Wilson 95 % (`results/intervals.md`): URL judge held-out strict recall 93.9 % (93.4 to 94.4 %); UAE named phishing 96.3 % (93.6 to 97.9 %); the blind engine run 80 % (60.9 to 91.1 %).
- New test `tests/docs.test.js`: the README held-out row and the cautious recall must quote `data/judge-report.json`. Total: 63 of 63.
- Privacy gaps checked in the code (plain-text IPQS key and reported-number list in `Store.java`; Accessibility declared in `AndroidManifest.xml`; hashed numbers are not anonymous). Written down with the planned fixes in `docs/COMPANION.md`. Not changed in code: each needs a device test.
- Two teammate claims were wrong: the police side already exists (Sentinel console, takedown packs, campaign linking), and the Falcon Lens "two agents" description is not in our data.

## Added files (second pass)

- `results/intervals.md`: error ranges (Wilson 95 %) for the headline numbers. Generated by `scripts/intervals.mjs`.
- `results/engine/eval-all.txt` and `eval-holdout.txt`: the engine's full and holdout evaluations, run on 24 Nov (`node tests/eval.js --all` and `--holdout`).
- `TEST_RESULTS.md`: the unit tests, 63 of 63 (the new docs test is `tests/docs.test.js`).
- `REPRODUCTION_CHECK.md`: the clean-extraction check. npm test 63 of 63; the three audits and the held-out and engine evaluations reproduce the saved outputs exactly.

## Step 5: the other AI's challenge, verified and merged (24 Nov, evening)

The other AI, working from the handoff folder, produced a challenge (`11_CHALLENGE_BY_OTHER_AI/`, kept as received). Our review is `11_REVIEW_OF_CHALLENGE.md`. The checks ran in a separate copy. Everything it claimed was re-run, and the patch was applied only after the checks passed.

- **Verified:** the patch applies cleanly; 70 of 70 tests pass; the held-out numbers reproduce (test strict 98.4 / 94.6 / 0.58 % with a phishing floor); defanged input was invalid before and is phishing after; the CSV reader and the popular-domain baseline (235 of 402 = 58.5 %) reproduce; no network or shell calls in the runtime code; our UAE audit is identical after the patch.
- **Corrected by us:** the short-link default is suspicious (0.3), not phishing (0.5), because the data holds no legitimate short link; the hosting-list generator defaults to 3, as the list was built; the report's count of 25 short links is 21 in our anchored count (1 home page, not 2).
- **Open, and not verified:** the Falcon Lens deck file named in the report is not in the local clone (the phrase is in the deck build script); the bucket gap for a victim e-mail split across parameters is confirmed and still open.
- **Results after the merge (test split):** strict precision 98.4 %, recall 94.5 %, false alarms 0.58 %; cautious recall 96.19 %, false alarms 1.05 %. Validation strict 97.0 / 92.8 / 0.72 %. Popular-domain phishing 72.8 % (295 of 405). Unit tests 70 of 70.
- **Note on the test split:** it has now been used by the challenger, by the patched run, and for the short-link decision. Treat the test numbers as final for this version only.
- **Files:** `audit/results/after3/` holds the merged outputs: our three audits, the challenger's red-team output, the validation and test evaluations, the breakdown, and the unit-test run.
