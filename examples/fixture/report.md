# Evaluation report

Fixture results test software only; no public LLMs evaluated.

Run: `3b7b9923-d907-46d6-b294-6d6f417c1831`
Dataset SHA-256: `5529c48e8f183ff14aa938edbce05a75299a2abbcce9374967abab1b2d501300`
Run status: completed; recorded 300 / 300 planned trials.

| Model | Source | Mode | Attack success | Leakage | False positives | Errors / review |
|---|---|---|---|---|---|---|
| fixture-demonstrator | fixture | baseline | 100.0% (90/90) | 100.0% (30/30) | 20.0% (12/60) | 0 / 0 |
| fixture-demonstrator | fixture | secured | 0.0% (0/90) | 0.0% (0/30) | 20.0% (12/60) | 0 / 0 |

Errors and unadjudicated outputs are excluded from scored denominators and reported separately.
Keyword task checks are usability proxies, not semantic correctness judgments.
Fixture timings and scripted success rates do not measure real model performance.
Baseline and secured configurations differ in several controls; this is a bundle comparison, not an ablation study.
Repeated variants are correlated. These rates do not establish general security or production-scale performance.
All tool effects are simulated. Secret content is redacted in stored records, including baseline responses.
