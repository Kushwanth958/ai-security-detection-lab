# Initial pipeline findings

**These are software-validation observations from a scripted fixture, not model-security research results.**

The demonstrator returns intentional attack successes in baseline mode, proposes disallowed tools in both modes, and intentionally emits the planted canary in secured mode so output containment is exercised. Its responses are selected using case and mode metadata. This makes it unsuitable for comparing model robustness or measuring mitigation efficacy.

The 300-trial run uses 50 cases, two configurations, and three repetitions. There are 90 adversarial and 60 legitimate trials per mode. All trials completed without errors or pending adjudication.

| Observation | Baseline fixture | Secured fixture |
|---|---|---|
| Application attack success | 90 / 90 | 0 / 90 |
| Model boundary violations | 90 / 90 | 60 / 90 |
| Delivered canary leakage | 30 / 30 | 0 / 30 |
| Legitimate trials flagged by input heuristics | 12 / 60 | 12 / 60 |
| Legitimate task proxy completion | 60 / 60 | 60 / 60 |

The secured output-filter pathway contains intentional canary disclosures, while tool authorization contains restricted-file and collector proposals. Baseline disclosures still count as successful observations even though their stored text is redacted. The same legitimate training phrases produce input-rule false positives in both modes; the dashboard exposes rather than hides them.

Four synthetic SOC alerts produced four schema-valid, matching fixture verdicts with the required references. This validates the pipeline's asset/identity joins, timelines, and evidence checks. The fixture uses the deterministic correlation result to construct those responses, so the matches do not measure AI analyst accuracy.

## Next research step

Configure five exact, compatible model IDs and conduct a one-model pilot. Freeze the corpus and grading after resolving compatibility issues, then run the 1,500-trial live suite. Preserve error rates, ambiguous outputs, manual-review notes, and false positives. Rewrite findings around observed live results, with dated model/configuration identifiers and explicit study limitations.

Until then, a supported portfolio statement is: **Built a reproducible LLM application-security lab with 50 synthetic cases, tool-policy controls, five detection rules, a SQLite evidence trail, and a simulated SOC investigation workflow.**

The claim **“evaluated five public LLM models”** becomes supportable only after those live evaluations are actually completed and documented.
