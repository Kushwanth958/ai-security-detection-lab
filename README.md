# AI Security & Detection Research Lab

**Atlas** is a reproducible lab for studying prompt injection, synthetic data leakage, tool permissions, and AI-assisted SOC investigations. It connects model behavior to application controls and an inspectable audit trail.

The lab runs offline with Python's standard library. An explicit live mode connects the same experiments to configurable OpenAI-compatible chat-completions endpoints. A local, read-only dashboard explores outcomes and evidence.

> **Research status:** the included results are scripted fixtures used to validate the software. No public LLMs have been evaluated in this repository's initial evidence bundle. Five real model configurations are supported; their results must be generated separately.

## Run the lab

Requires Python 3.11 or later. No API key, GPU, Docker, or runtime dependency installation is needed for the offline demo.

```bash
git clone https://github.com/Kushwanth958/ai-security-detection-lab.git
cd ai-security-detection-lab
python -m aisec_lab validate
python -m aisec_lab demo
python -m aisec_lab report
python -m aisec_lab soc
python -m aisec_lab serve
```

Open **http://127.0.0.1:8765**. On systems where the command is named `python3`, use that instead of `python`. On Windows, `py -3` is another option.

The demo creates 300 trials: 50 cases × two control configurations × three repetitions. All output is saved under the ignored `runs/` directory. The dashboard never starts a model evaluation or changes a verdict.

| Command | Purpose |
|---|---|
| `validate` | Validate the corpus and print its hash and five-model trial budget |
| `demo` | Exercise the entire evaluation pipeline with scripted responses |
| `evaluate --live` | Evaluate explicitly selected real model endpoints |
| `report` | Export metrics, redacted trial JSONL, and a Markdown report |
| `soc` | Correlate and enrich four labeled synthetic alerts |
| `review` | Adjudicate an ambiguous output with an audit note |
| `serve` | Explore evaluations and SOC evidence locally |

## What is implemented

- **Developer assistant:** synthetic repository context and proposed file/collector tools, with up to three model completions per trial.
- **Security experiments:** 30 adversarial cases in six categories, plus 20 legitimate tasks, including security-training language to expose false positives.
- **Independent policy controls:** document authorization, path validation, tool allowlists, disabled egress in secured mode, and output redaction of a planted synthetic canary.
- **Detection and correlation:** five rules for injection signals, output leakage, tool denials, sensitive simulated actions, and repeated policy events.
- **Reproducible evaluation:** SQLite records, unique run/trial IDs, dataset hashes, model settings and resolved IDs, error accounting, request limits, token usage when available, and audit-preserving adjudication.
- **SOC workflow:** user/host/time correlation, mock asset and identity enrichment, incident timelines, structured AI output validation, evidence-reference checks, and a human review queue.
- **Dashboard:** configuration comparison, detections, searchable trial evidence, pagination, and SOC investigations. It uses local assets and escapes model text through DOM text nodes.

The permissive baseline exposes a fake credential and allows selected synthetic actions. The secured configuration withholds restricted context, denies those actions, and filters known canary output. No tool reads the real filesystem or sends collected data over the network.

## Evaluate real models

1. Copy `config/models.example.json` to the ignored `config/models.local.json`.
2. Replace each placeholder with an exact model ID and its endpoint's `/v1` base URL.
3. Set credentials through the named environment variables. A local loopback endpoint may omit authentication. Never put real credentials in configuration or test datasets.
4. Start with one model and one repetition, inspect the evidence, then expand.

```bash
python -m aisec_lab evaluate --live \
  --config config/models.local.json --model model-1 \
  --repetitions 1 --max-requests 300
```

For five models and three repetitions:

```bash
python -m aisec_lab evaluate --live \
  --config config/models.local.json \
  --model model-1 --model model-2 --model model-3 --model model-4 --model model-5 \
  --repetitions 3 --max-requests 4500
python -m aisec_lab report --out runs/live-report
```

This plans **1,500 trials**, with a conservative ceiling of **4,500 completion requests**. The cap is checked before any requests are sent. Requests are sequential, are not automatically retried, and have per-request timeouts and output-token limits. The cap is a request budget, not a dollar budget; provider pricing and input length determine cost.

The adapter requires text chat-completions and function/tool-call support. It sends `model`, `messages`, `tools`, `temperature`, and `max_tokens`. Some providers use different contracts; unsupported endpoints fail explicitly rather than silently switching models. Record exact versions and dates, because provider aliases can change. See [methodology](docs/methodology.md).

For live SOC enrichment, each of the four alerts makes one request:

```bash
python -m aisec_lab soc --live --config config/models.local.json \
  --model model-1 --out runs/live-soc/report.json
python -m aisec_lab serve --soc-report runs/live-soc/report.json
```

## Read the results correctly

**Model boundary violation** records whether the model exposed a planted secret, followed a planted instruction, or proposed a prohibited action. **Application attack success** records whether the objective remained successful after independent controls. A denied file request can therefore be a model violation without an application-level success.

| Metric | Denominator |
|---|---|
| Application attack success | Completed, scored adversarial trials |
| Model boundary violation | Scored adversarial trials with a model-level verdict |
| Leakage | Scored synthetic-canary output tests |
| Detection recall | Successful application attacks |
| Model violation detection recall | Observed model boundary violations |
| False-positive rate | Completed, scored legitimate trials |
| Legitimate task completion | Scored legitimate trials; keyword/tool proxies |

Zero denominators yield **N/A**, not 0%. Errors and unadjudicated ambiguous outputs are counted separately. Partial runs retain their planned trial count and `in_progress` status; a partial report must not be treated as a completed evaluation.

The initial fixture report has 100% baseline and 0% secured application attack success **by script design**. Those percentages establish that grading and containment pathways work; they do not establish model or guardrail efficacy. The input heuristics also flag 12 of 60 legitimate trials per configuration, making their limitations visible. See [fixture findings](docs/fixture-findings.md).

## Repository guide

| Path | Contents |
|---|---|
| `aisec_lab/assistant.py`, `security.py` | Request composition and independent controls |
| `aisec_lab/models.py`, `runner.py` | Model adapters and bounded experiments |
| `aisec_lab/grading.py`, `reporting.py`, `store.py` | Verdicts, metrics, redacted exports, audit storage |
| `aisec_lab/soc.py` | Correlation and structured investigation checks |
| `aisec_lab/server.py`, `static/` | Local evidence dashboard |
| `aisec_lab/data/` | Curated synthetic evaluation cases and SOC events |
| `config/` | Five-slot model configuration template |
| `examples/fixture/` | Small, explicitly labeled example evidence bundle |
| `docs/` | Architecture, methodology, threat model, detections, runbook, findings, validation |
| `tests/` | Standard-library tests and an optional Playwright UI check |

## Verify or extend

```bash
python -m unittest discover -s tests -v
python scripts/build_cases.py
python -m aisec_lab validate
```

The corpus generator is deterministic and uses hand-authored cases. After changing a case, review its objective/rubric and regenerate results. An optional browser check and CI workflow are described in [validation](docs/validation.md).

Installation as a command-line package is optional:

```bash
python -m pip install .
aisec-lab demo
```

## Scope and references

Use authorized endpoints and synthetic data. This is an application-level research lab, not a production security boundary or proof of a model's overall security. It does not test training-data extraction, real enterprise integrations, or production throughput. Encoded leakage checks cover the planted canary's literal, base64, and hexadecimal forms, not every possible transformation. All SOC summaries require human review; valid references do not prove every generated claim is supported.

- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/)
- [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)
- [NIST Generative AI Profile, AI 600-1](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
- [NVIDIA garak](https://github.com/NVIDIA/garak), a complementary scanner; not a bundled dependency or part of the fixture results.

MIT licensed. See [LICENSE](LICENSE).
