# Validation record

Validation performed during initial implementation on Python 3.12.14:

| Check | Observed result |
|---|---|
| Standard-library unit/integration tests | 48 passed |
| Resource-warning check | Tests passed with ResourceWarning configured as an error |
| Full offline evaluation | 300 recorded trials; zero provider/runner errors |
| Structured SOC pipeline | Four schema-valid fixture investigations with required evidence |
| JavaScript syntax | `node --check aisec_lab/static/app.js` passed |
| Package build/install | Wheel built and installed; bundled data and default commands verified outside the source directory |
| Browser UI smoke test | Passed in GitHub CI with Chromium; filters, pagination, evidence, SOC, mobile overflow, and hostile-text rendering checked |
| Remote Python matrix | Passed on Python 3.11, 3.12, and 3.13, including package installation outside the source tree |

The model-adapter integration tests use a local HTTP stub, not a public LLM. They verify the request contract, structured tool calls, safe error handling, redirects, and malformed-response handling. No real model evaluation or billing occurred during these checks.

The backend tests also cover encoded canary matching, traversal attempts, explicit live-mode authorization, preflight request budgets, separate model/application verdicts, review audit preservation, interrupted-run persistence, zero denominators, host checks, and SOC time/entity boundaries.

## Reproduce backend validation

```bash
python -m unittest discover -s tests -v
python -W error::ResourceWarning -m unittest discover -s tests
python -m aisec_lab validate
python -m aisec_lab demo
python -m aisec_lab report
python -m aisec_lab soc
```

## Optional browser verification

The UI check uses Playwright and Chromium. It covers filters, pagination, evidence inspection, keyboard dismissal, SOC view, mobile overflow, hostile-text rendering, and console errors. It expects a freshly generated three-repetition demo (300 trials) and SOC report.

```bash
npm install --prefix .ui-tools --no-save playwright@1.62.1
.ui-tools/node_modules/.bin/playwright install chromium --only-shell
python -m aisec_lab serve
```

In another terminal on macOS/Linux:

```bash
NODE_PATH=.ui-tools/node_modules node tests/ui_smoke.cjs
```

To capture screenshots after a successful check, also set `LAB_SCREENSHOT_DIR=docs/assets`. The GitHub browser job preserves screenshots as an artifact for visual inspection.

The GitHub workflow defines separate Python-matrix and Chromium UI jobs. All four jobs passed in [run 36882545584](https://github.com/Kushwanth958/ai-security-detection-lab/actions/runs/36882545584), at commit `84af7d0e654850d48b1555912f5d51c6e487d1f4`. The included dashboard and SOC screenshots were captured in that run and visually inspected before publication.

The initial browser assertion incorrectly expected a substring search for `direct_injection` to exclude `indirect_injection`. The corrected test uses `encoded_leakage` and passed. The application search behavior was unchanged. Local browser verification could not run because the implementation environment lacked Chromium and the download returned invalid archives; remote Chromium CI supplied the browser evidence.
