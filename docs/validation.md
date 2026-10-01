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
| Browser UI smoke test | Not executed successfully: no Chromium binary; download returned invalid archives |

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

To capture screenshots after a successful check, also set `LAB_SCREENSHOT_DIR=docs/assets`. Screenshots are not supplied in the initial bundle because the browser check could not run in the implementation environment.

The GitHub workflow defines separate Python-matrix and Chromium UI jobs. Remote CI has not run until the repository is published and the workflow executes. A declared workflow is not evidence of a passing remote check.
