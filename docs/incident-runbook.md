# AI assistant incident handling runbook

This playbook is exercised against synthetic lab events. Operational use would require organization-specific owners, retention requirements, and authorized containment mechanisms.

## 1. Triage

Open the trial or SOC evidence record. Confirm fixture/live source, run completeness, case objective, model settings, and correlation IDs. Distinguish suspicious input, unsafe model output, a denied proposal, and a permitted action. Check whether output redaction contained the observed leakage.

Treat a permitted sensitive action or unfiltered credential disclosure as high priority. A denied tool request warrants investigation but does not itself establish exfiltration. A malformed SOC response goes to human review; it must not become an automatic benign verdict.

## 2. Preserve evidence

Export the run's redacted JSONL, metrics, and Markdown report. Preserve corpus/configuration hashes, tool proposals/decisions, timestamps, resolved model IDs, incident event IDs, and adjudication rationale. Keep the original database; do not edit automatic verdicts to improve the result.

In this lab, the planted secret is redacted from persisted text in both modes. The observation booleans explain whether it was present before storage redaction. No real provider key or personal data should appear in evidence.

## 3. Contain

For the lab, switch to secured mode and stop the live run if needed. Completed trials remain available. In an actual application, the authorized operator would disable the affected tool/session, suspend automatic actions, isolate compromised context, and rotate an actually exposed credential. This project does not execute those actions.

## 4. Investigate

Trace the source of the untrusted instructions. Compare trusted task, document/log content, model response, proposed actions, and Python decisions. Review whether retrieval exposed restricted material, whether a model requested a prohibited action, and whether a control filtered the output.

For SOC evidence, correlate user, host, source address, and time. Inspect the failed-login sequence, subsequent success, asset criticality, privilege context, and AI references. Identify omitted events and verify the summary's claims against the original timeline.

## 5. Recover and validate

Repair the boundary in application code, add a regression case for the observed objective, and run legitimate tasks to measure usability impact. Re-run the same corpus/settings and preserve both result bundles. Separate mitigation tuning cases from held-out evaluation cases.

## 6. Record findings

Record the entry point, violated boundary, permitted effect, containment result, detection coverage, false-positive implications, evidence references, and residual limitations. Assign human-reviewed follow-up work. State whether the finding was synthetic, fixture-driven, or observed against a real model endpoint.
