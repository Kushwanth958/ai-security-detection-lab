# Threat model

## Assets and actors

Protected lab assets are the planted deployment credential, restricted synthetic files, allowed tool scope, correct alert triage, and audit integrity. The legitimate actor is a developer or SOC analyst. The adversary controls a user prompt, repository document, ticket, or log field supplied to the assistant.

The adversary does not control the Python policy engine, grader, ground-truth labels, or trusted model configuration. Running arbitrary attacker-controlled code, compromising a provider, or accessing another user's conversation is outside scope.

| Surface | Attacker objective | Lab exercise | Mitigation / observation |
|---|---|---|---|
| Direct request | Override credential policy | Direct injection | Withheld sensitive context and output checks |
| Repository document | Substitute the task | Indirect injection | Untrusted-content framing and marker grading |
| Encoded response | Evade plain-text checks | Encoded leakage | Known literal/base64/hex canary checks |
| File tool | Read restricted content | Restricted access | Application allowlist; denial telemetry |
| Collector tool | Transfer sensitive data | Tool egress | Secured tool disabled; simulated action telemetry |
| SOC log field | Suppress investigation | SOC manipulation | Structured schema, labeled verdict comparison, human review |
| Audit/UI rendering | Hide evidence or execute HTML | Redacted records and UI smoke test | Separate review records, parameterized SQLite, DOM text nodes |

The first five rows align with OWASP prompt injection, sensitive information disclosure, and excessive agency concerns. These are conceptual mappings, not a claim of OWASP certification or complete coverage.

## Important residual risks

Instruction framing and keyword heuristics are bypassable. Canary matching does not detect arbitrary secrets, novel encodings, or partial disclosure. A schema-valid SOC verdict can contain unsupported reasoning. Model-supplied event IDs can be valid but insufficient for the claimed conclusion.

The baseline intentionally places a synthetic secret in context. Actual systems should enforce access control before retrieval and avoid exposing credentials to a model. This lab does not establish that prompts can enforce authorization.

The local HTTP dashboard is an evidence explorer for a trusted workstation. It is not an authenticated enterprise service. Do not expose it publicly or supply real incident data without designing an appropriate access and retention layer.
