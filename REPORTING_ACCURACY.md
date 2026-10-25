# KryptScan Assessment Accuracy Contract

## Purpose

KryptScan separates operational execution from security conclusions. A scanner process completing is not evidence that a target passed a security check.

## Check results

Every applicable automated check records:

- Execution status: `PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, `TIMED_OUT`, `CANCELLED`, or `SKIPPED`.
- Security result: `VULNERABLE`, `NOT_VULNERABLE`, `POTENTIAL`, `INCONCLUSIVE`, `NOT_TESTED`, or `NOT_APPLICABLE`.
- Category, elapsed execution time, and a client-safe diagnostic summary.

Connection failures, filtered-only port results, missing dependencies, empty discovery output that cannot be interpreted safely, and timeouts are not passes. They are inconclusive or failed checks.

## Coverage

Coverage is calculated as:

`successfully evaluated applicable checks / total applicable checks * 100`

A successfully evaluated check must complete and produce one of these security results: `VULNERABLE`, `NOT_VULNERABLE`, or `POTENTIAL`.

Failed, timed-out, skipped, and inconclusive checks do not increase coverage. Category-level coverage is derived from the same check records.

## Assessment outcomes

- `COMPLETED`: every applicable check produced a usable security result.
- `COMPLETED_WITH_LIMITATIONS`: at least 80 percent of applicable checks produced usable results, with documented limitations.
- `PARTIAL`: some usable results exist, but coverage is below 80 percent.
- `INCONCLUSIVE`: no applicable check produced enough evidence for a defensible security conclusion.
- `FAILED`, `CANCELLED`, and `NOT_STARTED`: reserved for their corresponding job lifecycle states.

The scan job may finish operationally while the assessment outcome remains partial or inconclusive.

## Risk model KS-RISK-2.0

KryptScan scores only supported evidence.

1. Findings are normalized and deduplicated.
2. Scanner errors and assessment notes are excluded from vulnerability counts.
3. Severity, CVSS-derived weight, confidence, and finding count contribute to the observed score.
4. Confirmed critical, high, medium, and low findings have minimum score floors of 80, 60, 35, and 15 respectively.
5. When no actionable finding exists, a numerical rating is issued only if coverage is at least 85 percent, with no failed or timed-out checks and no material inconclusive gap. A complete clean result receives a non-zero residual score of 5.
6. When evidence is insufficient, the score is `null` and the report displays `Overall Security Risk: Undetermined - Insufficient Assessment Evidence`.

Incomplete coverage never lowers the severity of a confirmed finding. A low observed finding count is not represented as proof that the environment is secure.

## Penetration-testing reports

Automated discovery and safe validation are not a completed professional penetration test. PT reports identify whether manual analyst evidence exists. Without manual exploitability validation and sign-off, the report says so explicitly and cannot claim a completed analyst-validated penetration test.

## Report integrity controls

- Report generation time is recorded at or after scan completion.
- Tool names are excluded from customer service inventory and affected-service charts.
- ANSI terminal control sequences are removed from evidence.
- AI narrative failure does not change deterministic findings, coverage, or risk. Rate-limited AI calls use bounded retries and an in-memory response cache.
- Artificial scan-duration delays are prohibited. Progress is taken from actual worker stages.

## Planned model extensions

External exploitation intelligence such as CISA KEV and EPSS, asset criticality, compensating controls, formal analyst approval, attack-path evidence, and organization-managed white-label assets require separately versioned data sources and review workflows before they can affect the score.
