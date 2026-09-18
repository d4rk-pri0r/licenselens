# Reading a LicenseLens report

The report has two jobs:

1. help an operator decide what deserves attention;
2. let a skeptical reviewer inspect why the tool reached that conclusion.

Those jobs are intentionally separated. The first screen is not a data dump, and the technical ledger is not the narrative.

## The reader's path

```text
Where you stand
  → What matters most
  → What you already own
  → Why this finding exists
  → Technical evidence
```

### 1. Where you stand

The large percentage is a capability rollup. Its sentence immediately beside it is the interpretation. The distribution bar shows the shape of the owned, assessed population without asking the reader to parse seven competing counters.

Use **How we got here** only when you need the denominator or the treatment of incomplete and unknown populations.

### 2. What matters most

This is the action page. It is intentionally short. The first move is the highest-ranked action from the engine; later moves are not equal recommendations, and should not visually compete with it.

Read the title and Why first. The action link is a route into Microsoft administration, not an instruction to make a change without review.

### 3. What you already own

This section explains the denominator behind the headline. It answers:

- which paid or observed capabilities were found;
- which are operational, incomplete, or need attention;
- why each capability matters.

The capability list is a summary surface. License plans, service-plan IDs, assignment counts, and raw entitlement provenance are supporting evidence and should remain closed until needed.

### 4. Findings

Findings explain the actions. Start with a finding that corresponds to a priority move, not with the full inventory.

The closed row is a triage surface: status, title, severity, workload, and a one-line signal. Expand it only when you need the belief block:

| Evidence slot | Meaning |
|---|---|
| Expected | The state defined by the check's contract. |
| Observed | The evidence-backed observation from this scan. |
| Why it matters | The capability and risk context. |
| Recommended action | The operator-facing next step. |
| Evidence | Sources, evidence fields, confidence, and limitations. |
| Admin destination | A starting page for manual review. |

The report does not treat all evidence equally:

- **Direct** means the control was read from the relevant surface.
- **Proxy** means a neighboring signal was used and must be verified.
- **Manual** means the API cannot establish the state.
- **Not assessed / incomplete** means the evidence did not permit a conclusion.

### 5. Technical reference

Technical details are for implementation review, troubleshooting, export, and integration. They include product names, SKUs, check IDs, evaluator references, and evidence fields.

They are deliberately last. A technical identifier is useful when you already know which decision or finding you are investigating; it is not a useful opening sentence for a customer.

## Why some numbers are not in the headline

LicenseLens keeps entitlement and assessment populations separate so a missing or ambiguous signal cannot inflate the score:

| Population | Used in headline? | Why |
|---|---:|---|
| Owned, assessed capabilities | Yes | This is the defined denominator. |
| Met assessed criteria | Yes | This is the defined numerator. |
| Not licensed | No | No entitlement means no activation gap. |
| Entitlement unknown | No | Ownership was not established. |
| Assessment incomplete | No | The evidence was insufficient. |

A clean headline is not permission to ignore the excluded populations. Open the accounting disclosure when the denominator matters.

## How to challenge a result

1. Copy the `check_id` and status from the finding.
2. Read Expected, Observed, Evaluation, Confidence, and Limitations together.
3. Inspect the named data sources and evidence fields.
4. Compare the finding's claim with the tenant scope and licensing assignment.
5. Reproduce the issue with a sanitized fixture or redacted artifact.
6. Use the matching practitioner challenge template if the claim remains wrong.

Do not submit tenant IDs, UPNs, tokens, secrets, or unredacted live reports.

## Why the report can be long

The report contains a full assessment inventory because the JSON and HTML are also evidence artifacts. The main path is not intended to expose every row at once. Use the nav for movement, the priority section for decisions, and the technical disclosure for audit work.

If a new report feature makes the main path harder to read, it belongs in progressive disclosure or in the reference docs instead.
