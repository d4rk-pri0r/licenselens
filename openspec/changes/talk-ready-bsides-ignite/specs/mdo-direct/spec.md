## Purpose

Defender for Office email protection cannot be assessed with direct Graph evidence: the spike (Sep 2026) confirmed no Graph v1.0/beta API reads MDO policy configuration (preset Standard/Strict, Safe Links, Safe Attachments) — Exchange Online PowerShell is the only read path and needs an interactive session. This spec pins the email pack behavior: off the default talk path, never Secure-Score-proxy by default, direct evidence only via an explicit research opt-in.

## ADDED Requirements

### Requirement: Email pack is not a default talk pack
The email check (`mdo-p2-policies-default`) MUST NOT run in the default talk packs. The default demo ships identity + endpoint. The email check keeps its stable id for diff continuity but is excluded from default pack scope.

#### Scenario: Default demo scan
- **WHEN** an operator runs the default talk scan
- **THEN** the email check is out of scope (not in default packs) and the demo's data sources contain no Secure Score proxy for email

### Requirement: No Secure Score proxy by default
Secure Score MUST NOT be used as the default or primary evidence source for the email check. If a proxy is kept, it MUST be opt-in, clearly labeled proxy, subject to strict proxy quality policy, and MUST NOT roll up to fully working.

#### Scenario: Degraded proxy mode if enabled
- **WHEN** an operator explicitly opts into the Secure Score proxy for email
- **THEN** findings include proxy limitations, never roll up to fully working, and doctor labels the evidence as proxy

#### Scenario: Not licensed
- **WHEN** the tenant does not own the required email capability
- **THEN** the check returns not_licensed and does not report a false configuration gap

### Requirement: Opt-in research path may use Exchange Online PowerShell
A direct evidence path, if built, MUST use Exchange Online PowerShell (interactive, opt-in, research-only) reading preset-policy assignment / Safe Links / Safe Attachments state. It is not a default talk-pack dependency and is not required for the talk to be ready.

#### Scenario: EXO research run
- **WHEN** an operator supplies an interactive Exchange Online PowerShell session
- **THEN** the email check may evaluate with direct policy evidence labeled as research/EXO

### Requirement: Owner-voice email move
Email findings MUST provide customer_title and next step suitable for a top-card move without requiring product jargon in the title.

#### Scenario: Top move rendering
- **WHEN** the email check is among the top ranked gaps
- **THEN** the move title is verb-led and understandable to a moderately skilled IT generalist

### Requirement: Doctor probes email readability
Doctor (full or email-relevant profile) SHOULD report whether email protection signals are readable (opt-in proxy/EXO present) and, when not, give a one-line human fix pointing at the Exchange admin center or PowerShell. Doctor MUST NOT dump raw Graph errors as the only message.

#### Scenario: No email evidence available
- **WHEN** email signals are not readable (no opt-in path configured)
- **THEN** doctor marks a warning with a human-readable pointer and the scan still produces a partial overall card for the other packs
