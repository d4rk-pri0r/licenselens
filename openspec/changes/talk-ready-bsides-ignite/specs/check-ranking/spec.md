## Purpose

Defines declarative check metadata and deterministic ranking so top moves and pack scope reflect SME judgment rather than check-id order.

## ADDED Requirements

### Requirement: Checks declare ranking metadata
Each enabled check definition MUST declare impact (high|medium|low), approximate effort (minutes|hours|half_day|days), blast radius, pack membership (identity|email|endpoint|starter), and exposure_class (none|elevated|exposed). Missing required metadata MUST fail check loading or CI validation.

#### Scenario: Valid identity check loads
- **WHEN** checks are loaded from the checks tree
- **THEN** every enabled check exposes impact, effort, blast_radius, pack, and exposure_class to the scan engine

#### Scenario: Missing effort rejected
- **WHEN** an enabled check omits effort
- **THEN** loader or validation reports an error identifying the check id

### Requirement: Default talk packs
Unless the operator overrides packs, a normal scan MUST include identity, email, and endpoint packs and MAY include starter pack checks. Starter findings MUST NOT outrank talk-pack gaps of equal or higher impact when building top moves.

#### Scenario: Default scan ranking preference
- **WHEN** top moves are selected and both a starter partial and an identity gap exist
- **THEN** the identity gap is preferred over the starter partial for card placement

### Requirement: Deterministic move ranking
The system SHALL rank candidate moves with a deterministic function of impact, exposure_class, confidence, pack preference, and effort penalty. Equal scores MUST break ties by stable check id ordering.

#### Scenario: Exposed outranks ordinary gap
- **WHEN** one finding is exposed and another is an ordinary high-impact gap with similar effort
- **THEN** the exposed finding ranks higher for top moves

#### Scenario: Proxy confidence cannot crown a winner over direct gap
- **WHEN** a proxy-capped partial competes with a direct-evidence gap
- **THEN** the direct-evidence gap ranks higher

### Requirement: Move objects not bare strings
Scan results MUST expose structured move objects including title, why text, effort label, related check ids, and optional portal deep link — not only a flat list of recommendation strings.

#### Scenario: JSON artifact consumers
- **WHEN** a scan JSON is written
- **THEN** ranked moves are available as structured objects suitable for the HTML card and MSP index
