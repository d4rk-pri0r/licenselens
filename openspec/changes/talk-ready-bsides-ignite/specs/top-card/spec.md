## Purpose

Defines the scan report top card — the shareable surface that states entitlement realization, ranked next moves, and trust seals for owners and MSPs.

## ADDED Requirements

### Requirement: Top card states ownership versus realization
The HTML report SHALL present a top card that includes distinct counts for capabilities the tenant owns (in-scope for the scan packs) and capabilities that are fully working, plus a realized percentage and a plain-language sentence restating how many owned capabilities are not fully working.

#### Scenario: Lab tenant with mixed outcomes
- **WHEN** a scan completes with eight owned in-scope capabilities and two fully working
- **THEN** the top card shows YOU OWN 8, FULLY WORKING 2, 25% realized, and a sentence equivalent to "6 of 8 still not fully working"

#### Scenario: Dry-run mode is visible
- **WHEN** a scan runs in dry-run mode
- **THEN** the top card clearly labels the mode as dry-run so the artifact cannot be mistaken for a live tenant assessment

### Requirement: Fully working excludes weak evidence
A capability MUST NOT count as fully working if any related finding is gap, partial, error, or skipped, or if related evidence is proxy-capped under strict proxy policy.

#### Scenario: Proxy-only capability
- **WHEN** all checks for an owned capability are proxy-based and quality policy caps status at partial
- **THEN** that capability counts toward YOU OWN but not FULLY WORKING

### Requirement: Top card shows at most three ranked moves
The top card SHALL list at most three top moves. Each move MUST include an owner-voice title, a one-sentence why, and an approximate effort label. Effort MUST be presented as a rough guide (not a precise estimate).

#### Scenario: More than three actionable findings
- **WHEN** more than three findings qualify as candidate moves
- **THEN** only the top three by ranking appear on the card and additional moves remain available below the card

### Requirement: EXPOSED chip is conditional
The top card SHALL show an EXPOSED summary chip only when at least one finding is classified exposed. When absent, the card MUST NOT reserve empty alarm chrome that implies exposure.

#### Scenario: No exposed findings
- **WHEN** a scan has gaps but no exposed findings
- **THEN** the top card omits the EXPOSED chip and shows ordinary attention/partial chips only

#### Scenario: One exposed finding
- **WHEN** a scan has one exposed finding
- **THEN** the top card shows an EXPOSED count and a short owner-voice hint for that exposure

### Requirement: Trust seal and attribution
The top card MUST include a trust strip stating read-only, advisory, not a Microsoft product, and attribution to d4rk-pri0r. The top card MUST NOT include Huntress marks or employer upsell.

#### Scenario: Screenshot includes seal
- **WHEN** a user views or screenshots the top card
- **THEN** version or product identity, read-only/advisory posture, non-affiliation, and d4rk-pri0r attribution are visible without scrolling below the card

### Requirement: Hallway line on the card
The top card SHALL display the product eyebrow line: "The security you already own (and ignore)".

#### Scenario: Default HTML report
- **WHEN** an HTML report is generated
- **THEN** the top card includes that eyebrow line near the product name
