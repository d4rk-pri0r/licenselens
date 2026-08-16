# DESIGN_V2 — Security License Lens HTML Report (v2, true redesign)

> Status: the binding implementation contract for the v2 report redesign.
> This document **supersedes `DESIGN.md` (v1) and every prior v2 draft in full** —
> including the earlier "Ink and Verdigris" contract, which is withdrawn. Where an old
> constraint conflicts with this document, this document wins. Nothing ships that is not
> declared here.
>
> Audience: the engineer implementing the v2 templates. Architecture is fixed and may not
> change: **Jinja2 templates + hand-written CSS + vanilla JS, offline-first, zero build
> step, zero external resources.** No React/Vue/Svelte/Vite/Tailwind, no CDN, no external
> fonts, no external images, no chart libraries, no API calls, no data-URIs, no network
> requests of any kind. The report must render identically from a local file with the
> network unplugged.

## 0. Research log

- **Owner brief** (`.omo/notepads/report-design-v2-realization/learnings.md`): the redesign
  is *fundamentally different*, not an incremental refresh. v1 constraints are superseded:
  10–16px radii, softer surfaces, selective elevation, more negative space, larger type,
  subtle tonal gradients, controlled blur, meaningful animation, animated data viz,
  progressive disclosure, hierarchy-first metrics, interactive constellation, branded
  workload icons restored, data-driven opening sequence.
- **Existing templates** (`templates/report/v2/*.j2`, `templates/report.html.j2`,
  `templates/report_app/v2/app.{css,js}`): the renderers already support server-rendered
  content with JS enhancement (body-class opt-in animation), native `<details>` disclosure,
  inline SVG glyphs, data-attribute filtering, hashed `<img>` icon plumbing
  (`vendor_assets.py` `REPORT_WORKLOAD_TO_ICON_KEY`), and sr-only chart data tables. This
  contract reuses those mechanisms and retires their "Ink and Verdigris" styling layer only.
- **ui-ux-pro-max design DB**: micro-interactions 150–300ms (never >500ms except the
  single orchestrated opening sequence); animate at most a small number of key elements;
  `prefers-reduced-motion` always; data-dense interfaces want a sans body + mono for
  technical values; hover feedback via color/border, never layout shift.

## 1. Identity and guardrails

**Identity: "Warm Charcoal".** A warm charcoal canvas with muted, warm-neutral surfaces and
a restrained champagne-ivory identity accent. Premium, calm, instrument-like. The only
chromatic color in the UI is **semantic** (red / amber / green). The identity accent is a
warm *neutral* and therefore can never be confused with a status. Blue as a UI-wide accent
is retired; the blue in the page comes from branded Microsoft workload marks only.

**Architecture guardrails (non-negotiable, unchanged from v1):**

- Offline-first. No external JS/CSS/images/chart libraries/API calls to render. No data-URI
  assets in the single-file renderer. Network access is not required for any behavior.
- No frontend framework. Jinja + CSS + vanilla JS only.
- Semantic HTML: exactly one `<main>`, exactly one `<h1>`, heading levels never skip
  (`h1 → h2 → h3` only).
- WCAG 2.2 AA: keyboard navigation, visible `:focus-visible`, screen-reader labels, status
  never color-only, `prefers-reduced-motion` honored, `forced-colors` honored.
- Print stylesheet: light ink inversion, expanded content predictable, visualizations get
  textual fallbacks.
- Responsive at 900px and 640px breakpoints.
- Performance for several hundred findings: server-rendered DOM, delegated events, no
  per-finding listeners, no virtualization that breaks print/search.

**Retired "Ink and Verdigris" constraints (withdrawn, must not reappear):**

- The radius ceiling of 4px. **Withdrawn.** Radii up to 16px are authorized where declared
  in section 4.
- The blanket ban on gradients. **Withdrawn.** Two pinned, subtle tonal gradients are
  authorized in section 3.
- The blanket ban on blur / `backdrop-filter`. **Withdrawn.** One controlled blur is
  authorized on the sticky navigation in section 10.
- The retirement of the `<img>` workload-icon allowlist. **Withdrawn.** The 12 branded
  workload marks are restored; render rules in section 12.
- The "Ink and Verdigris" token ramp, the equal-weight metric-card grid, the static
  constellation, and the 0.95rem body scale. **Withdrawn and replaced below.**

**Still forbidden (unchanged, plus what the owner's brief adds):**

- No pure black `#000000` canvas or surface fill.
- No saturated navy `#5b9dff`-style product accent, no neon, no violet/purple UI chrome.
- No glassmorphism: no translucent surfaces, no `backdrop-filter` except the single pinned
  nav blur in section 10.
- No arbitrary or hue-shifting gradients; only the two pinned tonal gradients in section 3.
- No external font, icon package, image asset, chart library, data-URI, or network request.
- No emoji for metadata, statuses, labels, or icons.
- No light-mode screen UI. Screen is always dark; only print inverts to light ink.
- No bouncing cards, floating icons, perpetual ambient motion, looping gradients, animated
  backgrounds, wobbling controls, dramatic parallax, logo theatrics. (Section 11.)

## 2. Token palette

Declared once in `:root`, referenced by name everywhere else. Never re-declared. The only
literal hex values in any shipped CSS live inside the `:root` block; every other selector
references tokens.

### 2.1 Screen tokens (dark-first, warm)

| Token | Hex | Role |
| --- | --- | --- |
| `--canvas` | `#191714` | Warm charcoal page stock |
| `--surface-1` | `#211E1A` | Primary surface (sections, findings, table bodies) |
| `--surface-2` | `#2A2621` | Secondary surface (capability rows, move items, filter bars) |
| `--surface-3` | `#332E27` | Raised surface (open disclosures, selected panes, sticky nav) |
| `--surface-4` | `#3D3730` | Highest surface (focused panes, masthead chrome) |
| `--border` | `#37322B` | Default 1px rule |
| `--border-strong` | `#4A443B` | Strong / emphasis 1px rule |
| `--text-1` | `#F2EFE9` | Primary ink (warm near-white) |
| `--text-2` | `#B8B2A7` | Secondary ink (labels, meta, section help) |
| `--text-3` | `#8A847A` | Tertiary ink (captions, placeholders, faint counts) |
| `--accent` | `#E8DFC8` | Champagne-ivory identity + interaction (links, focus, selection, posture figure, logo mark) |
| `--accent-hover` | `#F5EFDD` | Accent hover |
| `--accent-focus` | `#FFF6E3` | Focus ring |
| `--accent-print` | `#57482E` | Warm umber print ink for links and identity figures |
| `--state-action` | `#E5695F` | Action-required (gap) and error (≥ 5:1 on `--canvas`) |
| `--state-incomplete` | `#D9A03F` | Incomplete (partial) (≥ 7:1 on `--canvas`) |
| `--state-ok` | `#55AE84` | Operational (ok) (≥ 6:1 on `--canvas`) |
| `--state-neutral` | `#9E988C` | Neutral (not-licensed / skipped) (≥ 5:1 on `--canvas`) |
| `--grad-hero` | `linear-gradient(165deg, var(--surface-2) 0%, var(--surface-1) 55%, var(--canvas) 100%)` | Pinned tonal wash, hero only |
| `--grad-raised` | `linear-gradient(180deg, var(--surface-3) 0%, var(--surface-2) 100%)` | Pinned tonal wash, elevated panes (selected finding, open side panel) |
| `--shadow-1` | `0 1px 2px rgba(0,0,0,.35), 0 1px 4px rgba(0,0,0,.25)` | Raised controls, open disclosures |
| `--shadow-2` | `0 2px 6px rgba(0,0,0,.4), 0 8px 20px rgba(0,0,0,.35)` | Elevated panes: selected finding, side panel, floating sticky nav |
| `--shadow-3` | `0 4px 12px rgba(0,0,0,.45), 0 16px 40px rgba(0,0,0,.4)` | Hero only |
| `--blur-nav` | `blur(8px)` | The single authorized blur (section 10) |

### 2.2 Print tokens (light inversion)

Screen is always dark; `@media print` inverts to light ink by swapping to these tokens:

| Token | Hex | Role |
| --- | --- | --- |
| `--print-ink` | `#23201B` | Warm near-black body text (never `#000000`) |
| `--print-paper` | `#FFFFFF` | Paper |
| `--print-hero` | `#F6F3EC` | Warm paper hero wash |
| `--print-border` | `#D8D2C7` | Default print rule |
| `--print-border-strong` | `#A79F90` | Strong print rule |
| `--print-action` | `#B03A26` | Print gap/error (≥ 6:1 on white) |
| `--print-incomplete` | `#7A5200` | Print partial (≥ 6.8:1 on white) |
| `--print-ok` | `#20603C` | Print ok (≥ 6.2:1 on white) |
| `--print-neutral` | `#5A625C` | Print neutral (≥ 6.5:1 on white) |

### 2.3 Usage rules and contrast floors

- **Accent is identity-only.** It colors the logo mark, links (always underlined at
  default text sizes), focus rings, selection, the posture figure, and the active state of
  segmented controls. It never colors a semantic status and never colors chart data.
- **Semantic mapping (locked):** `gap` → `--state-action`; `partial` → `--state-incomplete`;
  `ok` → `--state-ok`; `not_licensed` → `--state-neutral`; `skipped` → `--state-neutral`;
  `error` → `--state-action` (rail + label, screen and print, same as gap).
  Capability-outcome statuses map onto the same variants:
  `needs_attention` → `gap`, `partly_set_up` → `partial`, `fully_working` → `ok`,
  `not_licensed` → `not_licensed`.
- **Contrast floors (WCAG 2.2 AA), pre-measured:** body text ≥ 4.5:1; large text and
  non-text status indicators ≥ 3:1; `--text-3` ≥ 4:1 on `--surface-1` and must never carry
  essential information alone; focus ring ≥ 3:1 against any adjacent surface; print accent
  ≥ 7:1. The measured ratios are part of the contract — a palette edit requires
  re-measurement.
- **Surface ladder:** `--canvas` → `--surface-1` → `--surface-2` → `--surface-3` →
  `--surface-4`. Every declared token must be consumed by at least one selector; dead
  tokens are a violation.
- **Gradient policy:** `--grad-hero` and `--grad-raised` are the only gradients in the
  system. Both are single-hue warm tonal lifts (surface-to-surface); no hue shifts, no
  `color-mix()`, no gradient on text, no gradient on interactive controls.
- **Blur policy:** `--blur-nav` is the only blur. It applies to the sticky contextual nav
  only, behind a `@supports (backdrop-filter: blur(1px))` guard with an opaque
  `--surface-3` fallback; disabled in print and forced-colors.

## 3. Typography

System-only, offline-safe stacks (locked values).

| Role | Value |
| --- | --- |
| Sans stack | `"Segoe UI Variable Text", "Segoe UI", ui-sans-serif, system-ui, -apple-system, sans-serif` |
| Mono stack | `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace` |

**Type scale (locked, larger than v1 by mandate):**

| Role | Size / weight / line-height | Notes |
| --- | --- | --- |
| Display (signature line) | `2rem / 650 / 1.2` | Hero opening line only; `letter-spacing: -0.01em` |
| Hero figure (dominant metric) | `3.5rem / 650 / 1.05` | The one dominant metric; `tabular-nums` |
| Metric figure (secondary) | `1.75rem / 600 / 1.15` | Supporting stats; `tabular-nums` |
| h1 (masthead) | `1.5rem / 650 / 1.25` | Exactly one per page |
| Section heading (h2) | `1.25rem / 600 / 1.3` | Sections A–E |
| Card / finding title (h3) | `1.06rem / 600 / 1.35` | Finding titles, capability names |
| Body | `1rem / 400 / 1.6` | Prose (up from v1's 0.95rem) |
| Body-strong | `1rem / 600 / 1.6` | Lead-ins, belief-slot values |
| Label | `0.8125rem / 600 / 1.4` | Meta rows, filter labels |
| Micro-label | `0.75rem / 700 / 1.4` | Section kickers and group captions only; `0.03em` letter-spacing |
| Tech meta (mono) | `0.8125rem / 400 / 1.5` | Config values, IDs, evidence |

**Heading hierarchy (locked):** exactly one `<h1>` ("Security License Lens" in the
masthead); one `<h2>` per section A–E; `<h3>` for finding titles and capability names. No
skipped levels. The signature opening line is display text in a `<p>`, **not** a heading,
so the tree stays `h1 → h2 → h3`.

**Case and personality rules (this is where v1 failed):**

- **No all-uppercase everywhere.** Uppercase is reserved for *section kickers* and
  *constellation group captions* (micro-label role) — nothing else. Status words, filter
  labels, meta keys, and buttons are title case.
- **Monospace is not the personality.** The mono stack renders *only*: `check_id` values,
  SKU part numbers, service-plan names, timestamps, evidence keys and values, paths,
  commands, object names, configuration values, and numeric columns. Never headings, never
  body prose, never status words.
- **Numeral rules:** every metric figure sets `font-variant-numeric: tabular-nums`;
  numbers right-align, text left-aligns; long tokens wrap with `overflow-wrap: anywhere`.
- **Comfortable reading:** body copy is 1rem/1.6 with `max-width: 72ch` on prose blocks;
  the finding summary and belief slots never run full column width at desktop.

## 4. Radius, spacing, layout, elevation

- **Base unit: 4px.** Every padding, gap, and inset is a multiple of 4.
- **Spacing stops:** 4, 8, 12, 16, 20, 24, 32, 48, 64. Canonical values below reflect
  "substantially more negative space" vs v1: section padding `24px 32px`, section gap
  `24px`, hero padding `32px 40px`, card padding `20px`, finding gap `16px`, page gutters
  `32px`, grid gaps `16px`/`24px`.
- **Radius contract (replaces the 4px ceiling):**
  - `0px` — tables, finding status rails, masthead, open section boundaries.
  - `2px` — inputs, selects, search box, evidence code blocks.
  - `6px` — buttons, filter chips, status labels, effort labels.
  - `10px` — cards, capability rows, move items, chart frames, small panes.
  - `16px` — hero, side panel, selected/elevated panes, constellation group container.
  - `999px` (pill) — **only** for proportion-based fills: the posture track, the
    operational-distribution segments, and horizontal chart bars. Never for text-bearing
    controls, labels, or chips.
- **Elevation is selective.** Shadows communicate *state*, not decoration: `--shadow-1` on
  open disclosures and raised controls; `--shadow-2` on the selected finding, an open side
  panel, and the sticky nav once it floats; `--shadow-3` on the hero only. A card at rest
  has no shadow. Depth otherwise comes from the tonal ladder and the two pinned gradients.
- **Layout:** desktop 12-column grid, content max-width `1160px`, centered. Breakpoints
  `900px` and `640px`: at 900px the two-column hero collapses to a single column and the
  nav wraps; at 640px gutters halve, the hero figure scales to `2.5rem`, the constellation
  scrolls horizontally with visible scroll affordance, and tables get `overflow-x: auto`
  wrappers (same collapse behavior as v1).
- **Target sizes:** coarse pointer minimum `44×44px`; fine pointer
  (`@media (pointer: fine)`) minimum `24×24px`.
- **Not everything is a card (binding).** The page is a mixture of:
  - *open typographic layout* for the hero (dominant figure, prose, distribution strip);
  - *whitespace and rules* for section boundaries (`--border` rules, no box chrome);
  - *tables* for SKUs, evidence, and chart fallbacks;
  - *cards* only where a bounded unit earns it (capability row, move item, chart frame);
  - *elevated surfaces* only for the currently selected/focused element.

## 5. Information architecture (A–E, in this order)

The report is a single bounded `<main>` containing five sections, exactly in order A, B, C,
D, E. Section labels:

- **A — "Where you stand"** (signature opening; hierarchy-first)
- **B — "What you're paying for"** (entitlements → capabilities; signature constellation)
- **C — "What matters most"** (prioritized recommendations)
- **D — "Why LicenseLens believes this"** (per-finding belief blocks)
- **E — "Explore everything"** (search, filters, charts, findings, deep links)

### A. "Where you stand" — the signature opening sequence

**Hierarchy-first: ONE dominant metric.** Section A is dominated by the posture figure
(`capability_rollup.realized_percent`, rendered as `<N>% realized` at hero-figure size).
The supporting numbers — owned, fully working, needs attention, partly set up, not
licensed — are **secondary statistics that support the dominant metric**, rendered as a
compact inline stat strip separated by rules and an operational-distribution bar. **It is
explicitly not a grid of six equal metric cards.** Any implementer who ships a
`grid-template-columns: repeat(auto-fit, minmax(120px, 1fr))` row of equal boxes in section
A has violated this contract.

**Opening sequence, exact order and copy structure** (all values data-driven from the view
model — the template contains no literal numbers; `17% realized` and "5 of 6" are
illustrative sample data only):

1. **Org / tenant identity** — one line: `{tenant_display_name or tenant_id or
   "demo / dry-run"} — Security License Lens assessment`. Binds the same source as the
   masthead organization row.
2. **Assessment identity** — one meta line: version, `display_scanned_at`, mode, and
   `packs_scanned` priority packs.
3. **Posture metric count-up** — `realized_percent` counts 0 → N (section 11).
4. **Posture visualization** — the radial realization gauge draws, and the operational
   distribution bar fills to its proportions (sections 9 and 11).
5. **Operational distribution** — three labeled items: `needs_attention` ("Action
   required"), `partly_set_up` ("Incomplete"), `fully_working` ("Operational"), each with
   its status marker (glyph + word + color). `not_licensed` may appear as a fourth,
   neutral item.
6. **Most important implication** — one sentence bound from the rollup: "N of your M
   priority capabilities need attention" where N = `needs_attention` and M = `you_own`;
   when N is 0 the sentence must read as the positive equivalent (e.g. "All M of your
   priority capabilities are operational"), derived from the same fields — never a
   hardcoded string. `realized_sentence` remains the supporting sentence beneath.
7. **Highest-impact actions** — the top 2–3 items from `moves` (section C's source list),
   title + effort label, each linked to its move in section C.

When `has_exposed` is true or any gap/error finding exists, the 3px `--state-action` left
rail from v1 is retained: it lists the exposed/gap check titles (from `exposed_check_ids`
resolved against findings), capped at three with "and N more" trailing text.

### B. "What you're paying for"

**Purpose.** Show the entitlements the tenant already pays for and what each maps to.

- **Owned SKUs strip:** one row per `subscribed_skus` entry — SKU name and part number in
  mono, license count right-aligned `tabular-nums`. A compact table, not cards.
- **Capability field (signature visualization):** the capability constellation, section 7.
  It is the section's centerpiece.
- **Capability detail list:** summary rows first, context on demand (section 8). Each row
  shows the workload brand icon (section 12), `plain_name`, status marker, and the first
  sentence of "What it does". The expansion reveals "Why it matters" (`why_it_matters`),
  "If left off" (`if_unused`), and provenance (matched SKUs and service plans, mono).
  Explicitly **not** a giant expandable card containing everything up front.

### C. "What matters most"

- Renders `moves` (the `TopMove` list), at most the top 3, as an `<ol>`.
- Each item: bold `title`, effort label (bound `effort_label`, e.g. "~a few hours"), a
  "Why" line (`why`), and an action line (`customer_next_step`). `deep_link`, when present,
  renders as the visible text link "Open the admin page" — accent color, underlined, no
  fake button.
- Order is rank: the model's list order is authoritative; the UI must not re-sort.
- Each move item is a bounded surface (10px radius, `--surface-2`) but the items are a
  *numbered sequence*, not equal cards: the first item is visually dominant (larger title,
  `--shadow-1`).

### D. "Why LicenseLens believes this"

Per-finding belief block. Every finding renders as a full-width `article` with a 3px left
status rail and a header (status marker + title + meta row: severity, effort, scope,
workload, confidence, evaluation mode). The body is the **six-slot belief block**, always
in this order, each slot with a visible bold label prefix:

| Slot | Label | Binding (in fallback order) |
| --- | --- | --- |
| 1 | Expected | `summary`, then `customer_summary` |
| 2 | Observed | `customer_summary`, then evidence-derived summary line |
| 3 | Why it matters | `impact_label` + `severity` label |
| 4 | Recommended action | `customer_next_step`, then `remediation` |
| 5 | Evidence | `data_sources` + `evidence` keys inside the disclosure (section 8) |
| 6 | Admin destination | `deep_link` as the visible link "Open the admin page" |

Slot 5's detail lives in a native `<details class="tech">` disclosure holding the evidence
table and `source_references`. Empty optional fields render "Not reported" — never crash.

Findings are open typographic articles separated by rules, not stacked cards. The
**selected / focused finding** becomes an elevated surface (`--surface-3`, `--grad-raised`,
`--shadow-2`, 10px radius) — one at a time, never all.

### E. "Explore everything"

- **Search:** `<input type="search">`, visible label "Search findings", `autocomplete="off"`
  `spellcheck="false"`. Case-insensitive substring match over finding text only. Never
  regex against user input, never render matches back as HTML.
- **Filter groups:** one `role="group"` (with `aria-label`) per facet — status, severity,
  confidence, evaluation mode, pack, workload. Within a group selection is OR
  (multi-toggle); across groups facets compose with AND. Every button exposes
  `aria-pressed`. A "Clear all" control resets all groups and the search box.
- **Sort:** a native `<select>` with a visible label. Options (fixed): "Impact (default)",
  "Severity", "Effort", "Title A–Z". Default is model rank order; only "Title A–Z" is a
  locale-insensitive byte sort — all others are deterministic and documented here.
- **Counts:** result count is `role="status"` `aria-live="polite"`, right-aligned,
  `tabular-nums`.
- **Pagination:** prev/next buttons, "Page N of M", page-size select 25/50/100; hidden when
  zero results. Page changes preserve focus on the pager.
- **Charts:** the four data-visualization figures from section 9 live at the top of E.
- **Deep linking:** `#finding-<check_id>` selects, reveals, and scrolls to a finding
  (paging to its page in the bundle app); `#section-a` … `#section-e` anchor the sections.

## 6. Sticky contextual navigation and section-aware state

- **Bundle app only:** a sticky nav (`position: sticky; top: 0`) listing A–E with the
  workload nav, rendered on `--surface-3` with the `--blur-nav` backdrop blur (section 2.3
  guards). Links carry `aria-current="true"` for the section currently in view, updated by
  an IntersectionObserver scrollspy (no scroll listeners). Keyboard focus into any nav item
  is visible per section 13.
- **Single-file renderer:** a compact table-of-contents list under the masthead linking to
  the five sections (same anchors, same labels) — no sticky behavior required, no
  scrollspy.
- Workload nav state and section state are the same mechanism: `aria-current` on exactly
  one nav target; `is-active` class is never the only indicator.

## 7. Signature visualization: the capability constellation

A deterministic field of capability nodes grouped by workload. **Not a sci-fi network
map** — no node-link topology, no edges, no physics, no canvas, no randomness, no glow.

**Data.** One node per `capability_outcomes` entry, sorted and grouped exactly as the view
model emits (`build_constellation`): groups in the fixed workload order
`identity, defender, sentinel, purview, endpoint, exchange, collaboration, teams,
power_platform, power_bi, intune, azure, general`; within a group, nodes sorted by
`plain_name` ascending (byte sort, locale-insensitive). Identical input yields identical
pixels, always.

**Node anatomy.** Each node is a 16×16px circle (pill radius authorized for this
proportion-free decorative fill) with a 2px status-colored ring and a soft status-tinted
translucent fill, beside its `plain_name` label (`0.8125rem`, `--text-2`). Status is never
the only channel: every node's label is always visible, every group carries a caption with
the workload's branded icon + plain name (icon never alone), and a legend maps the six
statuses to words + colors.

**Group caption.** Brand icon (section 12) + workload plain name as micro-label. The
caption is a button in both renderers: activating it toggles the workload facet filter
across the page (cross-filtering, section 10).

**Grouping and reconfiguration.** Default: groups render as columns in fixed enum order.
Workload selection (nav tab, filter chip, or group caption) **reconfigures the field**:
the selected workload's group becomes the first column, remaining groups follow in enum
order, and the selected group's container is emphasized (`--border-strong`, `--shadow-1`).
"All" restores the default order. Reconfiguration animates via FLIP (section 11); the DOM
order is the only thing that changes — nodes never move outside their group.

**Resolution animation.** On first reveal, every node starts at `--state-neutral` color and
resolves to its status color column by column (section 11).

## 8. Progressive disclosure

Three levels, always in this order, never all at once:

1. **Summary** — finding: title, status marker, meta row, slot 1–2 prose (Expected /
   Observed). Capability: row with brand icon, name, status, one-line "What it does".
2. **Explanation** — finding: slots 3–4 (Why it matters / Recommended action) plus the
   admin link. Capability: the expansion with why-it-matters / if-unused / provenance.
3. **Evidence** — the `<details class="tech">` disclosure: evidence keys, `data_sources`,
   `source_references`, technical table.

**Mechanism:** native `<details>` everywhere — the single-file renderer must work with zero
JavaScript. Closed state: dashed `--border` on `--surface-1`; open state: solid
`--border-strong` on `--surface-3` with `--shadow-1`. Caret glyph (decorative,
`aria-hidden`) rotates 90° on open. Native keyboard/AT behavior; state conveyed via
`open`. **No giant expandable card contains everything** — the finding article is always
open prose + rail; only evidence is collapsible. Capability rows are summary rows + a
`<details>`; the bundle app may additionally anchor a side panel for a selected capability,
but the panel must contain the same three levels in the same order and be keyboard
reachable (focus moved on open, returned on close).

**Evidence expands beneath findings.** Opening a disclosure grows content downward in
place; it never floats over, never covers, never scroll-jumps the page.

## 9. Data visualization contract

Every chart answers one question. There are exactly four figures (bundle) / three
(single-file), plus the two hero visualizations. No default Chart.js-dashboard aesthetic:
no doughnut libraries, no stacked card walls, no decorative grids.

| Figure | Question it answers | Form | Data |
| --- | --- | --- | --- |
| Posture radial gauge (A) | "How much of my investment is realized?" | Radial arc, realization % — radial is used *because the datum is a single proportion* (mathematically appropriate) | `capability_rollup.realized_percent` |
| Operational distribution (A) | "How is my posture distributed?" | Segmented horizontal bar: action / incomplete / operational segments proportional to counts; `999px` caps | `you_own`, `fully_working`, `needs_attention`, `partly_set_up`, `not_licensed` |
| Findings by status (E) | "What kind of shape are my findings in?" | Clean horizontal bars, one per status, status colors | `findings` grouped by `status` |
| Findings by workload (E) | "Where are the gaps concentrated?" | Horizontal bars with branded icon + label per workload | `findings` grouped by `workload` |
| Findings by severity (E) | "How bad is it?" | Horizontal bars | `findings` grouped by `severity` |
| Findings by confidence / mode (E) | "How sure are we?" | Horizontal bars | `findings` grouped by `confidence` / `evaluation_mode` |

- Bars are labeled on the row (label left, value right, `tabular-nums`); the bar itself is
  a proportion of the largest value, never misleadingly from zero-max.
- **Accessibility (binding, both renderers):** every figure is a `<figure>` whose body is
  `role="img"` with `aria-labelledby` (figcaption id) and `aria-describedby`, plus a
  visually-hidden equivalent data table (`sr-only`) — the existing v2 pattern is retained.
- **Print:** the sr-only data table becomes visible (styled print table) as the textual
  fallback for every chart; SVG bars render flat with `print-color-adjust: exact`.
- **Animation:** bars grow to their proportions on first reveal (`transform: scaleX(0→1)`,
  `transform-origin: inline-start`, GPU-composited); the radial gauge draws via
  `stroke-dashoffset`; the segmented bar fills left-to-right. Once. Never re-animates on
  filter changes (filter changes swap values instantly with a ≤150ms color-only
  transition).
- **Chart-to-finding cross-filtering:** a bar (or segment) is a `<button>` inside the
  figure with an accessible name like "Filter findings: Action required"; activating it
  toggles the corresponding facet filter (section 10) and scrolls E's list into view.

## 10. Interactivity

- **Workload selection** reconfigures the constellation (section 7) and filters findings
  by workload facet. Controls: bundle nav tabs, filter chips, constellation group captions.
  All three stay in sync (single source of truth in JS state; `aria-pressed` /
  `aria-current` everywhere).
- **Status filtering** via filter chips; each chip shows the status glyph + word.
- **Capability selection:** activating a node or capability row filters section D's
  findings to the capability's `related_check_ids` and scrolls to section D. The node
  becomes the selected node (ring thickens to 3px `--accent` — but status color remains on
  the ring's inner edge so status is never lost).
- **Finding focus:** clicking (or deep-linking to) a finding elevates it (section 5 D) and
  highlights its related capability node and matching chart bars (`is-related` class:
  `--accent` outline). Exactly one finding is selected at a time; `aria-expanded` state
  lives on the finding's disclosure only.
- **Smooth evidence expansion:** native `<details>`; content fade ≤150ms; no scroll jump.
- **Chart-to-finding cross-filtering:** section 9.
- **Deep linking:** `#finding-<check_id>`, `#section-a…e`; the bundle app syncs filters to
  the URL hash on change and restores them on load.
- **Sticky contextual navigation and section-aware nav state:** section 6.
- **Keyboard-accessible, nothing hover-only.** Every interactive surface is a real
  control (button / link / details) reachable and operable by keyboard; hover is a
  redundant affordance (color/border change ≤150ms), never the only one. No
  `onmouseenter`-only behavior anywhere.

## 11. Motion contract

Motion is **information design**: it animates information arriving, reconfiguring, or
expanding. Everything is server-rendered; animation is an opt-in enhancement (JS adds a
`body` class; without JS the page is fully visible and static — no information loss).

**Opening sequence (signature), total 500–1000ms, then calm:**

| Stage | Element | Timing |
| --- | --- | --- |
| 1 | Org/tenant identity line | fade + 6px rise, `200ms ease-out`, t≈0ms |
| 2 | Assessment meta line | `200ms ease-out`, delay `60ms` |
| 3 | Posture metric count-up 0→N | rAF, `700ms ease-out`, delay `120ms`, `tabular-nums`, lands exactly on N |
| 4a | Radial gauge draw | `stroke-dashoffset` to value, `700ms ease-out`, delay `160ms` |
| 4b | Distribution bar fill | segments `scaleX(0→1)` left-to-right, `600ms ease-out`, delay `200ms` |
| 5 | Distribution labels (3–4) | fade + rise, `250ms`, stagger `60ms` |
| 6 | Implication sentence | fade + rise, `300ms ease-out`, delay `380ms` |
| 7 | Top actions (2–3) | fade + rise, `300ms`, stagger `80ms` |

Sequence is data-driven at every stage. Under `prefers-reduced-motion` the final state is
instant (below).

**Reveal and construction (once, calm):**

| Animation | Target | Timing |
| --- | --- | --- |
| Constellation resolve | Nodes start `--state-neutral`, resolve to status color column by column in deterministic order | `450ms ease-out`, `50ms` per column |
| Chart construction | Bars `scaleX(0→1)`; rows staggered | `500ms ease-out` (cubic-bezier(0.22, 1, 0.36, 1)), `40ms` per row |
| Below-fold section reveal | Sections B–E on first entry: fade + 6px rise, one-shot IntersectionObserver (threshold 0.12, observe once, unobserve after) | `250ms ease-out`, `40ms` stagger |
| Priority actions entry | C-section items | `300ms`, `80ms` stagger, restrained |
| Evidence expansion | Disclosure content fade; caret rotate 90° | `≤150ms` |
| Workload reconfiguration | Constellation groups reorder via FLIP (rAF measure → transform → settle) | `300ms ease-out` |
| Interactive states | Color, border, background only on buttons/links/inputs/summary | `≤150ms` |
| Filter result swaps | Value text and bar widths update instantly; only color/border transitions | `≤150ms`, no layout animation |

**Rules:**

- Only `transform` and `opacity` animate position/appearance (plus `stroke-dashoffset` for
  the gauge). No layout-property animation (no `height`/`width`/`margin` transitions).
- Nothing loops; nothing is ambient; nothing animates continuously while the user scrolls
  or types (one-shot reveals only).
- **Prohibited, complete list:** bouncing cards; floating icons; perpetual ambient motion;
  looping gradients; animated backgrounds; wobbling controls; dramatic parallax; logo
  theatrics; marquees; shimmer skeletons on content that exists.

**`@media (prefers-reduced-motion: reduce)`:** all transitions and animations collapse to
the instant final state (duration `0s`, delay `0s`, iteration count `1`, no transform
offset ever applied; count-up renders N immediately; gauges, bars, nodes, and sections
appear fully resolved). No information is lost: every animated element's final content is
server-rendered.

## 12. Workload icon allowlist (restored)

The v1 branded workload marks are **restored** — the "Ink and Verdigris" retirement of the
`<img>` allowlist is withdrawn. Exactly these twelve marks, keyed as
`REPORT_WORKLOAD_TO_ICON_KEY` maps them:

| Workload | Icon key |
| --- | --- |
| identity | `entra-id` |
| defender, endpoint | `defender` |
| sentinel | `microsoft-sentinel` |
| purview | `purview` |
| exchange | `exchange` |
| collaboration | `sharepoint` |
| teams | `teams` |
| power_platform | `power-platform` |
| power_bi | `power-bi` |
| intune | `intune` |
| azure | `azure` |
| general | *(no icon — text label only)* |

`onedrive` is vendored and available to the collaboration group (sharepoint leads) if T2
wants a paired mark; the allowlist for rendering is the twelve keys above.

**Render rules (binding):**

1. **Single-file renderer (inline-only — no external refs, no data-URI):** the render path
   is fixed by the verified upstream constraint at the pinned commit
   (`loryanstrant/MicrosoftCloudLogos @ fc3a6c9506dc9a6ebdfb4f5891ee486f2717257c` ships
   brand SVGs for only six of the twelve marks; an upstream tree audit confirms only
   PNG/PDF exist there for the other six). The six **SVG-vendored** marks (`entra-id`,
   `intune`, `purview`, `microsoft-sentinel`, `power-platform`, `power-bi`) render as
   **inline SVG markup** (`viewBox` as vendored), 16–18px square,
   `aria-hidden="true" focusable="false"`, always beside a visible text label. The six
   **PNG-only** marks (`defender`, `exchange`, `sharepoint`, `onedrive`, `teams`, `azure`)
   render as **text label only** in the single-file renderer — no data-URI, no hotlink,
   per the offline contract. The bundle renders all twelve marks as hashed `<img>` assets
   (rule 2).
2. **Bundle renderer (v1 pattern):** hashed `<img>` assets emitted by `report/icons.py` —
   `<img class="workload-icon" src="{{ workload_icon_urls[workload] }}" width="16/18"
   height="16/18" alt="" aria-hidden="true" />` — plus the text label.
3. **Decorative only.** Brand marks never carry meaning alone; the workload's plain-name
   label is always adjacent and is the accessible name of any control. Icons are never the
   only status or state channel.
4. **Sizes:** 16px inside finding meta rows and nav tabs; 18px in constellation group
   captions and capability summary rows.
5. **Color:** brand marks keep their official colors (never repainted by `currentColor`);
   under `forced-colors: active` they fall back to `CanvasText` via
   `forced-color-adjust: auto`; in print they keep brand colors with
   `print-color-adjust: exact`.
6. **No emoji, no invented marks.** If a workload has no mapped icon (`general`), render
   the text label alone — never a generic glyph.

## 13. Status glyph system (retained from v1, unchanged)

Six distinct inline SVG glyphs, locked geometry, `<svg viewBox="0 0 24 24">` painted with
`currentColor`, `aria-hidden="true" focusable="false"`, **always** rendered beside the
visible presentation word (never icon-only): `gap` = chevron-alert ("Action required"),
`partial` = half-fill ("Incomplete"), `ok` = check-ring ("Operational"), `not_licensed` =
slash-circle ("Not licensed"), `skipped` = dash ("Not assessed"), `error` =
triangle-alert ("Verification failed"). Status is carried by **color + glyph geometry +
word together** — never color-only, anywhere, including constellation nodes and chart
bars.

## 14. Accessibility (WCAG 2.2 AA, binding)

1. Exactly one `<main>`; exactly one `<h1>`; heading levels never skip.
2. Every interactive element has hover, active, and `:focus-visible` (2px `--accent-focus`
   outline, 2px offset). Target sizes per section 4.
3. Filter buttons expose `aria-pressed`; result count is a polite live region; filter
   groups are `role="group"` with `aria-label`; navs use `<nav aria-label>`; charts follow
   section 9's role/label/description contract; disclosures are native `<details>`.
4. Keyboard: Tab reaches every control in DOM order; Enter/Space activates; Arrow keys
   within segmented controls (optional, radio-group semantics); focus is never trapped
   except inside a temporarily open modal-like side panel (returned on close).
5. `forced-colors: active`: glyphs, node rings, and chart bars fall back to system colors
   (`CanvasText`), backgrounds collapse to `Canvas`/`CanvasText`, brand icons keep their
   shapes via `forced-color-adjust: auto`.
6. `prefers-reduced-motion: reduce`: section 11's instant-final-state contract.
7. Status is never color-only (section 13); charts always have textual equivalents
   (section 9); icons are never the only label (section 12).
8. Null/empty fields render without crash: omit the row or show "Not reported" /
   "None reported".
9. Color is not the only indicator anywhere in section A's distribution: each segment is
   labeled with glyph + word + count.

## 15. Print stylesheet

Light inversion via section 2.2 tokens, with these behaviors:

- Both dark surfaces collapse to paper; shadows suppressed everywhere; the two gradients
  are replaced by flat `--print-hero` / white fills; `--blur-nav` removed (opaque).
- All ink becomes `--print-ink`; links and identity figures use `--accent-print`; status
  words use the print state tokens with transparent label backgrounds.
- **Expanded content predictable:** all `<details>` content renders expanded in print
  (`details > *:not(summary) { display: block; }` under `@media print`), so the printed
  artifact contains the complete evidence without interaction.
- **Visualizations get textual fallbacks:** each chart's data table (sr-only on screen)
  becomes a visible, styled print table; the radial gauge is replaced by its accessible
  description line in print.
- Hero, move items, capability rows, findings, and the constellation stay whole across
  pages (`break-inside: avoid`); technical chrome (sticky nav, filter bar, pagination,
  footer) is hidden.
- `print-color-adjust: exact` everywhere so status colors and brand marks survive.

## 16. Performance (several hundred findings)

- Server-rendered DOM; JS enhances, never renders the whole list on load.
- Event delegation on the findings container and filter bar — zero per-finding listeners.
- Filtering toggles `[hidden]` on existing rows; no innerHTML rebuild of the list.
- Charts render once; filter changes update values in place (no re-layout animation).
- One-shot IntersectionObservers are unobserved after firing.
- Optional progressive enhancement: `content-visibility: auto` with
  `contain-intrinsic-size` on finding articles in section E only — never combined with
  `scrollIntoView`-dependent deep links without first removing it from the target.
- All animations GPU-composited (`transform`/`opacity`/`stroke-dashoffset` only).

## 17. Anti-patterns (prohibited, complete list)

Grids of identical cards; every metric in a rounded rectangle; dozens of pills; arbitrary
gradients; excessive glassmorphism; glowing borders; huge empty hero areas; generic SaaS
dashboards; excessive iconography; gratuitous hover effects; everything competing for
equal visual attention; bouncing cards; floating icons; perpetual ambient motion; looping
gradients; animated backgrounds; wobbling controls; dramatic parallax; logo theatrics;
monospace as the primary personality; all-uppercase headings; metric cards with no
dominant hierarchy; a sci-fi network map for the constellation; icon-only controls; any
status conveyed by color alone.

## 18. Definition of done

- Every color in the shipped CSS is a declared token from section 2; the only literal hex
  values live inside the `:root` block.
- Posture figure binds `capability_rollup.realized_percent`; searching the templates for
  `17` or `5 of 6` yields no literal constant.
- Section A contains exactly one dominant metric (hero-figure size) and a supporting stat
  strip + distribution bar — no grid of equal metric cards (grep: no
  `repeat(auto-fit, minmax(120px, 1fr))` in the hero markup).
- Constellation renders identically for identical input; nodes resolve from neutral;
  workload selection reconfigures group order; no node-link edges anywhere.
- The twelve workload marks render per section 12: inline SVG for the six SVG-vendored
  marks and text-label-only for the six PNG-only marks in the single-file renderer; hashed
  `<img>` for all twelve in the bundle; always beside a visible text label.
- Radii used are only from the section 4 stops; gradients are only the two pinned tokens;
  blur is only `--blur-nav` behind its `@supports` guard.
- Opening sequence runs once, 500–1000ms total, data-driven at every stage; reduced-motion
  renders the instant final state with zero information loss.
- One `<h1>`, one `<h2>` per section A–E, no skipped levels; all charts carry role/label/
  description + sr-only data tables; print expands disclosures and shows textual chart
  fallbacks.
- Screen is dark, print is light; both pass the section 2.3 contrast floors; status is
  never color-only.
- The templates contain no external URL except the Microsoft admin deep links, no emoji,
  no framework, no CDN, no network request.
