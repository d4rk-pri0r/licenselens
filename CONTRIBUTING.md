# Contributing to Security License Lens

Thanks for helping map paid Microsoft security capabilities to real configuration.

## Ways to contribute

1. **New checks** (highest value) — YAML under `checks/<workload>/`
2. **Catalog updates** — service plan / SKU mappings in `catalog/`
3. **Collectors** — read-only Graph / Azure data sources
4. **Docs and samples** — clearer MSP/consultant workflows
5. **Bug fixes and tests**

## Development setup

This is the same pip + venv path CI uses:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quality checks

These match CI (`.github/workflows/ci.yml`). Run them before opening a PR:

```bash
ruff check src tests
ruff format --check src tests
pytest tests/ -m "not browser" --cov=licenselens --cov-fail-under=72
licenselens scan --dry-run -o reports
```

`licenselens scan --dry-run` exits 0 or 1 when the demo catalog has gaps or
partial findings; both are expected. Any other exit code is a failure.

## Optional checks

Not required for every PR:

- Playwright report tests: `python -m playwright install --with-deps chromium`
  then `pytest tests/test_report_browser.py --browser chromium`
- Pester suites (Windows): adapter contracts in
  `powershell/LicenseLens.Collectors/tests/` and installer tests in
  `packaging/windows/tests/`
- Regenerated reference docs: `python scripts/generate_reference_docs.py`
- Docs site: `mkdocs build --strict` or `scripts/docs-check.sh` (that script
  invokes `uv run` for mkdocs and codespell)

## Adding a check

Follow [docs/adding-a-check.md](docs/adding-a-check.md).

Minimum bar for a new check PR:

- Valid YAML with stable `id`
- `required_capabilities` pointing at catalog entries
- Clear remediation and at least one reference URL
- Unit test or fixture when collector logic is included
- No write/remediation API calls

## Code style

- Python 3.12+, type hints preferred
- `ruff` for lint and format
- Do not commit secrets, tenant IDs from real customers, or unredacted reports

## Public docs and releases

This repo is a standalone product. Keep GitHub-facing material presentation-neutral:

- Do **not** mention talks, slide decks, event-tied milestones, or event names in README, CHANGELOG, docs, CLI help, release notes, or commit messages meant for GitHub.
- Describe features in product terms (quick start, default packs, demo command).
- Local planning tools (OpenSpec changes, editor agent config) stay out of the repo — see `.gitignore`.

## Pull requests

- One logical change per PR
- Link related issues
- Include dry-run output snippet when behavior changes

## Code of conduct

Be respectful. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
