# Contributing to LicenseLens

Thanks for helping map paid Microsoft security capabilities to real configuration.

## Ways to contribute

1. **New checks** (highest value) — YAML under `checks/<workload>/`
2. **Catalog updates** — service plan / SKU mappings in `catalog/`
3. **Collectors** — read-only Graph / Azure data sources
4. **Docs and samples** — clearer MSP/consultant workflows
5. **Bug fixes and tests**

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
ruff check src tests
pytest
licenselens scan -o reports
```

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
- `ruff` for lint
- Do not commit secrets, tenant IDs from real customers, or unredacted reports

## Pull requests

- One logical change per PR
- Link related issues
- Include dry-run output snippet when behavior changes

## Code of conduct

Be respectful. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
