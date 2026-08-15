## Summary

<!-- What changed and why -->

## Type

- [ ] New check
- [ ] Catalog update
- [ ] Collector / engine
- [ ] Docs
- [ ] Fix

## Checklist

- [ ] `ruff check src tests` passes
- [ ] `ruff format --check src tests` passes
- [ ] `pytest tests/ -m "not browser"` passes
- [ ] `licenselens scan --dry-run` still works
- [ ] No secrets or customer tenant data included
