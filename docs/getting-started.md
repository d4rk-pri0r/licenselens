# Getting started

## Install (dev)

```bash
git clone https://github.com/d4rk-pri0r/licenselens.git
cd licenselens
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Dry-run scan

```bash
licenselens version
licenselens checks
licenselens scan -o reports
```

Open `reports/security-license-lens-report.html` in a browser.

## Live scan (entitlements)

1. Register an app and grant admin consent — [app-registration.md](app-registration.md)
2. Preflight:

```bash
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
licenselens doctor --live --auth client_secret
```

3. Scan:

```bash
licenselens scan --live --auth client_secret -o reports
```

Interactive alternative:

```bash
licenselens scan --live --auth device \
  --tenant-id "$AZURE_TENANT_ID" \
  --client-id "$AZURE_CLIENT_ID" \
  -o reports
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (no gap/partial findings) |
| 1 | Completed with gap or partial findings |
| 2 | Auth/config/Graph error |
