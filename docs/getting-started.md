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

Open `reports/licenselens-report.html` in a browser.

## Live scan

Not available in the alpha scaffold. See the roadmap in the root README.
