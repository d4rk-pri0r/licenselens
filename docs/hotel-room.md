# Run it in your hotel room tonight

Four commands. Your laptop. Your tenant. Nothing leaves the machine.

![QR code: the hotel-room quick start](assets/hotel-room-qr.svg)

Python 3.12+ and [pipx](https://pipx.pypa.io/) are the only prerequisites. See [Getting started](getting-started.md) if you need to install them.

## 1. Install

```bash
pipx install licenselens
```

## 2. See a sample report (offline)

```bash
licenselens demo --open
```

Curated demo data. Works with no network. Not a real tenant.

## 3. Scan your own tenant (read-only)

```bash
licenselens quickstart
```

Device code sign-in in the browser. Read-only. Credentials never leave your machine. No account, no telemetry. The report stays on disk.

## 4. Fix one thing, then watch the gap close

```bash
licenselens diff reports/scan-old/security-license-lens-report.json reports/scan-new/security-license-lens-report.json
```

`quickstart` and `scan` write timestamped subdirectories so both runs are preserved. Point `diff` at the two JSON files.

## What you'll see

Owned licenses mapped to the security capabilities they unlock, gaps with inspectable evidence, and a direct link into the admin page for each fix. The report is a single HTML file on your computer.

No account. No telemetry. The report stays on your machine.
