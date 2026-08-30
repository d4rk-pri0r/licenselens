# Run it in your hotel room tonight

Four commands. Your laptop. Your tenant. The report stays on disk.

![QR code: the hotel-room quick start](assets/hotel-room-qr.svg)

You need Python 3.12+ and [pipx](https://pipx.pypa.io/). If those are missing,
see [Getting started](getting-started.md).

## 1. Install

```bash
pipx install licenselens
```

## 2. Offline sample report

```bash
licenselens demo --open
```

Demo data. No network. Not your tenant.

## 3. Scan your own tenant (read-only)

```bash
licenselens quickstart
```

Browser device-code sign-in. Read-only. No LicenseLens account.

## 4. Fix one thing, then diff

```bash
licenselens diff reports/scan-old/security-license-lens-report.json reports/scan-new/security-license-lens-report.json
```

`quickstart` and `scan` write timestamped folders, so both runs stay on disk.
Point `diff` at the two JSON files.

## What you'll see

Owned licenses, the controls those licenses unlock, gaps with evidence, and a
link to the admin page for each fix. One HTML file on your computer.
