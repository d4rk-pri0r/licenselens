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

Write the two scans to **different directories**. A second `scan`/`demo`/`quickstart`
into a directory that already holds report files is diverted to a timestamped
subdirectory so the first run is not overwritten — but do not rely on that as
the documented path. Name the folders yourself:

```bash
licenselens demo -o reports/before
licenselens demo --after -o reports/after
licenselens diff reports/before/security-license-lens-report.json reports/after/security-license-lens-report.json
```

`--after` is a simulated remediated tenant (demo data only). For a live tenant,
run `quickstart` twice into two directories after you make a real change.

## What you'll see

Owned licenses, the controls those licenses unlock, gaps with evidence, and a
link to the admin page for each fix. One HTML file on your computer.
