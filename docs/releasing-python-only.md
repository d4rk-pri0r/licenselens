# Releasing Python wheel and sdist (human-gated)

This is the **human** path to publish LicenseLens 0.4.0 as wheel + sdist only.

It is **not** the signed Windows channel. That remains `.github/workflows/publish.yml` (Stage 2b) and stays locked.

Agents never tag, never dispatch this workflow, and never publish to PyPI.

## Preconditions

1. `.github/workflows/publish-python.yml` is on `main`.
2. You (PyPI owner, 2FA) add a **trusted publisher** for:
   - repository `d4rk-pri0r/licenselens`
   - workflow `.github/workflows/publish-python.yml`
   - environment `pypi` (or `production` if you rename the workflow environment to match your publisher entry)
3. Confirm `pyproject.toml` version, `src/licenselens/__init__.py`, and `CHANGELOG.md` agree (`python scripts/release/verify_version.py`).

## What the workflow guarantees

- Manual dispatch only (no push, no tags, no pull request).
- Version consistency against the tree.
- Wheel + sdist built once, then downloaded for publish (no rebuild).
- SHA-256 digests printed for the artifacts.
- PyPI trusted publishing via OIDC.
- **No Windows artifact. No signing. No invented installer.**

## Dispatch (human)

1. GitHub → Actions → **Release Python (wheel + sdist)** → Run workflow on `main`.
2. Wait for success.
3. Verify https://pypi.org/project/licenselens/ shows 0.4.0.
4. Flip the publication-status wording:
   - `docs/releases.md` and `CHANGELOG.md`: pending → published
   - `README.md` / `docs/package-readme.md`: drop the "PyPI latest is 0.3.0" parenthetical
   - `tests/test_release_status_docs.py` will require that flip (live PyPI lock)
5. Push the wording commit so Pages redeploys.

## What this does not do

- No signed Windows zip.
- No macOS package.
- No extra package-manager listings until those channels actually exist.
- No agent-runnable publish. Every step above is a person.

## Rollback

PyPI yank is a human decision. This runbook does not automate it.
