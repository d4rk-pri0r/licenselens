#!/usr/bin/env python3
"""Three-state credential gate for live validation.

Parses the repo ``.env`` (no python-dotenv), asserts the client-secret
credentials are present, then runs ``licenselens doctor --live --auth
client_secret`` with those credentials injected into its environment.

Exit codes:
  0   CREDENTIALS_OK          — credentials present and doctor passed
  78  BLOCKED                 — a required AZURE_* variable is missing
  2   CONNECTIVITY_FAILED     — doctor ran but did not pass (auth/API error)

Never prints the client secret and never raises an unhandled traceback.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = REPO_ROOT / ".env"

REQUIRED_VARS = ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET")

EX_CONFIG = 78  # sysexits.h EX_CONFIG


def load_env(path: Path) -> dict[str, str]:
    """Parse ``KEY=value`` lines, ignoring blanks and comments."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def resolve_licenselens() -> list[str]:
    """Locate the ``licenselens`` CLI: PATH, project venv, then module fallback."""
    on_path = shutil.which("licenselens")
    if on_path:
        return [on_path]
    for candidate in (
        REPO_ROOT / ".venv" / "bin" / "licenselens",
        REPO_ROOT / ".venv" / "Scripts" / "licenselens.exe",
    ):
        if candidate.is_file():
            return [str(candidate)]
    return [sys.executable, "-m", "licenselens.cli"]


def main() -> int:
    env = load_env(ENV_PATH)

    missing = [name for name in REQUIRED_VARS if not env.get(name)]
    if missing:
        for name in missing:
            print(f"BLOCKED: missing {name} — see docs/tenant-provisioning-guide.md")
        return EX_CONFIG

    cmd = resolve_licenselens() + ["doctor", "--live", "--auth", "client_secret"]
    child_env = os.environ.copy()
    child_env.update({name: env[name] for name in REQUIRED_VARS})

    try:
        proc = subprocess.run(
            cmd,
            cwd=REPO_ROOT,
            env=child_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"CONNECTIVITY_FAILED: could not run licenselens doctor: {exc}")
        return 2

    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    last_line = lines[-1] if lines else "no output from doctor"

    if proc.returncode == 0:
        print("CREDENTIALS_OK")
        return 0

    print(f"CONNECTIVITY_FAILED: {last_line}")
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 — the gate must never traceback
        print(f"CONNECTIVITY_FAILED: {exc}")
        sys.exit(2)
