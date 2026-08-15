#!/usr/bin/env bash
# Deterministic documentation quality gate.
#
#   strict build  -> mkdocs build --strict (internal links + anchors fail the build)
#   spelling      -> codespell over the docs source
#   external link -> lychee over the docs source (checks http(s) links + file refs)
#
# Requires `lychee` on PATH (e.g. `brew install lychee`). CI uses the
# SHA-pinned lycheeverse/lychee-action instead.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> mkdocs build --strict"
uv run mkdocs build --strict

echo "==> codespell"
uv run codespell docs mkdocs.yml

echo "==> lychee (external links + file references)"
lychee --no-progress --max-concurrency 8 docs/

echo "==> docs checks passed"
