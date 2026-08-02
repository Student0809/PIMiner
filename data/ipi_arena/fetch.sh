#!/usr/bin/env bash
# The IPI-Arena upstream benchmark (GraySwanAI/ipi_arena_os, MIT) is now VENDORED
# under ./repo, so you normally do NOT need to run this script. It is kept only to
# (re-)fetch or update the upstream copy. Idempotent — no-ops if ./repo is present.
#
# After ./repo exists you have:
#   data/ipi_arena/repo/data/tool/*.json
#   data/ipi_arena/repo/data/coding/*.json
# Install it so `ipi_arena_bench` is importable:
#   pip install -e data/ipi_arena/repo
# The iterative-attack-shaped JSONL (ipi_arena_rows.jsonl) is committed; rebuild
# it only if you change the pool: `python data/ipi_arena/build_rows.py`.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="$HERE/repo"
URL="https://github.com/GraySwanAI/ipi_arena_os.git"

if [ -f "$DEST/pyproject.toml" ]; then
    echo "[fetch] $DEST already present (vendored) — nothing to do."
    if [ -d "$DEST/.git" ]; then
        echo "[fetch] git checkout detected; pulling latest"
        git -C "$DEST" pull --ff-only --quiet
    fi
else
    echo "[fetch] cloning $URL into $DEST"
    git clone --depth 1 --quiet "$URL" "$DEST"
fi

echo "[fetch] tool entries:    $(ls "$DEST/data/tool"/*.json 2>/dev/null | wc -l)"
echo "[fetch] coding entries:  $(ls "$DEST/data/coding"/*.json 2>/dev/null | wc -l)"
echo "[fetch] browser entries: $(ls "$DEST/data/browser"/*.json 2>/dev/null | wc -l) (skipped by iterative attack integration)"
