#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# PIMiner - Full IPIArena test on deepseek-v4-flash
# Expected split: 20 train + 21 test
# Full test config: n=21, offset=20
# ============================================================

cd ~/autodl-tmp/PIMiner

SRC="eval_results/pim_test/deepseek_small"
DST="eval_results/pim_test/deepseek_full"

echo "[1/6] Preparing output directory: $DST"
mkdir -p "$DST"

echo "[2/6] Locating source test plan..."
PLAN=$(grep -rl '"test_datasets"' "$SRC" --include='*.json' 2>/dev/null | head -1 || true)

if [ -z "${PLAN:-}" ]; then
    echo "[ERROR] Could not find a JSON file containing \"test_datasets\" under:"
    echo "        $SRC"
    echo
    echo "Try locating the plan manually with:"
    echo "  grep -Rnl '\"test_datasets\"' eval_results/pim_test"
    exit 1
fi

echo "[check] Source plan: $PLAN"

NEW_PLAN="$DST/$(basename "$PLAN")"

echo "[3/6] Copying plan to: $NEW_PLAN"
cp "$PLAN" "$NEW_PLAN"

echo "[4/6] Updating IPIArena config to n=21, offset=20..."
python - "$NEW_PLAN" <<'PY'
import json
import sys

path = sys.argv[1]

with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

found = False

for item in data.get("test_datasets", []):
    if (
        item.get("dataset") == "ipi_arena"
        and item.get("target_model") == "deepseek-v4-flash"
    ):
        item["n"] = 21

        # Preserve/force the test split start at sample 20.
        if "offset" in item:
            item["offset"] = 20
        if "sample_offset" in item:
            item["sample_offset"] = 20
        if "sample-offset" in item:
            item["sample-offset"] = 20

        # If no recognized offset field exists, add the common one.
        if not any(k in item for k in ("offset", "sample_offset", "sample-offset")):
            item["offset"] = 20

        found = True

if not found:
    raise RuntimeError(
        "No test_datasets entry found for "
        "dataset=ipi_arena and target_model=deepseek-v4-flash"
    )

with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=2)

print(f"[OK] Updated plan: {path}")
PY

echo
echo "========== UPDATED TEST PLAN =========="
python -m json.tool "$NEW_PLAN"
echo "======================================="
echo

echo "[5/6] Starting full IPIArena test..."
echo "      Expected startup line should contain: n=21 off=20"
echo

PIM_AGENT_MODEL=claude-haiku-4-5 \
PIM_EFFORT=high \
PIM_WAVE_SIZE=1 \
PIM_DATASET_CONC=1 \
PIM_ATTACK_MODE=wave \
PIMINER_IPI_JUDGE_MODEL=deepseek-v4-flash \
./piminer_test_parallel.sh "$DST"

echo
echo "[6/6] Test finished."
echo

RESULT="$DST/test_results.json"

if [ -f "$RESULT" ]; then
    echo "========== FINAL RESULTS =========="
    python -m json.tool "$RESULT"
    echo "==================================="
else
    echo "[WARN] Expected result file not found:"
    echo "       $RESULT"
fi

echo
echo "Done."
