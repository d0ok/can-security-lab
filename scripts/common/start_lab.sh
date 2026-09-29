#!/bin/bash
# Starts baseline_traffic.py and a candump capture together, verifies
# both are actually producing traffic before declaring the lab "ready".
# Usage: ./start_lab.sh <log_output_path>

set -e
LOGFILE="${1:-logs/capture_$(date +%s).log}"
cd "$(dirname "$0")/../.."   # repo root, regardless of where this is called from

echo "[start_lab] killing any stray processes..."
pkill -f baseline_traffic.py 2>/dev/null || true
pkill -f candump 2>/dev/null || true
sleep 1

echo "[start_lab] starting baseline_traffic.py..."
source venv/bin/activate
python3 scripts/common/baseline_traffic.py &
BASELINE_PID=$!
sleep 2

echo "[start_lab] verifying baseline is producing traffic..."
FRAME_COUNT=$(timeout 2 candump vcan0 | wc -l)
if [ "$FRAME_COUNT" -lt 5 ]; then
    echo "[start_lab] FAILED: only saw $FRAME_COUNT frames in 2s — baseline not running correctly."
    kill "$BASELINE_PID" 2>/dev/null || true
    exit 1
fi
echo "[start_lab] OK: baseline confirmed alive ($FRAME_COUNT frames/2s)"

echo "[start_lab] starting capture -> $LOGFILE"
candump -L vcan0 > "$LOGFILE" &
CANDUMP_PID=$!
sleep 1

echo ""
echo "=========================================="
echo " LAB READY"
echo "   baseline_traffic.py  PID=$BASELINE_PID"
echo "   candump               PID=$CANDUMP_PID  -> $LOGFILE"
echo ""
echo " Run your attack script now in another terminal."
echo " When done, stop this script (Ctrl+C) to clean up."
echo "=========================================="

trap "echo '[start_lab] stopping...'; kill $BASELINE_PID $CANDUMP_PID 2>/dev/null; exit 0" INT
wait
