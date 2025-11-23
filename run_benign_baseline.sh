#!/bin/bash
# Run benign baseline prompts through the MCP client to establish baseline in hackerFinder9000

PROMPTS_FILE="tests/baseline/benign_prompts_650.txt"
LOG_FILE="tests/baseline/run_$(date +%Y%m%d_%H%M%S).log"
COUNT=0
TOTAL=$(wc -l < "$PROMPTS_FILE")

echo "=== Benign Baseline Run ===" | tee "$LOG_FILE"
echo "Prompts: $TOTAL" | tee -a "$LOG_FILE"
echo "Started: $(date)" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Mark start position in fastapi log
START_LINES=$(wc -l < /tmp/fastapi.jsonl 2>/dev/null || echo 0)
echo "FastAPI log start position: $START_LINES" | tee -a "$LOG_FILE"

while IFS= read -r line; do
    COUNT=$((COUNT + 1))
    echo "[$COUNT/$TOTAL] Running: ${line:0:60}..." | tee -a "$LOG_FILE"

    # Run with timeout, capture just the key output
    echo "$line" | timeout 120 uv run --with-requirements requirements.txt python run_red_team.py --no-system-prompt 2>&1 | tail -5 >> "$LOG_FILE"

    echo "" >> "$LOG_FILE"

    # Small delay to avoid overwhelming
    sleep 0.5
done < "$PROMPTS_FILE"

# Mark end position
END_LINES=$(wc -l < /tmp/fastapi.jsonl 2>/dev/null || echo 0)
NEW_ENTRIES=$((END_LINES - START_LINES))

echo "" | tee -a "$LOG_FILE"
echo "=== Baseline Complete ===" | tee -a "$LOG_FILE"
echo "Finished: $(date)" | tee -a "$LOG_FILE"
echo "New log entries: $NEW_ENTRIES" | tee -a "$LOG_FILE"
echo "FastAPI log: /tmp/fastapi.jsonl" | tee -a "$LOG_FILE"
