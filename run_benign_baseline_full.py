#!/usr/bin/env python3
"""
Run full benign baseline with proper headers for fingerprinting.
Reads from CSV and passes task_id, task_category, and baseline_type headers.
"""

import asyncio
import csv
import os
import sys
import subprocess
from datetime import datetime
from pathlib import Path

CSV_FILE = "/home/ubuntu/hackerFinder9000/benign_baseline_650.csv"
LOG_DIR = Path(__file__).parent / "tests" / "baseline"
LOG_DIR.mkdir(parents=True, exist_ok=True)

def count_log_lines():
    """Count lines in fastapi log."""
    try:
        with open("/tmp/fastapi.jsonl") as f:
            return sum(1 for _ in f)
    except:
        return 0

def run_prompt(task_id, category, prompt, timeout=90):
    """Run a single prompt with proper headers."""
    cmd = [
        "uv", "run", "--with-requirements", "requirements.txt",
        "python", "run_red_team.py",
        "--no-system-prompt",
        "--baseline-type", "benign",
        "--task-id", str(task_id),
        "--task-category", category,
        "--max-iterations", "10",
    ]

    try:
        result = subprocess.run(
            cmd,
            input=prompt + "\n",
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(Path(__file__).parent),
        )
        return result.returncode == 0, result.stdout[-500:] if result.stdout else ""
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    except Exception as e:
        return False, str(e)

def main():
    start_time = datetime.now()
    log_file = LOG_DIR / f"full_baseline_{start_time.strftime('%Y%m%d_%H%M%S')}.log"

    # Read CSV
    tasks = []
    with open(CSV_FILE) as f:
        reader = csv.DictReader(f)
        for row in reader:
            tasks.append({
                'task_id': row['task_id'],
                'category': row['category'],
                'prompt': row['input_prompt'],
            })

    total = min(500, len(tasks))  # Run first 500
    initial_lines = count_log_lines()

    print(f"=== BENIGN BASELINE FULL RUN ===")
    print(f"Started: {start_time}")
    print(f"Tasks: {total}")
    print(f"Initial log lines: {initial_lines}")
    print(f"Log file: {log_file}")
    print()

    with open(log_file, 'w') as log:
        log.write(f"=== BENIGN BASELINE FULL RUN ===\n")
        log.write(f"Started: {start_time}\n")
        log.write(f"Tasks: {total}\n")
        log.write(f"Initial log lines: {initial_lines}\n\n")

        successes = 0
        for i, task in enumerate(tasks[:total], 1):
            task_id = task['task_id']
            category = task['category']
            prompt = task['prompt']

            print(f"[{i}/{total}] Task {task_id} [{category[:15]:15s}] {prompt[:40]}...")
            log.write(f"[{i}/{total}] Task {task_id} [{category}]\n")
            log.write(f"  Prompt: {prompt[:100]}...\n")

            success, output = run_prompt(task_id, category, prompt)

            if success:
                successes += 1
                log.write(f"  Status: OK\n")
            else:
                log.write(f"  Status: FAILED - {output[:100]}\n")

            log.write("\n")
            log.flush()

            # Progress checkpoint every 50
            if i % 50 == 0:
                current_lines = count_log_lines()
                new_lines = current_lines - initial_lines
                print(f"  === Checkpoint {i}/{total}: {new_lines} new log entries, {successes} successes ===")
                log.write(f"=== Checkpoint {i}/{total}: {new_lines} new log entries ===\n\n")

        end_time = datetime.now()
        final_lines = count_log_lines()
        duration = end_time - start_time

        summary = f"""
=== COMPLETE ===
Finished: {end_time}
Duration: {duration}
Tasks run: {total}
Successes: {successes}
Final log lines: {final_lines}
New entries: {final_lines - initial_lines}
"""
        print(summary)
        log.write(summary)

if __name__ == "__main__":
    main()
