#!/usr/bin/env python3
"""
Run benign baseline with 16 parallel processes and high variability.
Each worker gets different temperature, max_iterations, and shuffled task order.
"""

import asyncio
import csv
import os
import random
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
import hashlib

CSV_FILE = "/home/ubuntu/hackerFinder9000/benign_baseline_650.csv"
LOG_DIR = Path(__file__).parent / "tests" / "baseline"
LOG_DIR.mkdir(parents=True, exist_ok=True)

NUM_WORKERS = 16
TASKS_PER_WORKER = 32  # Each worker runs 32 tasks = 512 total

# Variability parameters
TEMPERATURES = [0.3, 0.5, 0.7, 0.9, 1.0]
MAX_ITERATIONS = [5, 8, 10, 12, 15]
SERVERS_SUBSETS = [
    ["network", "web", "osint"],
    ["subdomain", "web", "cloud"],
    ["network", "subdomain", "vuln"],
    ["web", "osint", "crypto"],
    ["network", "cloud", "report"],
    ["all"],  # Full server set
]

def get_worker_config(worker_id: int) -> dict:
    """Generate unique configuration for each worker."""
    random.seed(worker_id * 42)
    return {
        "temperature": random.choice(TEMPERATURES),
        "max_iterations": random.choice(MAX_ITERATIONS),
        "worker_id": worker_id,
        "session_salt": hashlib.md5(f"worker-{worker_id}-{datetime.now().isoformat()}".encode()).hexdigest()[:8],
    }

def run_single_task(args):
    """Run a single task with given configuration."""
    task_id, category, prompt, worker_id, config = args

    cmd = [
        "uv", "run", "--with-requirements", "requirements.txt",
        "python", "run_red_team.py",
        "--no-system-prompt",
        "--baseline-type", "benign",
        "--task-id", str(task_id),
        "--task-category", category,
        "--max-iterations", str(config["max_iterations"]),
        "--temperature", str(config["temperature"]),
    ]

    try:
        result = subprocess.run(
            cmd,
            input=prompt + "\n",
            capture_output=True,
            text=True,
            timeout=60,  # Shorter timeout for parallel
            cwd=str(Path(__file__).parent),
        )
        return (task_id, True, config)
    except subprocess.TimeoutExpired:
        return (task_id, False, "TIMEOUT")
    except Exception as e:
        return (task_id, False, str(e))

def worker_process(worker_id: int, tasks: list) -> dict:
    """Worker that processes a batch of tasks."""
    config = get_worker_config(worker_id)
    results = {"worker_id": worker_id, "config": config, "successes": 0, "failures": 0, "tasks": []}

    # Shuffle tasks for this worker for variability
    random.seed(worker_id)
    shuffled_tasks = tasks.copy()
    random.shuffle(shuffled_tasks)

    for task in shuffled_tasks[:TASKS_PER_WORKER]:
        task_id, category, prompt = task["task_id"], task["category"], task["prompt"]

        task_result = run_single_task((task_id, category, prompt, worker_id, config))

        if task_result[1]:
            results["successes"] += 1
        else:
            results["failures"] += 1
        results["tasks"].append(task_result)

    return results

def main():
    start_time = datetime.now()
    log_file = LOG_DIR / f"parallel_baseline_{start_time.strftime('%Y%m%d_%H%M%S')}.log"

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

    # Count initial log lines
    try:
        with open("/tmp/fastapi.jsonl") as f:
            initial_lines = sum(1 for _ in f)
    except:
        initial_lines = 0

    print(f"=== PARALLEL BENIGN BASELINE ({NUM_WORKERS} workers) ===")
    print(f"Started: {start_time}")
    print(f"Tasks per worker: {TASKS_PER_WORKER}")
    print(f"Total tasks: {NUM_WORKERS * TASKS_PER_WORKER}")
    print(f"Initial log lines: {initial_lines}")
    print(f"Temperature range: {TEMPERATURES}")
    print(f"Max iterations range: {MAX_ITERATIONS}")
    print()

    # Distribute tasks to workers with overlap for variability
    worker_tasks = []
    for i in range(NUM_WORKERS):
        # Each worker gets a different slice of tasks with some overlap
        start_idx = (i * (len(tasks) // NUM_WORKERS)) % len(tasks)
        worker_slice = tasks[start_idx:] + tasks[:start_idx]  # Rotate
        worker_tasks.append((i, worker_slice))

    # Run workers in parallel
    all_results = []
    with ProcessPoolExecutor(max_workers=NUM_WORKERS) as executor:
        futures = {
            executor.submit(worker_process, worker_id, task_list): worker_id
            for worker_id, task_list in worker_tasks
        }

        for future in as_completed(futures):
            worker_id = futures[future]
            try:
                result = future.result()
                all_results.append(result)
                print(f"Worker {worker_id} done: {result['successes']} successes, {result['failures']} failures (temp={result['config']['temperature']}, iter={result['config']['max_iterations']})")
            except Exception as e:
                print(f"Worker {worker_id} failed: {e}")

    # Count final log lines
    try:
        with open("/tmp/fastapi.jsonl") as f:
            final_lines = sum(1 for _ in f)
    except:
        final_lines = 0

    end_time = datetime.now()
    duration = end_time - start_time

    total_successes = sum(r["successes"] for r in all_results)
    total_failures = sum(r["failures"] for r in all_results)

    # Write summary log
    with open(log_file, 'w') as f:
        f.write(f"=== PARALLEL BASELINE SUMMARY ===\n")
        f.write(f"Started: {start_time}\n")
        f.write(f"Finished: {end_time}\n")
        f.write(f"Duration: {duration}\n")
        f.write(f"Workers: {NUM_WORKERS}\n")
        f.write(f"Total tasks: {total_successes + total_failures}\n")
        f.write(f"Successes: {total_successes}\n")
        f.write(f"Failures: {total_failures}\n")
        f.write(f"New log entries: {final_lines - initial_lines}\n")
        f.write(f"\nWorker configurations:\n")
        for r in all_results:
            f.write(f"  Worker {r['worker_id']}: temp={r['config']['temperature']}, iter={r['config']['max_iterations']}, success={r['successes']}\n")

    print(f"\n=== COMPLETE ===")
    print(f"Duration: {duration}")
    print(f"Total successes: {total_successes}")
    print(f"Total failures: {total_failures}")
    print(f"New log entries: {final_lines - initial_lines}")
    print(f"Log file: {log_file}")

if __name__ == "__main__":
    main()
