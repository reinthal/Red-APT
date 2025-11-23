#!/usr/bin/env python3
"""
Randomize passwords in a credentials file.

Replaces passwords with random strings while preserving email addresses.
Useful for creating sanitized test datasets.
"""

import argparse
import random
import string
import sys
from pathlib import Path


def generate_random_password(length: int = 12, complexity: str = "medium") -> str:
    """
    Generate a random password.

    Args:
        length: Password length
        complexity: "low" (letters only), "medium" (letters+digits), "high" (all chars)

    Returns:
        Random password string
    """
    if complexity == "low":
        chars = string.ascii_letters
    elif complexity == "high":
        chars = string.ascii_letters + string.digits + string.punctuation
    else:  # medium
        chars = string.ascii_letters + string.digits

    return "".join(random.choice(chars) for _ in range(length))


def randomize_passwords(
    input_file: Path,
    output_file: Path,
    min_length: int = 8,
    max_length: int = 16,
    complexity: str = "medium",
) -> dict:
    """
    Read credentials file and randomize all passwords.

    Args:
        input_file: Path to input credentials file
        output_file: Path to output file
        min_length: Minimum password length
        max_length: Maximum password length
        complexity: Password complexity level

    Returns:
        Dict with statistics
    """
    stats = {
        "total_lines": 0,
        "processed": 0,
        "skipped": 0,
        "errors": [],
    }

    output_lines = []

    with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            stats["total_lines"] += 1
            line = line.strip()

            if not line:
                output_lines.append("")
                stats["skipped"] += 1
                continue

            if ":" not in line:
                output_lines.append(line)
                stats["skipped"] += 1
                stats["errors"].append(f"Line {line_num}: No colon separator")
                continue

            # Split on first colon only
            parts = line.split(":", 1)
            if len(parts) != 2:
                output_lines.append(line)
                stats["skipped"] += 1
                continue

            email = parts[0].strip()
            if not email:
                output_lines.append(line)
                stats["skipped"] += 1
                continue

            # Generate random password
            length = random.randint(min_length, max_length)
            new_password = generate_random_password(length, complexity)

            output_lines.append(f"{email}:{new_password}")
            stats["processed"] += 1

    # Write output
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(output_lines))
        if output_lines:
            f.write("\n")

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Randomize passwords in a credentials file"
    )
    parser.add_argument(
        "input_file",
        type=Path,
        help="Input credentials file (format: email:password)",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Output file (default: overwrites input file)",
    )
    parser.add_argument(
        "--min-length",
        type=int,
        default=8,
        help="Minimum password length (default: 8)",
    )
    parser.add_argument(
        "--max-length",
        type=int,
        default=16,
        help="Maximum password length (default: 16)",
    )
    parser.add_argument(
        "--complexity",
        choices=["low", "medium", "high"],
        default="medium",
        help="Password complexity: low (letters), medium (letters+digits), high (all chars)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducibility",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without writing",
    )

    args = parser.parse_args()

    if not args.input_file.exists():
        print(f"Error: Input file not found: {args.input_file}", file=sys.stderr)
        sys.exit(1)

    if args.seed is not None:
        random.seed(args.seed)

    output_file = args.output or args.input_file

    if args.dry_run:
        print(f"Dry run - would process: {args.input_file}")
        print(f"Output would go to: {output_file}")
        print(f"Password length: {args.min_length}-{args.max_length}")
        print(f"Complexity: {args.complexity}")

        # Show sample
        with open(args.input_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()[:5]

        print("\nSample transformations:")
        for line in lines:
            line = line.strip()
            if ":" in line:
                email = line.split(":", 1)[0]
                new_pass = generate_random_password(
                    random.randint(args.min_length, args.max_length),
                    args.complexity
                )
                print(f"  {line[:50]}... -> {email}:{new_pass}")
        return

    print(f"Processing: {args.input_file}")
    stats = randomize_passwords(
        args.input_file,
        output_file,
        args.min_length,
        args.max_length,
        args.complexity,
    )

    print(f"Output: {output_file}")
    print(f"Total lines: {stats['total_lines']}")
    print(f"Processed: {stats['processed']}")
    print(f"Skipped: {stats['skipped']}")

    if stats["errors"]:
        print(f"Errors ({len(stats['errors'])}):")
        for err in stats["errors"][:10]:
            print(f"  {err}")
        if len(stats["errors"]) > 10:
            print(f"  ... and {len(stats['errors']) - 10} more")


if __name__ == "__main__":
    main()
