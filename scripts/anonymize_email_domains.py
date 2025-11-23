#!/usr/bin/env python3
"""
Anonymize email domains in credentials file.
Replaces domains with random characters while preserving length and structure.

Example: user@gmail.com -> user@kqwef.jrm (gmail=5 chars, com=3 chars)
"""

import random
import string
import sys
from pathlib import Path


def anonymize_domain(domain: str) -> str:
    """
    Replace domain with random lowercase letters matching character counts.

    Example: 'gmail.com' -> 'kqwef.jrm'
             'code-consultants.co.uk' -> 'qwertasdfzxcvbnm.op.lk'
    """
    parts = domain.split('.')
    anonymized_parts = [
        ''.join(random.choices(string.ascii_lowercase, k=len(part)))
        for part in parts
    ]
    return '.'.join(anonymized_parts)


def process_line(line: str) -> str:
    """Process a single line, anonymizing the email domain if present."""
    line = line.rstrip('\n\r')
    if not line or ':' not in line:
        return line

    # Split on first colon to separate email from password
    parts = line.split(':', 1)
    if len(parts) != 2:
        return line

    email, password = parts

    # Check if it looks like an email
    if '@' not in email:
        return line

    # Split email into local part and domain
    email_parts = email.rsplit('@', 1)
    if len(email_parts) != 2:
        return line

    local_part, domain = email_parts

    # Anonymize the domain
    anonymized_domain = anonymize_domain(domain)

    return f"{local_part}@{anonymized_domain}:{password}"


def main():
    input_file = Path(__file__).parent.parent / 'creds.txt'
    output_file = Path(__file__).parent.parent / 'creds_anonymized.txt'

    # Allow override via command line
    if len(sys.argv) >= 2:
        input_file = Path(sys.argv[1])
    if len(sys.argv) >= 3:
        output_file = Path(sys.argv[2])

    if not input_file.exists():
        print(f"Error: Input file not found: {input_file}")
        sys.exit(1)

    print(f"Processing: {input_file}")
    print(f"Output: {output_file}")

    line_count = 0
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as infile, \
         open(output_file, 'w', encoding='utf-8') as outfile:
        for line in infile:
            processed = process_line(line)
            outfile.write(processed + '\n')
            line_count += 1

            if line_count % 100000 == 0:
                print(f"Processed {line_count:,} lines...")

    print(f"Done! Processed {line_count:,} lines total.")
    print(f"Output written to: {output_file}")


if __name__ == '__main__':
    main()
