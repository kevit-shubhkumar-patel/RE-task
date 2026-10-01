import json
import re
from collections import Counter
from pathlib import Path


# Define the input log file and the JSON file used to store validated records.
LOG_FILE = Path("mysterybox.log")
OUTPUT_FILE = Path("validated_log_records.json")


# Validate the overall structure of a log record.
#
# Expected structure:
# YYYY-MM-DD HH:MM:SS | LEVEL | key=value | key=value
#
# Named groups are used so that timestamp, level, and fields can be
# accessed directly using match.group("timestamp"), etc.
#
# The key=value pattern allows keys such as user, action, ip, file, etc.
# and values can contain characters other than '|'.
#
# fullmatch() is used later so the complete line must follow this format.
LOG_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    r"\s*\|\s*"
    r"(?P<level>INFO|WARNING|ERROR)"
    r"\s*\|\s*"
    r"(?P<fields>[A-Za-z_][A-Za-z0-9_]*=[^|]+"
    r"(?:\s*\|\s*[A-Za-z_][A-Za-z0-9_]*=[^|]+)*)"
)


# Detect suspicious login records.
#
# Positive lookaheads are used here because we want to check that the
# same log line contains all three required conditions:
#
# 1. The log level is WARNING or ERROR.
# 2. A user field exists.
# 3. action=login_failed exists.
#
# (?=...) checks for a pattern without consuming characters.
SUSPICIOUS_LOGIN_PATTERN = re.compile(
    r"^(?=.*\|\s*(?:WARNING|ERROR)\s*\|)"
    r"(?=.*\|\s*user=(?P<user>[^|\s]+)\s*(?:\||$))"
    r"(?=.*\|\s*action=login_failed\s*(?:\||$)).*$"
)


# Match exactly 16 digits while preventing the match from being part
# of a longer sequence of digits.
CARD_PATTERN = re.compile(r"(?<!\d)\d{16}(?!\d)")


# Detect suspicious download filenames.
#
# (?i) makes the pattern case-insensitive, so values such as:
# PASSWORD_backup.EXE
# and
# password_backup.exe
# are treated the same.
#
# The filename must:
# - contain secret, backup, admin, or password
# - end with .zip, .exe, or .sh
SUSPICIOUS_FILENAME_PATTERN = re.compile(
    r"(?i)^(?=.*(?:secret|backup|admin|password)).+"
    r"\.(?:zip|exe|sh)$"
)


def extract_fields(field_text):
    """Convert a pipe-separated key=value string into a Python dictionary."""
    fields = {}

    # Split the fields at '|', then split each field only at the first '='.
    # Splitting only once allows values themselves to contain '='.
    for item in field_text.split("|"):
        key, value = item.strip().split("=", 1)
        fields[key.strip()] = value.strip()

    return fields


def analyze_log():
    """Read the MysteryBox log, analyze records, mask cards, and print a report."""

    # Make sure the required input file exists before attempting to read it.
    if not LOG_FILE.is_file():
        raise FileNotFoundError(f"Log file not found: {LOG_FILE}")

    # Basic record statistics.
    total_lines = 0
    valid_count = 0
    invalid_count = 0

    # Counter is useful for aggregating repeated values such as log levels
    # and failed login attempts.
    level_counts = Counter()
    failed_login_users = Counter()

    # A set automatically keeps only unique users.
    users = set()

    # Counters for the special requirements of the task.
    suspicious_login_count = 0
    suspicious_download_count = 0
    masked_card_count = 0

    # Store validated records so they can also be exported as JSON.
    records = []

    # Read the log file line by line instead of hard-coding any records.
    with LOG_FILE.open("r", encoding="utf-8") as log_file:

        for raw_line in log_file:
            total_lines += 1

            # Remove only the newline characters.
            # Keeping the rest of the line makes validation more precise.
            line = raw_line.rstrip("\r\n")

            # fullmatch() ensures that the entire line is a valid record.
            match = LOG_PATTERN.fullmatch(line)

            if not match:
                invalid_count += 1
                continue

            valid_count += 1

            # Extract the named groups from the validation regex.
            timestamp = match.group("timestamp")
            level = match.group("level")

            # Convert the complete key=value section into a dictionary.
            fields = extract_fields(match.group("fields"))

            # Count the log level.
            level_counts[level] += 1

            # Add the user to the set if a user field exists.
            if "user" in fields:
                users.add(fields["user"])

            # Build a structured representation of the log record.
            record = {
                "timestamp": timestamp,
                "level": level,
                **fields,
            }

            records.append(record)

            # ---------------------------------------------------------
            # Failed login detection
            # ---------------------------------------------------------
            #
            # Aggregation is deliberately performed with Python rather
            # than trying to count repeated users using regex.
            if fields.get("action") == "login_failed":
                if "user" in fields:
                    failed_login_users[fields["user"]] += 1

            # ---------------------------------------------------------
            # Suspicious login detection
            # ---------------------------------------------------------
            #
            # This uses the separate regex containing positive lookaheads.
            if SUSPICIOUS_LOGIN_PATTERN.fullmatch(line):
                suspicious_login_count += 1

            # ---------------------------------------------------------
            # Suspicious download detection
            # ---------------------------------------------------------
            #
            # First check that the action is a download.
            # Then apply the filename regex to the file field.
            if (
                fields.get("action") == "download"
                and SUSPICIOUS_FILENAME_PATTERN.fullmatch(
                    fields.get("file", "")
                )
            ):
                suspicious_download_count += 1

            # ---------------------------------------------------------
            # Card number masking
            # ---------------------------------------------------------
            #
            # Search every field for 16-digit card numbers.
            # subn() returns both the modified value and the number
            # of replacements performed.
            #
            # The original card number is replaced before the record
            # is written to the JSON output.
            for key, value in fields.items():
                masked_value, count = CARD_PATTERN.subn(
                    "****MASKED****",
                    value
                )

                if count:
                    fields[key] = masked_value
                    record[key] = masked_value
                    masked_card_count += count

    # Write validated and sanitized records to JSON.
    #
    # "w" is used instead of "a" so every execution produces a fresh
    # report rather than repeatedly appending duplicate records.
    with OUTPUT_FILE.open("w", encoding="utf-8") as json_file:
        json.dump(records, json_file, indent=2)

    # Find users who have failed to log in at least twice.
    #
    # This is intentionally normal Python aggregation rather than regex.
    repeat_failed_users = {
        user: count
        for user, count in failed_login_users.items()
        if count >= 2
    }

    # -------------------------------------------------------------
    # Final report
    # -------------------------------------------------------------
    print("MysteryBox Log Analysis")
    print("-----------------------")
    print(f"Total lines: {total_lines}")
    print(f"Valid lines: {valid_count}")
    print(f"Invalid lines: {invalid_count}")

    print(f"INFO records: {level_counts['INFO']}")
    print(f"WARNING records: {level_counts['WARNING']}")
    print(f"ERROR records: {level_counts['ERROR']}")

    print(f"Unique application users: {len(users)}")

    print(f"Suspicious login records: {suspicious_login_count}")

    print("Users with at least two failed logins:")

    if repeat_failed_users:
        for user, count in sorted(repeat_failed_users.items()):
            print(f"  {user}: {count}")
    else:
        print("  None")

    print(f"Suspicious downloads: {suspicious_download_count}")
    print(f"Card numbers masked: {masked_card_count}")

    print(f"Validated records saved to: {OUTPUT_FILE}")


# Run the analyzer only when this file is executed directly.
# This prevents analyze_log() from automatically running if the file
# is imported into another Python program.
if __name__ == "__main__":
    analyze_log()