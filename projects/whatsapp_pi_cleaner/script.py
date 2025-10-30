import re
import hashlib
import os
import sys
from typing import List

# ⚙️ Configurable salt (can also be set via environment variable)
SALT = os.getenv("CHAT_HASH_SALT", "my_secret_salt_2025")

# Broad regex to find phone-like sequences (includes +, spaces, dashes, contiguous digits)
MSISDN_BROAD_PATTERN = re.compile(r"\+?\d[\d\s\-]{6,}\d")

# Pattern for our pseudonym tokens produced by the script (8 hex chars, case-insensitive)
PSEUDONYM_PATTERN = re.compile(r"\bUser_[0-9a-fA-F]{8}\b")

def hash_msisdn(msisdn: str, salt: str = SALT) -> str:
    """
    Deterministically hash an MSISDN with a salt to a short anonymized ID.
    """
    normalized = re.sub(r"[^\d]", "", msisdn)
    salted_value = normalized + salt
    hash = hashlib.md5(salted_value.encode()).hexdigest()
    # PRevent false MSISDN triggers by inserting a letter
    hashed = hash[:4]+"m"+hash[4:8]
    return f"User_{hashed}"

def anonymize_chat_line(line: str) -> str:
    """
    Replace all MSISDNs in a chat line with salted hashed pseudonyms.
    """
    def replace_msisdn(match):
        msisdn = match.group(0)
        return hash_msisdn(msisdn)
    
    return MSISDN_BROAD_PATTERN.sub(replace_msisdn, line)

def is_real_msisdn_candidate(text: str) -> bool:
    """
    Heuristic to decide whether a matched text is a real MSISDN we should flag.
    - Count digits after stripping non-digits: real phone numbers usually have 7-15 digits.
    - Exclude our own pseudonym tokens.
    """
    # If the text matches our pseudonym format, it's safe.
    if PSEUDONYM_PATTERN.search(text):
        return False

    digits = re.sub(r"\D", "", text)
    digit_count = len(digits)
    # Typical phone numbers: roughly 7 - 15 digits depending on formatting/international codes
    return 7 <= digit_count <= 15

def verify_no_msisdn_exposure(lines: List[str], raise_on_leak: bool = True):
    """
    Check for remaining MSISDN-like patterns in anonymized output.
    - Uses a broad pattern but filters out matches that look like our pseudonyms.
    - If any suspicious match remains, either raise ValueError or return a list of findings.
    """
    findings = []
    for i, line in enumerate(lines, start=1):
        for match in MSISDN_BROAD_PATTERN.finditer(line):
            matched_text = match.group(0)
            if is_real_msisdn_candidate(matched_text):
                # Provide a small context window for easier debugging
                context_start = max(0, match.start() - 30)
                context_end = min(len(line), match.end() + 30)
                context = line[context_start:context_end].strip()
                findings.append((i, matched_text, context))
    if findings:
        msg_lines = []
        for lineno, matched_text, context in findings:
            msg_lines.append(
                f"Possible MSISDN leak on line {lineno}: '{matched_text}' — context: ...{context}..."
            )
        full_msg = "\n".join(msg_lines)
        if raise_on_leak:
            raise ValueError(full_msg)
        return findings
    return []

def main(input_file="data.txt", output_file="output.txt"):
    """
    Read the chat log, anonymize it, and write the cleaned output.
    """
    if not os.path.exists(input_file):
        print(f"❌ Input file '{input_file}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(input_file, "r", encoding="utf-8") as infile:
        lines = infile.readlines()

    anonymized_lines = [anonymize_chat_line(line) for line in lines]

    # Final safety check — no MSISDNs should remain. This now ignores our pseudonyms.
    try:
        verify_no_msisdn_exposure(anonymized_lines, raise_on_leak=True)
    except ValueError as e:
        # Fail early and print helpful diagnostic message
        print("❗ Verification failed — possible MSISDN leak(s) detected:", file=sys.stderr)
        print(str(e), file=sys.stderr)
        sys.exit(2)

    cleaned_lines = [line.replace("Bjorn", "User_1") for line in anonymized_lines if line.strip()]

    with open(output_file, "w", encoding="utf-8") as outfile:
        outfile.writelines(cleaned_lines)

    print(f"✅ Anonymized chat written to '{output_file}'")

if __name__ == "__main__":
    main()
