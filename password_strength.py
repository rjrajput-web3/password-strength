#!/usr/bin/env python3
"""Estimate a password's strength from the terminal.

Entropy-based scoring with concrete improvement tips. Everything runs
locally -- no network calls, no logging, nothing stored anywhere. Reads
from a secure prompt (getpass) or stdin, so the password never appears in
shell history or process lists.

Usage:
    python password_strength.py            # secure prompt, no echo
    echo "s3cret!" | python password_strength.py

Exit codes: 0 = password scored, 2 = no input given.
"""

import getpass
import math
import sys

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "12345678", "12345",
    "1234567", "1234567890", "letmein", "welcome", "admin", "iloveyou",
    "monkey", "dragon", "football", "baseball", "master", "sunshine",
    "princess", "shadow", "superman", "michael", "abc123", "111111",
    "000000", "123123", "passw0rd", "p@ssw0rd", "qwerty123", "1q2w3e4r",
    "qazwsx", "trustno1", "starwars", "whatever", "freedom",
}

KEYBOARD_SEQUENCES = (
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "0987654321",
)


def char_pool_size(pw):
    """Size of the character pool the password draws from."""
    pool = 0
    if any(c.islower() for c in pw):
        pool += 26
    if any(c.isupper() for c in pw):
        pool += 26
    if any(c.isdigit() for c in pw):
        pool += 10
    if any(not c.isalnum() for c in pw):
        pool += 33  # printable ASCII symbols, roughly
    if any(ord(c) > 127 for c in pw):
        pool += 1000  # non-ASCII bonus (approximate)
    return pool


def analyze_patterns(pw):
    """Return (weaknesses, discount) for predictable patterns.

    weaknesses: human-readable list. discount: number of password
    characters that carry ~1 char of real entropy instead of a full
    character's worth (a run like 'aaaa' or a sequence like '123' is
    predictable, so it contributes far less entropy than it looks).
    """
    weaknesses = []
    discount = 0
    lowered = pw.lower()

    if lowered in COMMON_PASSWORDS:
        weaknesses.append("it is one of the most-used passwords on the internet")
    else:
        for common in COMMON_PASSWORDS:
            if len(common) >= 6 and common in lowered:
                weaknesses.append("it contains the common password '%s'" % common)
                break

    # repeated runs: 'aaaa' carries ~1 char of real entropy, not 4
    prev, run = None, 1
    runs = []
    for ch in pw:
        if ch == prev:
            run += 1
        else:
            if run >= 3:
                runs.append((prev, run))
            prev, run = ch, 1
    if run >= 3:
        runs.append((prev, run))
    if runs:
        discount += sum(n - 1 for _, n in runs)
        desc = ", ".join("'%s' x%d" % (c, n) for c, n in runs)
        weaknesses.append("repeated characters (%s)" % desc)

    # keyboard sequences of 3+: each predictable frag ~1 char of entropy
    seq_hits = 0
    seen_frags = []
    for seq in KEYBOARD_SEQUENCES:
        for i in range(len(seq) - 2):
            frag = seq[i:i + 3]
            if frag in lowered or frag[::-1] in lowered:
                seq_hits += 1
                seen_frags.append(frag)
                break
    if seq_hits:
        discount += 2 * seq_hits
        weaknesses.append("predictable sequence ('%s...')" % seen_frags[0])

    return weaknesses, discount


def human_duration(seconds):
    """Render a number of seconds as a friendly duration string."""
    if seconds < 1:
        return "less than a second"
    if seconds < 60:
        return "~%d seconds" % seconds
    minutes = seconds / 60
    if minutes < 60:
        return "~%d minutes" % minutes
    hours = minutes / 60
    if hours < 48:
        return "~%.1f hours" % hours
    days = hours / 24
    if days < 730:
        return "~%.1f days" % days
    years = days / 365.25
    if years < 1_000_000:
        return "~%s years" % _fmt_int(years)
    return "effectively uncrackable"


def _fmt_int(value):
    return "{:,}".format(int(round(value)))


def score_label(score):
    if score < 28:
        return "VERY WEAK"
    if score < 36:
        return "WEAK"
    if score < 60:
        return "FAIR"
    if score < 80:
        return "STRONG"
    return "VERY STRONG"


def main(argv):
    if not sys.stdin.isatty():
        pw = sys.stdin.read().strip()
    else:
        try:
            pw = getpass.getpass("Password to check (not echoed, never stored): ")
        except (EOFError, KeyboardInterrupt):
            print(file=sys.stderr)
            return 2

    if not pw:
        print("error: no password given", file=sys.stderr)
        return 2

    pool = char_pool_size(pw)
    weaknesses, discount = analyze_patterns(pw)
    effective_len = max(1, len(pw) - discount)
    entropy = effective_len * math.log2(pool) if pool > 1 else 0.0

    score = min(100, int(round(entropy)))
    label = score_label(score)
    if any("common password" in w or "most-used passwords" in w
           for w in weaknesses):
        score, label = 5, "VERY WEAK"

    guesses_avg = 2 ** (entropy - 1)  # average guesses to crack
    online = human_duration(guesses_avg / 1_000)       # rate-limited service
    offline = human_duration(guesses_avg / 10_000_000_000)  # fast GPU rig

    print("Password strength: %s  (score %d/100)" % (label, score))
    print()
    print("  entropy        ~%.1f bits" % entropy)
    print("  online crack   %s  (1k guesses/sec)" % online)
    print("  offline crack  %s  (10B guesses/sec)" % offline)
    print()
    if weaknesses:
        print("Weaknesses found:")
        for w in weaknesses:
            print("  - " + w)
        print()
    print("Tips:")
    if len(pw) < 12:
        print("  - Make it longer: length beats cleverness every time.")
    classes = sum((
        any(c.islower() for c in pw), any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw), any(not c.isalnum() for c in pw),
    ))
    if classes < 3 and score < 80:
        print("  - Mix character types: upper + lower + digits + symbols.")
    if weaknesses:
        print("  - Drop the patterns above; attackers try those first.")
    if score < 60:
        print("  - Consider a passphrase: 4+ random words are strong "
              "and memorable.")
    if score >= 80 and not weaknesses:
        print("  - Solid. Still rotate it if it ever leaks anywhere.")
    print()
    print("NOTE: entropy is an estimate. A leaked password is compromised")
    print("regardless of strength -- change it, don't re-score it.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
