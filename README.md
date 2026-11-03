# password-strength

Estimate a password's strength from the terminal: entropy-based score, crack-time estimates, detected patterns (common passwords, repeated characters, keyboard sequences), and concrete improvement tips.

Everything runs locally — no network calls, no logging, nothing stored. The password is read through a secure prompt (no echo) or stdin, so it never appears in shell history or process lists.

## Requirements

- Python 3.8+
- No external dependencies (stdlib only)

## How to run

```bash
# secure prompt (input is not echoed)
python password_strength.py

# or pipe it in
echo "s3cret!" | python password_strength.py
```

## Example output

```
$ echo "Tr0ub4dor&3" | python password_strength.py
Password strength: STRONG  (score 72/100)

  entropy        ~72.3 bits
  online crack   effectively uncrackable  (1k guesses/sec)
  offline crack  ~9,012 years  (10B guesses/sec)

Tips:
  - Make it longer: length beats cleverness every time.

NOTE: entropy is an estimate. A leaked password is compromised
regardless of strength -- change it, don't re-score it.
```

```
$ echo "password123" | python password_strength.py
Password strength: VERY WEAK  (score 5/100)

  entropy        ~31.0 bits
  online crack   ~12.6 days  (1k guesses/sec)
  offline crack  less than a second  (10B guesses/sec)

Weaknesses found:
  - it contains the common password 'password'
  - predictable sequence ('123...')

Tips:
  - Make it longer: length beats cleverness every time.
  - Mix character types: upper + lower + digits + symbols.
  - Drop the patterns above; attackers try those first.
  - Consider a passphrase: 4+ random words are strong and memorable.
```

## Options / behaviour

- Reads from a secure `getpass` prompt when run interactively, from stdin when piped.
- Cracks times are estimates at two attacker speeds: a rate-limited online service (1k guesses/sec) and a fast offline GPU rig (10B guesses/sec).
- Predictable patterns (repeated runs, keyboard sequences) reduce the effective entropy, because attackers try those first.
- Exit code `0` when a password is scored, `2` when no input is given.

## Why this exists

Online password checkers ask you to type a real password into a stranger's website. This gives you the same insight — entropy, crack time, pattern warnings — with the password never leaving your own machine.
