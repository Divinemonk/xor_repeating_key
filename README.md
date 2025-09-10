# Repeating‑Key XOR: Toolkit & Challenge

> Decrypt or create repeating‑key XOR messages (CTF‑style flags like `crypto{...}` or any text), using a single Python CLI.

---

## What’s Inside

- `xor_repeating_key.py`: Unified CLI to generate, derive, and decrypt repeating‑key XOR.
- `ciphertext.txt`: Example ciphertext (hex). The script uses this by default if no input is passed.

Requirements: Python 3 (no external libraries).

---

## Quick Start

- Generate example ciphertext (demo values from the README):

```bash
python3 xor_repeating_key.py generate --example -o ciphertext_generated.txt
```

- Derive and decrypt from a known prefix (typical for flags):

```bash
python3 xor_repeating_key.py derive \
  --ct-file ciphertext_generated.txt \
  --known-prefix 'crypto{' \
  --allow-uppercase \
  --min-key-len 2 --max-key-len 32
```

- Decrypt with a known key:

```bash
python3 xor_repeating_key.py decrypt --ct-file ciphertext_generated.txt --key 'myXORkey'
```

---

## Why Hex?

- Ciphertexts and keys are raw bytes and may include non‑printable values. Hex is safe for copy/paste and storing in text files.
- The CLI prints plaintext as text by default. You can also save raw plaintext bytes with `--out-pt`.

Convert between hex and raw bytes:

```bash
# hex -> raw bytes (xxd)
xxd -r -p ciphertext_generated.txt > ciphertext.bin

# hex -> raw bytes (Python)
python3 -c "import sys, binascii; open('ciphertext.bin','wb').write(binascii.unhexlify(sys.stdin.read().strip()))" < ciphertext_generated.txt
```

---

## Subcommands & Options

### generate — Encrypt plaintext with a repeating key

```bash
python3 xor_repeating_key.py generate \
  [-p TEXT | --pt-file FILE | --pt-hex HEX] \
  [-k TEXT | --key-hex HEX] \
  [-o OUT] [--no-newline] [--example] [--encoding utf-8]
```

- `-p/--plaintext`: Plaintext as a UTF‑8 string.
- `--pt-file`: Read plaintext bytes from file.
- `--pt-hex`: Plaintext provided as hex.
- `-k/--key`: Key as UTF‑8 string.
- `--key-hex`: Key as hex.
- `-o/--out`: Write hex ciphertext to file (default: stdout).
- `--example`: Use built‑in demo plaintext/key.
- `--encoding`: Encoding for text inputs (default: utf‑8).

Examples:

```bash
# Simple
python3 xor_repeating_key.py generate -p 'hello world' -k 'myXORkey'

# From file
python3 xor_repeating_key.py generate --pt-file msg.txt -k 'myXORkey' -o ct.txt

# Hex inputs
python3 xor_repeating_key.py generate --pt-hex 68656c6c6f --key-hex 6b6579
```

### derive — Recover key (and plaintext) from hints

```bash
python3 xor_repeating_key.py derive \
  [--ciphertext-hex HEX | --ct-file FILE] \
  [--known-prefix TEXT | --prefix-hex HEX] \
  [--min-key-len N --max-key-len M] \
  [--no-assume-brace] [--allow-uppercase] \
  [--crib TEXT | --crib-hex HEX] [--crib-offset N] \
  [--out-pt FILE] [--out-key-hex FILE] [--encoding utf-8]
```

- `--ciphertext-hex` / `--ct-file`: Ciphertext input (hex). If omitted, uses `ciphertext.txt` in this folder.
- `--known-prefix` / `--prefix-hex`: Known plaintext prefix (e.g., `crypto{` or `FLAG{`).
- `--min-key-len`/`--max-key-len`: Key length search range (smaller range = faster).
- `--no-assume-brace`: Do not assume plaintext ends with `}` (useful for non‑flag messages).
- `--allow-uppercase`: Allow uppercase letters in the plaintext model.
- `--crib` / `--crib-hex`: Known substring appearing somewhere in the plaintext.
- `--crib-offset`: Position where the crib starts (default: search all positions).
- `--out-pt`: Write decrypted plaintext bytes to file.
- `--out-key-hex`: Write derived key (hex) to file.
- `--encoding`: Encoding for text inputs (default: utf‑8).

Tips:

- Short ciphertexts may be under‑determined with only a prefix; add a `--crib` to pin missing key bytes.
- Knowing the key length greatly improves speed and accuracy (set min=max).

Examples:

```bash
# 1) Classic flag; you know it starts with crypto{
python3 xor_repeating_key.py derive \
  --ct-file ciphertext_generated.txt \
  --known-prefix 'crypto{' --allow-uppercase \
  --min-key-len 2 --max-key-len 32

# 2) You know key length is 8
python3 xor_repeating_key.py derive \
  --ct-file ciphertext_generated.txt \
  --known-prefix 'crypto{' --allow-uppercase \
  --min-key-len 8 --max-key-len 8

# 3) Short message example (‘hello world’) — needs a crib
python3 xor_repeating_key.py derive \
  --ct-file ciphertext.txt \
  --known-prefix 'hello ' --crib world --no-assume-brace \
  --min-key-len 8 --max-key-len 8
```

### decrypt — Decrypt with a known key

```bash
python3 xor_repeating_key.py decrypt \
  [--ciphertext-hex HEX | --ct-file FILE] \
  [--key TEXT | --key-hex HEX] \
  [--out-pt FILE] [--encoding utf-8]
```

- `--key` / `--key-hex`: Provide the key directly (text or hex).
- `--out-pt`: Save plaintext bytes to a file (stdout prints text when possible).

---

## End‑to‑End Examples

### Create and Derive a CTF Flag

Create ciphertext (hex) for a sample flag using an 8‑byte key:

```bash
python3 xor_repeating_key.py generate \
  -p 'FLAG{112f3a99b283a4e1788dedd8e0e5d35375c33747}' \
  -k 'myXORkey' -o flag_ct.txt
```

Derive and decrypt (best‑practice config):

```bash
# If you know key length = 8
python3 xor_repeating_key.py derive \
  --ct-file flag_ct.txt \
  --known-prefix 'FLAG{' --allow-uppercase \
  --min-key-len 8 --max-key-len 8 \
  --out-key-hex derived_key.hex --out-pt derived_flag.bin

# If you do not know key length
python3 xor_repeating_key.py derive \
  --ct-file flag_ct.txt \
  --known-prefix 'FLAG{' --allow-uppercase \
  --min-key-len 2 --max-key-len 32 \
  --out-key-hex derived_key.hex --out-pt derived_flag.bin
```

Verify with known key (optional):

```bash
python3 xor_repeating_key.py decrypt --ct-file flag_ct.txt --key 'myXORkey'
```

---

## Notes & Troubleshooting

- Hex vs Text: ciphertext and key are shown in hex for safety. Plaintext is printed as text when possible.
- Encodings: string inputs/outputs default to UTF‑8; use `--encoding` if needed.
- Underdetermined Cases: if some key bytes aren’t covered by your prefix, add a `--crib` (known substring) or expand the prefix.
- Performance: constrain `--min-key-len` and `--max-key-len` when you know the key length; it speeds up and improves accuracy.
- Saving Outputs: use `--out-pt` for plaintext bytes and `--out-key-hex` for the derived key (hex). To try reading a hex key as text:

```bash
python3 -c "import binascii;print(binascii.unhexlify(open('derived_key.hex').read().strip()).decode('utf-8','replace'))"
```

---

## Reference Ciphertext (for practice)

```
0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104
```

