#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path

def xor_repeating(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("Key must be non-empty")
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key[i % len(key)])
    return bytes(out)

def _is_printable_byte(b: int) -> bool:
    # Allow common ASCII text range and whitespace
    return b in (9, 10, 13) or 32 <= b <= 126


def _score_plaintext(pt: bytes) -> float:
    if not pt:
        return -1e9
    printable = sum(1 for x in pt if _is_printable_byte(x))
    ratio = printable / len(pt)
    # Penalize NULs heavily
    penalty = 0.2 if 0 in pt else 0.0
    # Character category ratios
    letters = sum(1 for x in pt if 65 <= x <= 90 or 97 <= x <= 122)
    digits = sum(1 for x in pt if 48 <= x <= 57)
    spaces = pt.count(32)
    good_sym = sum(1 for x in pt if x in b"{}_-/.,;:?!'\"()")
    bad_sym = printable - (letters + digits + spaces + good_sym)
    valid = letters + digits + spaces + sum(1 for x in pt if x in b"{}_")
    alpha_ratio = (letters + digits) / len(pt)
    space_ratio = spaces / len(pt)
    good_ratio = good_sym / len(pt)
    bad_ratio = bad_sym / len(pt)
    # Weighted score
    score = (
        1.0 * ratio
        + 0.35 * alpha_ratio
        + 0.25 * space_ratio
        + 0.05 * good_ratio
        - 0.20 * bad_ratio
        - penalty
    )
    score += 0.70 * (valid / len(pt))
    # Bonus for having any space (word boundary)
    if spaces > 0:
        score += 0.1
    elif len(pt) >= 8:
        # Penalize fully space-less outputs of non-trivial length
        score -= 0.35
    # Bonus per alphabetic run length>=3
    run = 0
    runs3 = 0
    for x in pt:
        if 65 <= x <= 90 or 97 <= x <= 122:
            run += 1
        else:
            if run >= 3:
                runs3 += 1
            run = 0
    if run >= 3:
        runs3 += 1
    score += 0.12 * runs3
    # Tiny bonus for common substrings
    for word in (b"the", b"flag", b"crypto", b"hello", b"world"):
        if word in pt.lower():
            score += 0.1
    return score


def derive_key_repeating_xor(
    ct: bytes,
    prefix: bytes,
    min_L: int = 2,
    max_L: int = 32,
    assume_brace: bool = True,
    allow_uppercase: bool = False,
    crib: bytes = b"",
    crib_offset: int = -1,
) -> bytes:
    best_score = float("-inf")
    best_key = b""

    for L in range(min_L, max_L + 1):
        key = [None] * L
        # Apply constraints from known prefix
        for i in range(min(len(prefix), len(ct))):
            j = i % L
            cand = ct[i] ^ prefix[i]
            if key[j] is None:
                key[j] = cand
            elif key[j] != cand:
                # inconsistent with this L
                key = None
                break
        if key is None:
            continue

        # Optional constraint: last char is '}'
        if assume_brace and len(ct) > 0:
            j = (len(ct) - 1) % L
            cand = ct[-1] ^ ord('}')
            if key[j] is None:
                key[j] = cand
            elif key[j] != cand:
                # inconsistent with this L
                continue

        # Optional crib-dragging: apply known substring at one or all offsets
        offsets = [crib_offset] if (crib and crib_offset >= 0) else (list(range(0, max(0, len(ct) - len(crib) + 1))) if crib else [None])
        for off in offsets:
            ktemp = key[:]  # copy
            if crib:
                conflict = False
                for t, ch in enumerate(crib):
                    i = (off + t)
                    if i >= len(ct):
                        conflict = True
                        break
                    j = i % L
                    cand = ct[i] ^ ch
                    if ktemp[j] is None:
                        ktemp[j] = cand
                    elif ktemp[j] != cand:
                        conflict = True
                        break
                if conflict:
                    continue
            # Proceed with this augmented key hypothesis
            score_key = _complete_and_score_key(ct, ktemp, L, prefix, assume_brace, allow_uppercase)
            if score_key is None:
                continue
            sc, kbytes = score_key
            if sc > best_score:
                best_score = sc
                best_key = kbytes

    # As a fallback, return partial prefix-derived key if nothing better
    if best_key:
        # Local refinement: tune bytes for columns with a single observation
        return _refine_key_local(ct, best_key, prefix, assume_brace)
    return bytes(ct[i] ^ prefix[i] for i in range(min(len(prefix), len(ct))))


def _complete_and_score_key(ct, key, L, prefix, assume_brace, allow_uppercase):
    # Strict allowed character set
    allowed = set(b"abcdefghijklmnopqrstuvwxyz0123456789{}_ ")
    if allow_uppercase:
        allowed |= set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    # Narrow domains with set intersections per column
    domains = [None] * L
    for j in range(L):
        col = [ct[i] for i in range(j, len(ct), L)]
        if not col:
            domains[j] = {0}
            continue
        dom = set(range(256))
        for c in col:
            dom &= {kbyte for kbyte in range(256) if (c ^ kbyte) in allowed}
        domains[j] = dom
    # Check constraints compatibility and fill singletons
    consistent = True
    changed = True
    while changed:
        changed = False
        for j in range(L):
            if key[j] is not None:
                if key[j] not in domains[j]:
                    consistent = False
                    break
                domains[j] = {key[j]}
            else:
                if len(domains[j]) == 0:
                    consistent = False
                    break
                if len(domains[j]) == 1:
                    key[j] = next(iter(domains[j]))
                    changed = True
        if not consistent:
            break
    if not consistent:
        return None

    # Build candidate lists per position j (top-K by local column score)
    K = 10
    cand_lists = []
    for j in range(L):
        if key[j] is not None:
            cand_lists.append([(key[j], 1e6)])  # force fixed byte
            continue
        col = [ct[i] for i in range(j, len(ct), L)]
        if not col:
            cand_lists.append([(0, 0.0)])
            continue
        scored = []
        # Limit candidate kbytes to domain to curb search
        for kbyte in domains[j]:
            ok = True
            for pos in range(j, min(len(prefix), len(ct)), L):
                if (ct[pos] ^ kbyte) != prefix[pos]:
                    ok = False
                    break
            if not ok:
                continue
            score = 0.0
            for c in col:
                p = c ^ kbyte
                if _is_printable_byte(p):
                    score += 1.0
                    if p == 32:
                        score += 0.8
                    elif (65 <= p <= 90) or (97 <= p <= 122):
                        score += 0.5
                    elif 48 <= p <= 57:
                        score += 0.2
                    elif p in (ord('{'), ord('}'), ord('_')):
                        score += 0.3
                else:
                    score -= 0.5
            scored.append((score, kbyte))
        if not scored:
            cand_lists.append([(0, -1e3)])
        else:
            top = sorted(scored, reverse=True)[:K]
            cand_lists.append([(kb, sc) for sc, kb in top])

    # Beam search across positions
    BEAM = 200
    beam = [([], 0.0)]  # (partial_key, score)
    for j in range(L):
        new_beam = []
        for pk, sc in beam:
            for kb, loc in cand_lists[j]:
                new_beam.append((pk + [kb], sc + loc))
        # keep top BEAM
        new_beam.sort(key=lambda x: x[1], reverse=True)
        beam = new_beam[:BEAM]

    # Evaluate final candidates using global plaintext score
    best = max([
        (
            _score_plaintext(xor_repeating(ct, bytes(pk)))
            + (0.5 if xor_repeating(ct, bytes(pk)).startswith(prefix) else 0)
            + (0.3 if (assume_brace and xor_repeating(ct, bytes(pk)).endswith(b'}')) else 0),
            bytes(pk)
        )
        for pk, _ in beam
    ], key=lambda x: x[0])
    return best


def _refine_key_local(ct: bytes, key: bytes, prefix: bytes, assume_brace: bool) -> bytes:
    L = len(key)
    if L == 0:
        return key
    k = bytearray(key)
    # Determine columns that have exactly one sample and are not fully determined by prefix
    cols = {j: [i for i in range(j, len(ct), L)] for j in range(L)}
    preferred = b" etaoinshrdlucmfwypvbgkqjxzETAOINSHRDLUCMFWYPVBGKQJXZ0123456789{}_"
    for _ in range(5):  # multiple passes for convergence
        improved = False
        for j, idxs in cols.items():
            if len(idxs) != 1:
                continue
            i = idxs[0]
            # Skip if this position is within known prefix and thus fixed
            if i < len(prefix):
                continue
            # Build candidate set
            cand_chars = preferred
            if assume_brace and i == len(ct) - 1:
                cand_chars = b'}' + cand_chars
            best_local = None
            best_score = -1e9
            for ch in cand_chars:
                kb = ct[i] ^ ch
                old = k[j]
                k[j] = kb
                pt = xor_repeating(ct, bytes(k))
                sc = _score_plaintext(pt)
                if pt.startswith(prefix):
                    sc += 0.5
                if assume_brace and pt.endswith(b'}'):
                    sc += 0.3
                if sc > best_score:
                    best_score = sc
                    best_local = kb
                k[j] = old
            if best_local is not None and best_local != k[j]:
                k[j] = best_local
                improved = True
        if not improved:
            break
    return bytes(k)


# -------------------- generate mode --------------------

def _load_plaintext_for_generate(args: argparse.Namespace) -> bytes:
    if getattr(args, "pt_hex", None):
        return bytes.fromhex(args.pt_hex)
    if getattr(args, "pt_file", None):
        return args.pt_file.read_bytes()
    if getattr(args, "plaintext", None) is not None:
        return args.plaintext.encode(args.encoding)
    if getattr(args, "example", False):
        return b"crypto{1f_y0u_Kn0w_En0ugh_y0u_g0_all_th3_w4y}"
    raise SystemExit("Error: provide plaintext via -p/--pt-file/--pt-hex or --example")


def _load_key_for_generate(args: argparse.Namespace) -> bytes:
    if getattr(args, "key_hex", None):
        return bytes.fromhex(args.key_hex)
    if getattr(args, "key", None) is not None:
        return args.key.encode(args.encoding)
    if getattr(args, "example", False):
        return b"myXORkey"
    raise SystemExit("Error: provide key via -k/--key-hex or --example")


def generate_mode(args: argparse.Namespace) -> int:
    pt = _load_plaintext_for_generate(args)
    key = _load_key_for_generate(args)
    ct = xor_repeating(pt, key)
    hex_ct = ct.hex()
    if getattr(args, "out", None):
        args.out.write_text(hex_ct + "\n", encoding="utf-8")
        print(f"Wrote ciphertext to {args.out}")
    else:
        end = "" if getattr(args, "no_newline", False) else "\n"
        sys.stdout.write(hex_ct + end)
    return 0

def load_ct(args: argparse.Namespace) -> bytes:
    hex_in = getattr(args, "ciphertext_hex", None)
    if hex_in:
        return bytes.fromhex(hex_in.strip())
    ct_file = getattr(args, "ct_file", None)
    if ct_file:
        return bytes.fromhex(ct_file.read_text().strip())
    # default to repo ciphertext.txt if present
    default = Path(__file__).with_name("ciphertext.txt")
    if default.exists():
        return bytes.fromhex(default.read_text().strip())
    raise SystemExit("Error: provide --ciphertext-hex or --ct-file")


def load_prefix(args: argparse.Namespace) -> bytes:
    if getattr(args, "prefix_hex", None):
        return bytes.fromhex(args.prefix_hex)
    if getattr(args, "known_prefix", None) is not None:
        return args.known_prefix.encode(args.encoding)
    return b""  # default: no assumption


def load_key(args: argparse.Namespace) -> bytes:
    if getattr(args, "key_hex", None):
        return bytes.fromhex(args.key_hex)
    if getattr(args, "key", None) is not None:
        return args.key.encode(args.encoding)
    raise SystemExit("Error: provide key via --key or --key-hex")


def derive_mode(args: argparse.Namespace) -> int:
    ct = load_ct(args)
    user_prefix = load_prefix(args)
    min_len = getattr(args, "min_key_len", 2)
    max_len = getattr(args, "max_key_len", 32)
    assume_brace = getattr(args, "assume_brace", True)
    allow_uppercase = getattr(args, "allow_uppercase", False)
    crib = b""
    if getattr(args, "crib_hex", None):
        crib = bytes.fromhex(args.crib_hex)
    elif getattr(args, "crib", None):
        crib = args.crib.encode(args.encoding)
    crib_offset = getattr(args, "crib_offset", -1)
    
    candidates = []

    def attempt(prefix: bytes, assume: bool, label: str):
        key = derive_key_repeating_xor(ct, prefix, min_len, max_len, assume, allow_uppercase, crib, crib_offset)
        pt = xor_repeating(ct, key)
        score = _score_plaintext(pt)
        candidates.append((score, label, key, pt))

    # Always try the user's provided prefix first
    attempt(user_prefix, assume_brace, "user")
    # If no user prefix provided, try a few common prefixes
    if not user_prefix:
        attempt(b"crypto{", True, "crypto{")
        attempt(b"hello ", False, "hello ")
        attempt(b"flag{", True, "flag{")
        attempt(b"CTF{", True, "CTF{")
    # Choose the best-scoring candidate
    best = max(candidates, key=lambda x: x[0])
    _, label, key_guess, pt = best

    print(f"Prefix mode: {label}")
    print(f"Derived key (repr): {key_guess!r}")
    print(f"Derived key (hex):  {key_guess.hex()}")
    out_key_hex = getattr(args, "out_key_hex", None)
    if out_key_hex:
        Path(out_key_hex).write_text(key_guess.hex() + "\n", encoding="utf-8")
        print(f"Wrote key hex to {out_key_hex}")

    out_pt = getattr(args, "out_pt", None)
    if out_pt:
        Path(out_pt).write_bytes(pt)
        print(f"Wrote plaintext bytes to {out_pt}")
    else:
        try:
            print("Plaintext:", pt.decode(args.encoding))
        except UnicodeDecodeError:
            print("Plaintext (repr):", repr(pt))
    return 0


def decrypt_mode(args: argparse.Namespace) -> int:
    ct = load_ct(args)
    key = load_key(args)
    pt = xor_repeating(ct, key)

    if args.out_pt:
        Path(args.out_pt).write_bytes(pt)
        print(f"Wrote plaintext bytes to {args.out_pt}")
    else:
        try:
            print("Plaintext:", pt.decode(args.encoding))
        except UnicodeDecodeError:
            print("Plaintext (repr):", repr(pt))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Solve XOR with repeating key: derive key or decrypt")
    p.add_argument("--encoding", default="utf-8", help="Encoding for string inputs/outputs")
    sub = p.add_subparsers(dest="cmd", required=False)

    # generate subcommand
    g = sub.add_parser("generate", help="Generate XOR (repeating key) ciphertext from plaintext and key")
    g.add_argument("-p", "--plaintext", help="Plaintext as a UTF-8 string")
    g.add_argument("--pt-file", type=Path, help="Path to file containing plaintext (read as bytes)")
    g.add_argument("--pt-hex", help="Plaintext provided as hex string (e.g. 68656c6c6f)")
    g.add_argument("-k", "--key", help="Key as a UTF-8 string")
    g.add_argument("--key-hex", help="Key as hex string")
    g.add_argument("-o", "--out", type=Path, help="Write hex ciphertext to this file (default: stdout)")
    g.add_argument("--no-newline", action="store_true", help="Do not append newline when printing to stdout")
    g.add_argument("--example", action="store_true", help="Use example plaintext and key from README if no inputs provided")
    g.set_defaults(func=generate_mode)

    # derive subcommand
    d = sub.add_parser("derive", help="Derive key using known prefix and decrypt")
    d.add_argument("--ciphertext-hex", help="Ciphertext hex string")
    d.add_argument("--ct-file", type=Path, help="Path to file containing ciphertext hex")
    d.add_argument("--known-prefix", default="", help="Known plaintext prefix (UTF-8)")
    d.add_argument("--prefix-hex", help="Known plaintext prefix as hex (overrides --known-prefix)")
    d.add_argument("--min-key-len", type=int, default=2, help="Minimum key length to try")
    d.add_argument("--max-key-len", type=int, default=40, help="Maximum key length to try")
    d.add_argument("--no-assume-brace", dest="assume_brace", action="store_false", help="Do not assume plaintext ends with '}'")
    d.add_argument("--out-pt", help="Write plaintext bytes to this file")
    d.add_argument("--allow-uppercase", action="store_true", help="Allow uppercase letters in plaintext model")
    d.add_argument("--crib", help="Known substring (UTF-8) appearing somewhere in the plaintext")
    d.add_argument("--crib-hex", help="Known substring as hex (overrides --crib)")
    d.add_argument("--crib-offset", type=int, default=-1, help="Offset index where the crib appears (default: search all)")
    d.add_argument("--out-key-hex", help="Write derived key hex to this file")
    d.set_defaults(func=derive_mode)

    # decrypt subcommand
    dec = sub.add_parser("decrypt", help="Decrypt with provided key")
    dec.add_argument("--ciphertext-hex", help="Ciphertext hex string")
    dec.add_argument("--ct-file", type=Path, help="Path to file containing ciphertext hex")
    dec.add_argument("--key", help="Key as UTF-8 string")
    dec.add_argument("--key-hex", help="Key as hex string")
    dec.add_argument("--out-pt", help="Write plaintext bytes to this file")
    dec.set_defaults(func=decrypt_mode)
    
    return p


def main(argv=None) -> int:
    p = build_parser()
    args = p.parse_args(argv)
    if not args.cmd:
        # default to derive if no subcommand provided
        args.cmd = "derive"
        args.func = derive_mode
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
