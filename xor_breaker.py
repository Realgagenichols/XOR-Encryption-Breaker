#!/usr/bin/env python3
"""XOR encryption and cryptanalysis tool.

Encrypts and decrypts data with a repeating-key XOR cipher, and recovers
unknown keys (single- or multi-byte) from ciphertext via English letter
frequency analysis combined with Hamming-distance keysize estimation.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Relative frequencies of letters a-z in typical English prose.
ENGLISH_FREQ: dict[str, float] = {
    "a": 0.08167, "b": 0.01492, "c": 0.02782, "d": 0.04253, "e": 0.12702,
    "f": 0.02228, "g": 0.02015, "h": 0.06094, "i": 0.06966, "j": 0.00153,
    "k": 0.00772, "l": 0.04025, "m": 0.02406, "n": 0.06749, "o": 0.07507,
    "p": 0.01929, "q": 0.00095, "r": 0.05987, "s": 0.06327, "t": 0.09056,
    "u": 0.02758, "v": 0.00978, "w": 0.02360, "x": 0.00150, "y": 0.01974,
    "z": 0.00074,
}


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR ``data`` against ``key``, repeating the key as needed."""
    if not key:
        raise ValueError("key must be non-empty")
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def _score_english(data: bytes) -> float:
    """Score how English-like ``data`` looks. Lower is better; ``inf`` rejects."""
    if not data:
        return float("inf")

    # Reject candidates dominated by non-printable bytes — those are almost
    # certainly the wrong key.
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    if printable / len(data) < 0.85:
        return float("inf")

    n = len(data)
    letter_counts: dict[str, int] = {}
    upper = 0
    total_letters = 0
    for b in data:
        if 0x41 <= b <= 0x5A:  # uppercase ASCII
            ch = chr(b + 0x20)
            letter_counts[ch] = letter_counts.get(ch, 0) + 1
            total_letters += 1
            upper += 1
        elif 0x61 <= b <= 0x7A:  # lowercase ASCII
            ch = chr(b)
            letter_counts[ch] = letter_counts.get(ch, 0) + 1
            total_letters += 1
    if total_letters == 0:
        return float("inf")

    score = 0.0
    for letter, expected in ENGLISH_FREQ.items():
        observed = letter_counts.get(letter, 0) / total_letters
        score += abs(observed - expected)

    # Real English prose is mostly lowercase. Excess uppercase is the tell-tale
    # of a key off by 0x20 from the truth — without this penalty, "hidden" and
    # "HIDDEN" score identically.
    upper_frac = upper / n
    score += max(0.0, upper_frac - 0.10) * 5

    return score


def break_single_byte(ciphertext: bytes) -> tuple[int, float, bytes]:
    """Return ``(key_byte, score, plaintext)`` for the best single-byte XOR key."""
    best_key = 0
    best_score = float("inf")
    best_plain = b""
    for k in range(256):
        candidate = bytes(b ^ k for b in ciphertext)
        score = _score_english(candidate)
        if score < best_score:
            best_key = k
            best_score = score
            best_plain = candidate
    return best_key, best_score, best_plain


def _hamming_distance(a: bytes, b: bytes) -> int:
    """Bit-level Hamming distance between two equal-length byte strings."""
    if len(a) != len(b):
        raise ValueError("hamming distance requires equal-length inputs")
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def _rank_keysizes(
    ciphertext: bytes, min_size: int, max_size: int, top_n: int = 4
) -> list[int]:
    """Rank candidate keysizes by average normalized Hamming distance, best first."""
    scored: list[tuple[float, int]] = []
    for size in range(min_size, max_size + 1):
        blocks = [
            ciphertext[i : i + size]
            for i in range(0, len(ciphertext), size)
            if i + size <= len(ciphertext)
        ]
        if len(blocks) < 4:
            continue
        total = 0.0
        for i in range(len(blocks) - 1):
            total += _hamming_distance(blocks[i], blocks[i + 1]) / size
        avg = total / (len(blocks) - 1)
        scored.append((avg, size))
    scored.sort()
    return [size for _, size in scored[:top_n]]


def _minimal_period(key: bytes) -> bytes:
    """Collapse a key that is a repetition of a shorter pattern (e.g. ``ABAB`` → ``AB``)."""
    n = len(key)
    for p in range(1, n):
        if n % p == 0 and key[:p] * (n // p) == key:
            return key[:p]
    return key


def break_multi_byte(
    ciphertext: bytes, min_keylen: int = 2, max_keylen: int = 40
) -> tuple[bytes, float, bytes]:
    """Recover a repeating-key XOR cipher via Kasiski/Friedman keysize estimation."""
    candidates = _rank_keysizes(ciphertext, min_keylen, max_keylen)
    best_key = b""
    best_score = float("inf")
    best_plain = b""
    for keysize in candidates:
        key = bytearray()
        for offset in range(keysize):
            stream = ciphertext[offset::keysize]
            k, _, _ = break_single_byte(stream)
            key.append(k)
        key_bytes = _minimal_period(bytes(key))
        plaintext = xor_bytes(ciphertext, key_bytes)
        score = _score_english(plaintext)
        if score < best_score:
            best_key = key_bytes
            best_score = score
            best_plain = plaintext
    return best_key, best_score, best_plain


def break_xor(ciphertext: bytes, max_keylen: int = 40) -> tuple[bytes, bytes]:
    """Recover the most likely XOR key and plaintext, trying single- and multi-byte."""
    sb_key, sb_score, sb_plain = break_single_byte(ciphertext)
    if max_keylen < 2 or len(ciphertext) < 8:
        return bytes([sb_key]), sb_plain
    mb_key, mb_score, mb_plain = break_multi_byte(ciphertext, 2, max_keylen)
    if mb_key and mb_score < sb_score:
        return mb_key, mb_plain
    return bytes([sb_key]), sb_plain


def _unique_path(path: Path) -> Path:
    """Return ``path``, or ``stem-N.ext`` if it already exists."""
    if not path.exists():
        return path
    parent, stem, suffix = path.parent, path.stem, path.suffix
    count = 1
    while True:
        candidate = parent / f"{stem}-{count}{suffix}"
        if not candidate.exists():
            return candidate
        count += 1


def _read_input(path_str: str) -> bytes:
    path = Path(path_str)
    if not path.is_file():
        raise FileNotFoundError(f"input file not found: {path}")
    return path.read_bytes()


def cmd_encrypt(args: argparse.Namespace) -> int:
    plaintext = _read_input(args.input)
    key = args.key.encode("utf-8")
    ciphertext = xor_bytes(plaintext, key)
    output = Path(args.output) if args.output else _unique_path(
        Path(f"{args.input}.encrypted")
    )
    output.write_bytes(ciphertext)
    print(f"Encrypted -> {output}")
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    ciphertext = _read_input(args.input)
    key = args.key.encode("utf-8")
    plaintext = xor_bytes(ciphertext, key)
    if args.output:
        output = Path(args.output)
    else:
        in_path = Path(args.input)
        default = in_path.with_suffix("") if in_path.suffix == ".encrypted" else Path(
            f"{args.input}.decrypted"
        )
        output = _unique_path(default)
    output.write_bytes(plaintext)
    print(f"Decrypted -> {output}")
    return 0


def cmd_break(args: argparse.Namespace) -> int:
    ciphertext = _read_input(args.input)
    key, plaintext = break_xor(ciphertext, max_keylen=args.max_keylen)
    try:
        key_repr = key.decode("ascii")
        if not key_repr.isprintable():
            raise UnicodeDecodeError("ascii", key, 0, len(key), "non-printable")
    except UnicodeDecodeError:
        key_repr = f"0x{key.hex()}"
    plural = "" if len(key) == 1 else "s"
    print(f"Recovered key ({len(key)} byte{plural}): {key_repr}")
    print("Plaintext:")
    sys.stdout.flush()
    sys.stdout.buffer.write(plaintext)
    if not plaintext.endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")
    sys.stdout.buffer.flush()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xor_breaker",
        description="Encrypt, decrypt, or break repeating-key XOR ciphers.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_enc = sub.add_parser("encrypt", help="XOR-encrypt a file with a given key")
    p_enc.add_argument("input", help="input file path")
    p_enc.add_argument("key", help="encryption key (UTF-8 string)")
    p_enc.add_argument("-o", "--output", help="output path (default: <input>.encrypted)")
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="XOR-decrypt a file with a known key")
    p_dec.add_argument("input", help="input file path")
    p_dec.add_argument("key", help="decryption key (UTF-8 string)")
    p_dec.add_argument("-o", "--output", help="output path")
    p_dec.set_defaults(func=cmd_decrypt)

    p_brk = sub.add_parser(
        "break", help="recover an unknown XOR key via frequency analysis"
    )
    p_brk.add_argument("input", help="ciphertext file path")
    p_brk.add_argument(
        "--max-keylen",
        type=int,
        default=40,
        help="maximum key length to consider (default: 40; pass 1 to limit to single-byte)",
    )
    p_brk.set_defaults(func=cmd_break)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
