# XOR Breaker — Polish Pass

## Plan

- [x] Rewrite `xor_breaker.py`
  - [x] Fix bug: `file.read().encode()` on bytes
  - [x] Fix bug: frequency score iterates only observed letters (zero-letter outputs win)
  - [x] Fix bug: `ord(str(key[i % key_length]))` corrupts non-string keys
  - [x] Replace manual `sys.argv` parsing with `argparse` subcommands (encrypt/decrypt/break)
  - [x] Add multi-byte key breaking (Hamming-distance keysize guess + transposed single-byte attacks)
  - [x] Add `decrypt` subcommand
  - [x] Type hints, docstrings, clean code
- [x] Pytest suite (16 tests, all green)
- [x] `pyproject.toml` (uv-managed; pytest + ruff as dev deps)
- [x] `.gitignore`
- [x] `LICENSE` (MIT)
- [x] Update `README.md` to match new CLI + features
- [x] `uv run ruff check .` clean; `uv run pytest` 16/16 passing

## Review

**Scope landed:**

- Three real bugs fixed (bytes `.encode()`, frequency scoring vs observed-only letters, `ord(str(...))`).
- Cryptanalysis now handles multi-byte keys via Hamming-distance keysize ranking
  (top-4 candidates) + per-position transposition + single-byte solve, with a
  minimal-period collapse so `ABAB` → `AB`.
- Scoring gained a printable-byte gate + uppercase-fraction penalty. The latter
  was the fix for the one nontrivial issue surfaced during testing:
  case-folded letter frequencies couldn't distinguish a key from a key off by
  0x20, so per-position breaks sometimes returned `HIDDEN`-style outputs.
- CLI is now `argparse` with `encrypt`/`decrypt`/`break` subcommands.
  `break` flushes stdout text-mode writes before doing `buffer.write(plaintext)`
  (otherwise `print()`-buffered text appeared after the binary plaintext).
- Tests use a long natural-prose passage (Conan Doyle, public domain). Pangram
  paragraphs gave false negatives — XOR-by-0x02 permutations of pangram text
  scored *better* than the truth because pangram letter frequencies are
  artificially flat.

**Lessons captured:** see `tasks/lessons.md`.
