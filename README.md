# XOR Encryption Breaker

A small Python tool for repeating-key XOR encryption, decryption, and cryptanalysis.

Given a ciphertext encrypted with English plaintext, it can recover the key —
**single-byte** keys via classical letter-frequency analysis, **multi-byte**
keys via Hamming-distance keysize estimation followed by per-position
frequency attacks (Cryptopals Set 1 Challenge 6).

## Features

- **encrypt** — XOR-encrypt a file with a given key
- **decrypt** — XOR-decrypt with a known key (XOR is symmetric, but exposed as
  its own command for clarity)
- **break** — recover an unknown key (1–40 bytes by default) from ciphertext

## Requirements

- Python 3.9+
- [uv](https://github.com/astral-sh/uv) for dependency management (optional;
  the script has no runtime dependencies)

## Setup

```shell
uv sync --extra dev
```

This creates a virtual environment and installs `pytest` and `ruff` for
development. No runtime dependencies, so for plain use you can also just run
the script with any Python 3.9+ interpreter.

## Usage

```shell
python xor_breaker.py <command> [options]
```

### Encrypt

```shell
python xor_breaker.py encrypt plaintext.txt mykey
# Encrypted -> plaintext.txt.encrypted
```

### Decrypt (key known)

```shell
python xor_breaker.py decrypt plaintext.txt.encrypted mykey
# Decrypted -> plaintext.txt
```

### Break (key unknown)

```shell
python xor_breaker.py break ciphertext.bin
# Recovered key (7 bytes): longkey
# Plaintext:
# ...
```

To restrict the search to single-byte keys:

```shell
python xor_breaker.py break ciphertext.bin --max-keylen 1
```

## How the breaker works

1. **Single-byte attempt.** XOR the ciphertext against each of 256 possible
   bytes and score each candidate against English letter frequencies. The
   lowest-scoring (most English-like) output wins.
2. **Multi-byte attempt.** For each candidate keysize `N` in `[2, max_keylen]`:
   - Split the ciphertext into `N`-byte blocks and compute the average
     normalized Hamming distance between adjacent blocks. The true keysize
     tends to minimize this metric.
   - Take the top-ranked keysizes, transpose the ciphertext into `N`
     sub-streams (each is a single-byte XOR problem), and solve each.
   - Score the resulting plaintext; collapse the recovered key to its
     minimum repeating period.
3. Return whichever attempt produced the more English-like plaintext.

The breaker works well for ciphertexts at least ~20× the key length. For
shorter inputs frequency analysis becomes unreliable.

## Development

```shell
uv run pytest         # run tests
uv run ruff check .   # lint
```

## License

MIT — see [LICENSE](LICENSE).
