# Lessons

## L1: Don't test frequency analysis with pangram corpora
Pangram-heavy text has artificially flat letter frequencies, so any permutation
of letters scores nearly as well as the truth. The single-byte XOR breaker
preferred `key XOR 0x02` over the true key on a paragraph of pangrams by ~0.008
score points.

**Rule:** test English cryptanalysis with natural prose (Project Gutenberg,
Sherlock Holmes, etc.), not pangrams. The corpus must be representative of what
you claim to detect.

## L2: Case-folded frequency scoring can't see XOR-by-0x20
ASCII XOR-by-0x20 toggles letter case (`a` ↔ `A`). A scoring function that
lowercases before counting frequencies cannot distinguish `hidden` from
`HIDDEN`, so a multi-byte breaker that does per-position solves will sometimes
return keys with positions off by 0x20.

**Rule:** when scoring English-ness, add an uppercase-fraction penalty (real
prose is <5% uppercase). The penalty discriminates exactly the cases that
case-folded letter frequencies cannot.

## L3: Don't mix `print()` and `sys.stdout.buffer.write` without flushing
`print()` writes through stdout's text layer, which buffers separately from
`sys.stdout.buffer`. Interleaving them produces out-of-order output (binary
plaintext appears before the header line you "already printed").

**Rule:** `sys.stdout.flush()` after the last `print()` before writing to
`sys.stdout.buffer`, and `sys.stdout.buffer.flush()` after binary writes. Or
just stick to one of the two layers.
