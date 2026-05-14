"""Tests for the XOR encryption / breaking tool."""

from __future__ import annotations

import pytest

from xor_breaker import (
    _hamming_distance,
    _minimal_period,
    _score_english,
    break_multi_byte,
    break_single_byte,
    break_xor,
    xor_bytes,
)

# Natural English prose (opening of "A Scandal in Bohemia" by Arthur Conan Doyle,
# public domain). Long, ordinary text — frequency analysis works reliably on this
# but not on pangram-heavy paragraphs.
ENGLISH_PARAGRAPH = (
    b"To Sherlock Holmes she is always the woman. I have seldom heard him "
    b"mention her under any other name. In his eyes she eclipses and predominates "
    b"the whole of her sex. It was not that he felt any emotion akin to love for "
    b"Irene Adler. All emotions, and that one particularly, were abhorrent to his "
    b"cold, precise but admirably balanced mind. He was, I take it, the most "
    b"perfect reasoning and observing machine that the world has seen, but as a "
    b"lover he would have placed himself in a false position. He never spoke of "
    b"the softer passions, save with a gibe and a sneer. They were admirable "
    b"things for the observer, excellent for drawing the veil from men's motives "
    b"and actions. But for the trained reasoner to admit such intrusions into "
    b"his own delicate and finely adjusted temperament was to introduce a "
    b"distracting factor which might throw a doubt upon all his mental results. "
    b"Grit in a sensitive instrument, or a crack in one of his own high-power "
    b"lenses, would not be more disturbing than a strong emotion in a nature "
    b"such as his. And yet there was but one woman to him, and that woman was "
    b"the late Irene Adler, of dubious and questionable memory."
)


def test_xor_bytes_single_byte_roundtrip():
    ct = xor_bytes(b"hello world", b"X")
    assert xor_bytes(ct, b"X") == b"hello world"


def test_xor_bytes_multi_byte_roundtrip():
    pt = b"attack at dawn, but only if the weather holds"
    ct = xor_bytes(pt, b"SECRET")
    assert xor_bytes(ct, b"SECRET") == pt


def test_xor_bytes_rejects_empty_key():
    with pytest.raises(ValueError):
        xor_bytes(b"hi", b"")


def test_hamming_distance_cryptopals_canonical():
    # The canonical example from Cryptopals Set 1 Challenge 6.
    assert _hamming_distance(b"this is a test", b"wokka wokka!!!") == 37


def test_hamming_distance_length_mismatch():
    with pytest.raises(ValueError):
        _hamming_distance(b"abc", b"ab")


def test_hamming_distance_identical_is_zero():
    assert _hamming_distance(b"same", b"same") == 0


def test_minimal_period_collapses_repeats():
    assert _minimal_period(b"ABAB") == b"AB"
    assert _minimal_period(b"XYZXYZXYZ") == b"XYZ"
    assert _minimal_period(b"abcd") == b"abcd"
    assert _minimal_period(b"a") == b"a"


def test_break_single_byte_recovers_known_key():
    key = 0x42
    ct = bytes(b ^ key for b in ENGLISH_PARAGRAPH)
    recovered, _, plaintext = break_single_byte(ct)
    assert recovered == key
    assert plaintext == ENGLISH_PARAGRAPH


def test_break_multi_byte_recovers_known_key():
    key = b"KEY!"
    ct = xor_bytes(ENGLISH_PARAGRAPH, key)
    recovered, _, plaintext = break_multi_byte(ct, max_keylen=12)
    assert recovered == key
    assert plaintext == ENGLISH_PARAGRAPH


def test_break_multi_byte_longer_key():
    key = b"SuperSecret"
    ct = xor_bytes(ENGLISH_PARAGRAPH, key)
    recovered, _, plaintext = break_multi_byte(ct, max_keylen=20)
    assert recovered == key
    assert plaintext == ENGLISH_PARAGRAPH


def test_break_xor_uses_multi_byte_when_needed():
    key = b"longkey"
    ct = xor_bytes(ENGLISH_PARAGRAPH, key)
    recovered, plaintext = break_xor(ct)
    assert recovered == key
    assert plaintext == ENGLISH_PARAGRAPH


def test_break_xor_uses_single_byte_when_sufficient():
    key = bytes([0x37])
    ct = xor_bytes(ENGLISH_PARAGRAPH, key)
    recovered, plaintext = break_xor(ct)
    assert recovered == key
    assert plaintext == ENGLISH_PARAGRAPH


def test_score_english_prefers_real_text():
    garbage = bytes(range(256)) * 2
    assert _score_english(ENGLISH_PARAGRAPH) < _score_english(garbage)


def test_score_english_rejects_empty():
    assert _score_english(b"") == float("inf")


def test_score_english_rejects_binary_noise():
    binary_noise = bytes(range(0, 32)) * 10
    assert _score_english(binary_noise) == float("inf")


def test_end_to_end_encrypt_then_break(tmp_path):
    """Encrypt a file via the API, then break it without knowing the key."""
    key = b"hidden!"
    pt_path = tmp_path / "plain.txt"
    pt_path.write_bytes(ENGLISH_PARAGRAPH)
    ct_path = tmp_path / "cipher.bin"
    ct_path.write_bytes(xor_bytes(pt_path.read_bytes(), key))

    recovered, plaintext = break_xor(ct_path.read_bytes())
    assert recovered == key
    assert plaintext == ENGLISH_PARAGRAPH
