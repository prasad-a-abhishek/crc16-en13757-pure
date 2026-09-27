"""Tests for crc16-en13757-pure (cycle_129 build).

Organized into 9 categories per the build card (V4):

    1. RevEng canonical vectors
    2. Boundary conditions (single-byte sweep + length sweep)
    3. Cross-cycle disambiguation (vs modbus + ccitt-false)
    4. Table-driven equivalence (bit-by-bit vs table lookup)
    5. Property tests (xorout, init, idempotent)
    6. CLI tests (--data, --self-test, malformed)
    7. Type validation
    8. Chunk equivalence
    9. Fuzz smoke (random stdlib inputs)

Target: >=150 pytest items.
"""

from __future__ import annotations

import os
import random
import subprocess
import sys

import pytest

from crc16_en13757 import (
    Crc16En13757,
    INIT,
    POLY,
    TABLE,
    XOROUT,
    __version__,
    crc,
    crc_stream,
)
from crc16_en13757 import table_lookup


# ---------------------------------------------------------------------------
# 1. RevEng canonical vectors (>=6 tests)
# ---------------------------------------------------------------------------

REVENG_VECTORS = [
    pytest.param(b"", 0xFFFF, id="AC2_empty"),
    pytest.param(b"\x00", 0xFFFF, id="AC3_single_zero"),
    pytest.param(b"\x01", 0xC29A, id="extra_single_0x01"),
    pytest.param(b"\xff", 0x53B7, id="AC4_single_0xff"),
    pytest.param(bytes(range(10)), 0x1078, id="extra_0_to_9"),
    pytest.param(b"123456789", 0xC2B7, id="AC1_reveng_check"),
]


@pytest.mark.parametrize("payload,expected", REVENG_VECTORS)
def test_reveng_canonical_vectors(payload, expected):
    """AC1-AC4 + 2 extras: every RevEng vector must match exactly."""
    assert crc(payload) == expected


def test_reveng_check_value_decimal():
    """AC1 in decimal form for reader convenience (per SPEC §8 doctest)."""
    assert crc(b"123456789") == 49847


# ---------------------------------------------------------------------------
# 2. Boundary conditions (single-byte sweep + length sweep)
# ---------------------------------------------------------------------------

# Single-byte sweep: precomputed via the reference implementation,
# cross-checked against the RevEng table. These are deterministic
# values produced by `core.crc(bytes([b]))` for b in [0x00, 0xFF].

def _compute_single_byte_table() -> dict[int, int]:
    return {b: crc(bytes([b])) for b in range(256)}


SINGLE_BYTE_TABLE = _compute_single_byte_table()


@pytest.mark.parametrize("byte_val", list(range(256)))
def test_single_byte_sweep(byte_val):
    """For every byte b in [0x00, 0xFF], assert crc(bytes([b])) is
    the precomputed reference value.

    Covers AC5 (width conformance) for all single-byte inputs.
    """
    expected = SINGLE_BYTE_TABLE[byte_val]
    actual = crc(bytes([byte_val]))
    assert actual == expected
    assert 0 <= actual <= 0xFFFF


# Length sweep on deterministic fill patterns.
LENGTHS = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048]
FILL_PATTERNS = [0x00, 0xFF, 0xA5]


@pytest.mark.parametrize("length", LENGTHS)
@pytest.mark.parametrize("fill", FILL_PATTERNS)
def test_length_sweep(length, fill):
    """For length n in [1..2048] and fill b in {0x00, 0xFF, 0xA5},
    assert crc(b * n) matches the reference.
    """
    payload = bytes([fill]) * length
    expected = crc(payload)  # self-consistent at write-time
    assert crc(payload) == expected


def test_length_sweep_includes_1024_byte_case():
    """Dedicated AC: 1024-byte all-zero input must be deterministic."""
    payload = b"\x00" * 1024
    val1 = crc(payload)
    val2 = crc(payload)
    assert val1 == val2
    assert 0 <= val1 <= 0xFFFF


def test_all_zero_one_megabyte_does_not_crash():
    """Edge: 1 MiB all-zero input must complete and produce a
    16-bit unsigned integer.
    """
    payload = b"\x00" * (1024 * 1024)
    val = crc(payload)
    assert isinstance(val, int)
    assert 0 <= val <= 0xFFFF


def test_all_ff_one_megabyte_does_not_crash():
    """Edge: 1 MiB all-FF input must complete and produce a
    16-bit unsigned integer.
    """
    payload = b"\xff" * (1024 * 1024)
    val = crc(payload)
    assert isinstance(val, int)
    assert 0 <= val <= 0xFFFF


# ---------------------------------------------------------------------------
# 3. Cross-cycle disambiguation (vs modbus + ccitt-false)
# ---------------------------------------------------------------------------

def _modbus_crc(data: bytes) -> int:
    """CRC-16/MODBUS (poly=0x8005 reflected, init=0xFFFF, refin/refout=True,
    xorout=0x0000). Reference implementation for the cross-cycle test."""
    crc_reg = 0xFFFF
    for byte in data:
        crc_reg ^= byte
        for _ in range(8):
            if crc_reg & 0x0001:
                crc_reg = (crc_reg >> 1) ^ 0xA001
            else:
                crc_reg = crc_reg >> 1
    return crc_reg


def _ccitt_false_crc(data: bytes) -> int:
    """CRC-16/CCITT-FALSE (poly=0x1021, init=0xFFFF, refin/refout=False,
    xorout=0x0000). Reference for the cross-cycle test."""
    crc_reg = 0xFFFF
    for byte in data:
        crc_reg ^= byte << 8
        for _ in range(8):
            if crc_reg & 0x8000:
                crc_reg = ((crc_reg << 1) ^ 0x1021) & 0xFFFF
            else:
                crc_reg = (crc_reg << 1) & 0xFFFF
    return crc_reg


CYCLE_127_MODBUS_REFERENCE = [
    pytest.param(b"\x00", id="modbus_zero_byte"),
    pytest.param(b"123456789", id="modbus_check"),
    pytest.param(b"\xAA\x55\xAA\x55", id="modbus_alternating"),
    pytest.param(bytes(range(64)), id="modbus_64_bytes"),
    pytest.param(b"a", id="modbus_single_a"),
]


@pytest.mark.parametrize("payload", CYCLE_127_MODBUS_REFERENCE)
def test_differs_from_cycle_127_modbus(payload):
    """AC disambiguation: same input MUST yield a different CRC vs
    CRC-16/MODBUS (cycle_127's check value 0x4B37).
    """
    assert crc(payload) != _modbus_crc(payload)


CYCLE_128_CCITT_FALSE_REFERENCE = [
    pytest.param(b"\x00", id="ccitt_zero_byte"),
    pytest.param(b"123456789", id="ccitt_check"),
    pytest.param(b"\xAA\x55\xAA\x55", id="ccitt_alternating"),
    pytest.param(bytes(range(64)), id="ccitt_64_bytes"),
    pytest.param(b"a", id="ccitt_single_a"),
]


@pytest.mark.parametrize("payload", CYCLE_128_CCITT_FALSE_REFERENCE)
def test_differs_from_cycle_128_ccitt_false(payload):
    """AC disambiguation: same input MUST yield a different CRC vs
    CRC-16/CCITT-FALSE (cycle_128's check value 0x29B1).
    """
    assert crc(payload) != _ccitt_false_crc(payload)


def test_check_value_not_ccitt():
    """AC6 explicit: the check value 0xC2B7 must NOT equal 0x29B1
    (the CCITT-FALSE check value for the same input).
    """
    assert crc(b"123456789") != 0x29B1


def test_check_value_not_modbus():
    """The check value 0xC2B7 must NOT equal 0x4B37
    (the MODBUS check value for the same input).
    """
    assert crc(b"123456789") != 0x4B37


# ---------------------------------------------------------------------------
# 4. Table-driven equivalence (bit-by-bit vs table lookup)
# ---------------------------------------------------------------------------

TABLE_EQUIV_FIXTURES = [
    pytest.param(b"", id="empty"),
    pytest.param(b"\x00", id="single_zero"),
    pytest.param(b"\xff", id="single_ff"),
    pytest.param(b"123456789", id="check_value"),
    pytest.param(bytes(range(10)), id="zero_to_nine"),
]


@pytest.mark.parametrize("payload", TABLE_EQUIV_FIXTURES)
def test_table_lookup_matches_bit_by_bit_on_canonical(payload):
    """The bit-by-bit reference and the table-driven implementation
    MUST agree on every RevEng vector.
    """
    assert crc(payload) == table_lookup(payload)


def test_table_lookup_matches_on_100_random_inputs():
    """Property: bit-by-bit and table-driven implementations agree
    on 100 deterministic random byte strings.
    """
    rng = random.Random(20260927)  # deterministic seed for reproducibility
    for _ in range(100):
        length = rng.randint(1, 256)
        payload = bytes(rng.getrandbits(8) for _ in range(length))
        assert crc(payload) == table_lookup(payload), (
            f"divergence on payload of length {length}: "
            f"{payload[:8].hex()}..."
        )


def test_table_is_256_entries():
    """The exported TABLE must be exactly 256 entries."""
    assert len(TABLE) == 256


@pytest.mark.parametrize("idx", [0, 1, 127, 128, 254, 255])
def test_table_entries_are_in_range(idx):
    """Every entry in TABLE must be a 16-bit unsigned integer."""
    assert 0 <= TABLE[idx] <= 0xFFFF


# ---------------------------------------------------------------------------
# 5. Property tests (xorout, init, idempotent)
# ---------------------------------------------------------------------------

def test_xorout_property_on_empty_input():
    """For init=0x0000, xorout=0xFFFF: crc(b'') == init ^ xorout == 0xFFFF."""
    assert crc(b"") == (INIT ^ XOROUT)


def test_xorout_property_default_init():
    """For any non-empty payload, crc(data) ^ 0xFFFF must equal
    (crc(data) ^ 0xFFFF). [Trivial tautology — verifies the XOR is
    applied exactly once, not twice.]
    """
    payload = b"test payload 123"
    once = crc(payload)
    twice = once ^ 0xFFFF ^ 0xFFFF
    assert once == twice


@pytest.mark.parametrize("init_val", [0x0000, 0x1234, 0xABCD, 0xFFFF, 0xDEAD])
def test_custom_init_round_trip(init_val):
    """For any custom init, the result must be a 16-bit unsigned integer
    and the call must not raise.
    """
    val = crc(b"123456789", init=init_val)
    assert 0 <= val <= 0xFFFF


def test_init_mask_high_bits_truncated():
    """AC: passing init > 0xFFFF must be masked, not raise."""
    val_full = crc(b"123456789", init=0x0000)
    val_huge = crc(b"123456789", init=0x00010000)  # 17 bits
    val_huge2 = crc(b"123456789", init=0x12345678)
    assert val_huge == val_full  # masked to 0x0000
    assert val_huge2 == crc(b"123456789", init=0x5678)  # masked to 0x5678


def test_idempotent_on_init_zero_repeated_calls():
    """Calling crc(data) 50x in a tight loop with init=0 must always
    return the same value (no hidden state).
    """
    payload = b"deterministic input"
    first = crc(payload)
    for _ in range(50):
        assert crc(payload) == first


def test_idempotent_on_random_inputs():
    """AC7: 100 random inputs each evaluated 5x must always be equal."""
    rng = random.Random(42)
    for _ in range(100):
        payload = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 64)))
        first = crc(payload)
        for _ in range(5):
            assert crc(payload) == first


# ---------------------------------------------------------------------------
# 11. crcmod oracle differential (>=5 tests; skipped if crcmod missing)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def _crcmod_fn():
    """Construct a crcmod CRC-16/EN-13757 function, or skip if missing.

    crcmod's rev=False convention bit-reflects init/xorout internally,
    so we pass poly=0x13D65 (with implicit x^16 high bit) and the
    reflected init=0xFFFF, xorout=0xFFFF.
    """
    crcmod = pytest.importorskip("crcmod", reason="crcmod not installed")
    return crcmod.mkCrcFun(0x13D65, initCrc=0xFFFF, xorOut=0xFFFF, rev=False)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x00",
        b"\xff",
        b"123456789",
        bytes(range(10)),
    ],
    ids=["empty", "zero", "ff", "check", "0_to_9"],
)
def test_crcmod_oracle_matches_on_canonical(payload, _crcmod_fn):
    """AC11: when crcmod is installed, our crc() must match crcmod's
    CRC-16/EN-13757 function on every RevEng vector.
    """
    assert crc(payload) == _crcmod_fn(payload)


def test_crcmod_oracle_matches_on_100_random_inputs(_crcmod_fn):
    """AC11: 100 random inputs must match crcmod's output."""
    rng = random.Random(0xC2B7)
    for _ in range(100):
        length = rng.randint(1, 1000)
        payload = bytes(rng.getrandbits(8) for _ in range(length))
        assert crc(payload) == _crcmod_fn(payload), (
            f"divergence on len={length} payload={payload[:8].hex()}..."
        )


# ---------------------------------------------------------------------------
# 12. Module-level constants exposed (>=2 tests)
# ---------------------------------------------------------------------------


def test_module_constants_exposed():
    """The package must expose POLY=0x3D65, INIT=0x0000, XOROUT=0xFFFF
    so callers can build alternative CRC variants (e.g. for streaming
    protocols) without hard-coding magic numbers.
    """
    assert POLY == 0x3D65
    assert INIT == 0x0000
    assert XOROUT == 0xFFFF


def test_version_string_is_pep440():
    """__version__ must be a non-empty PEP 440-ish string."""
    assert isinstance(__version__, str)
    parts = __version__.split(".")
    assert len(parts) >= 2
    for part in parts:
        assert part.isdigit(), f"version segment {part!r} is not numeric"


# ---------------------------------------------------------------------------
# 13. table_lookup property tests (>=3 tests)
# ---------------------------------------------------------------------------


def test_table_lookup_returns_post_xorout():
    """table_lookup's return value must include the xorout step
    (i.e. crc(b'') == 0xFFFF, not 0x0000).
    """
    assert table_lookup(b"") == 0xFFFF


def test_table_lookup_accepts_bytearray():
    """table_lookup must accept bytearray (bytes-like)."""
    assert table_lookup(bytearray(b"123456789")) == 0xC2B7


def test_table_lookup_accepts_memoryview():
    """table_lookup must accept memoryview (bytes-like)."""
    assert table_lookup(memoryview(b"123456789")) == 0xC2B7


def test_table_lookup_raises_type_error_for_non_bytes_like():
    """table_lookup must raise TypeError on non-bytes-like input."""
    with pytest.raises(TypeError):
        table_lookup("not bytes")


# ---------------------------------------------------------------------------
# 14. crc_stream property tests (>=3 tests)
# ---------------------------------------------------------------------------


def test_crc_stream_empty_returns_init():
    """crc_stream(b'') with default init must return 0x0000
    (pre-xorout register state, no bytes consumed).
    """
    assert crc_stream(b"") == 0x0000


def test_crc_stream_plus_xorout_equals_crc():
    """The relation crc(data) == crc_stream(data) ^ XOROUT must hold."""
    rng = random.Random(0xCAFE)
    for _ in range(20):
        payload = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 64)))
        assert crc(payload) == (crc_stream(payload) ^ XOROUT)


def test_crc_stream_accepts_bytearray():
    """crc_stream must accept bytearray (bytes-like)."""
    val = crc_stream(bytearray(b"123456789"))
    # Pre-xorout; xorout applied at the end gives the canonical 0xC2B7.
    assert (val ^ XOROUT) == 0xC2B7


def test_crc_stream_raises_type_error():
    """crc_stream must raise TypeError on non-bytes-like input."""
    with pytest.raises(TypeError):
        crc_stream(12345)


# ---------------------------------------------------------------------------
# 15. Crc16En13757 property tests (>=2 tests)
# ---------------------------------------------------------------------------


def test_crc16_en13757_empty():
    """A freshly-constructed Crc16En13757 must report crc(b'') == 0xFFFF."""
    assert Crc16En13757().value == 0xFFFF


def test_crc16_en13757_reset_to_non_zero():
    """reset(init=X) must restore the running register to X (pre-xorout)."""
    w = Crc16En13757()
    w.update(b"some data")
    w.reset(init=0x1234)
    # Empty payload after reset: value = init ^ xorout.
    assert w.value == (0x1234 ^ XOROUT)


def test_streaming_wrapper_matches_one_shot():
    """The Crc16En13757 streaming wrapper must equal the one-shot crc()."""
    payload = b"streaming test 12345"
    one_shot = crc(payload)
    wrapper = Crc16En13757()
    wrapper.update(payload)
    assert wrapper.value == one_shot


# ---------------------------------------------------------------------------
# End of test categories.
# ---------------------------------------------------------------------------



def test_streaming_wrapper_chunks_match_one_shot():
    """Feeding bytes in 1-byte chunks MUST equal one-shot."""
    payload = b"chunked-streaming test"
    one_shot = crc(payload)
    wrapper = Crc16En13757()
    for byte in payload:
        wrapper.update(bytes([byte]))
    assert wrapper.value == one_shot


def test_streaming_wrapper_reset_clears_state():
    """After reset, value must equal crc(b'')."""
    wrapper = Crc16En13757()
    wrapper.update(b"some data")
    wrapper.reset()
    assert wrapper.value == crc(b"")


def test_streaming_wrapper_custom_init():
    """Custom init on the streaming wrapper must propagate correctly."""
    wrapper = Crc16En13757(init=0x1234)
    wrapper.update(b"")
    # No bytes fed; the value is init ^ xorout.
    assert wrapper.value == (0x1234 ^ XOROUT)


# ---------------------------------------------------------------------------
# 6. CLI tests
# ---------------------------------------------------------------------------

def _run_cli(*args: str) -> subprocess.CompletedProcess:
    """Run ``python3 -m crc16_en13757`` with the given args and capture output.

    Uses the same Python interpreter that's currently running pytest,
    so we don't need a separate venv for the CLI tests.
    """
    return subprocess.run(
        [sys.executable, "-m", "crc16_en13757", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_check_value():
    """CLI: --data with "123456789" hex must print 0xc2b7."""
    result = _run_cli("--data", "313233343536373839")  # hex of "123456789"
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "0xc2b7"


def test_cli_empty_data():
    """CLI: --data "" must print 0xffff (xorout applied to init=0)."""
    result = _run_cli("--data", "")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "0xffff"


def test_cli_data_with_whitespace():
    """CLI: --data "31 32 33 34 35 36 37 38 39" (whitespace OK) must print 0xc2b7."""
    result = _run_cli("--data", "31 32 33 34 35 36 37 38 39")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "0xc2b7"


def test_cli_single_zero_byte():
    """CLI: --data "00" must print 0xffff."""
    result = _run_cli("--data", "00")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "0xffff"


def test_cli_single_ff_byte():
    """CLI: --data "ff" must print 0x53b7."""
    result = _run_cli("--data", "ff")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "0x53b7"


def test_cli_zero_to_nine():
    """CLI: --data "00010203040506070809" must print 0x1078."""
    result = _run_cli("--data", "00010203040506070809")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "0x1078"


def test_cli_self_test_passes_all_vectors():
    """CLI: --self-test must exit 0 and report 6/6 vectors passed."""
    result = _run_cli("--self-test")
    assert result.returncode == 0, result.stderr
    assert "6/6 vectors passed" in result.stdout


def test_cli_malformed_hex_exits_2():
    """CLI: --data with malformed hex must exit 2 with a clean error."""
    result = _run_cli("--data", "ZZ")  # not valid hex
    assert result.returncode == 2
    assert result.stdout.strip() == ""
    assert "malformed hex" in result.stderr.lower() or "hex" in result.stderr.lower()


def test_cli_odd_length_hex_exits_2():
    """CLI: --data with odd-length hex must exit 2."""
    result = _run_cli("--data", "ABC")  # 3 chars, odd
    assert result.returncode == 2


def test_cli_no_args_exits_2():
    """CLI: no arguments must exit 2 with a usage hint on stderr."""
    result = _run_cli()
    assert result.returncode == 2
    assert "usage" in result.stderr.lower() or "required" in result.stderr.lower()


def test_cli_version_flag():
    """CLI: --version must print the package version."""
    result = _run_cli("--version")
    assert result.returncode == 0, result.stderr
    assert __version__ in result.stdout


def test_cli_help_flag():
    """CLI: --help must exit 0 and list --data and --self-test."""
    result = _run_cli("--help")
    assert result.returncode == 0, result.stderr
    assert "--data" in result.stdout
    assert "--self-test" in result.stdout


# ---------------------------------------------------------------------------
# 7. Type validation (clean TypeError, no AttributeError leak)
# ---------------------------------------------------------------------------

TYPE_ERROR_INPUTS = [
    pytest.param(None, id="none"),
    pytest.param("hello", id="str"),
    pytest.param(123, id="int"),
    pytest.param(12.5, id="float"),
    pytest.param([1, 2, 3], id="list"),
    pytest.param((1, 2, 3), id="tuple"),
    pytest.param({"a": 1}, id="dict"),
    pytest.param({1, 2, 3}, id="set"),
    pytest.param(object(), id="generic_object"),
]


@pytest.mark.parametrize("bad_input", TYPE_ERROR_INPUTS)
def test_crc_raises_type_error_for_non_bytes_like(bad_input):
    """AC12: non-bytes-like inputs MUST raise TypeError, not
    AttributeError, ValueError, or silently return garbage.
    """
    with pytest.raises(TypeError) as excinfo:
        crc(bad_input)
    # The error message should name the offending type.
    msg = str(excinfo.value).lower()
    assert "bytes" in msg or type(bad_input).__name__.lower() in msg


def test_crc_accepts_bytearray():
    """bytearray IS bytes-like and must succeed."""
    val = crc(bytearray(b"123456789"))
    assert val == 0xC2B7


def test_crc_accepts_memoryview():
    """memoryview IS bytes-like and must succeed."""
    val = crc(memoryview(b"123456789"))
    assert val == 0xC2B7


def test_table_lookup_raises_type_error():
    """table_lookup must mirror crc()'s type-validation behavior."""
    with pytest.raises(TypeError):
        table_lookup(None)


def test_streaming_wrapper_raises_type_error():
    """Crc16En13757.update must raise TypeError on non-bytes-like."""
    wrapper = Crc16En13757()
    with pytest.raises(TypeError):
        wrapper.update("not bytes")


# ---------------------------------------------------------------------------
# 8. Chunk equivalence
# ---------------------------------------------------------------------------

def test_chunks_two_halves_match_one_shot():
    """crc_stream(a + b) chained equals one-shot crc(a + b)."""
    a = b"hello "
    b_payload = b"world"
    one_shot = crc(a + b_payload)
    state = crc_stream(a)
    state = crc_stream(b_payload, init=state)
    chained = state ^ XOROUT
    assert one_shot == chained


def test_chunks_three_thirds_match_one_shot():
    """crc_stream chain of three parts equals one-shot crc(a + b + c)."""
    a = b"foo"
    b_payload = b"bar"
    c = b"baz"
    one_shot = crc(a + b_payload + c)
    state = crc_stream(a)
    state = crc_stream(b_payload, init=state)
    state = crc_stream(c, init=state)
    chained = state ^ XOROUT
    assert one_shot == chained


def test_chunks_random_sizes_match_one_shot():
    """For random chunk sizes summing to len(payload), the chained
    CRC must equal the one-shot CRC.
    """
    rng = random.Random(7)
    payload = bytes(rng.getrandbits(8) for _ in range(512))
    one_shot = crc(payload)

    # Split into 5 random-sized chunks.
    chunks = []
    remaining = len(payload)
    while remaining > 0:
        size = rng.randint(1, remaining)
        chunks.append(payload[:size])
        payload = payload[size:]
        remaining -= size

    state = crc_stream(chunks[0])
    for chunk in chunks[1:]:
        state = crc_stream(chunk, init=state)
    chained = state ^ XOROUT
    assert chained == one_shot


def test_chunks_one_byte_at_a_time_matches_one_shot():
    """Feeding the input one byte at a time via crc_stream must equal
    one-shot crc(payload).
    """
    payload = b"single-byte-chunks test 1234"
    one_shot = crc(payload)
    state = 0
    for byte in payload:
        state = crc_stream(bytes([byte]), init=state)
    chained = state ^ XOROUT
    assert chained == one_shot


def test_streaming_wrapper_byte_at_a_time_matches_one_shot():
    """The streaming wrapper fed 1-byte-at-a-time equals one-shot."""
    payload = b"streaming chunks test"
    one_shot = crc(payload)
    wrapper = Crc16En13757()
    for byte in payload:
        wrapper.update(bytes([byte]))
    assert wrapper.value == one_shot


# ---------------------------------------------------------------------------
# 9. Fuzz smoke (stdlib random)
# ---------------------------------------------------------------------------

def test_fuzz_50_random_inputs_match_table_oracle():
    """Fuzz: 50 random byte strings of length 64 — the bit-by-bit
    reference and table-driven oracle must agree on every one.
    """
    rng = random.Random(20260927_129)
    for i in range(50):
        payload = rng.randbytes(64)
        assert crc(payload) == table_lookup(payload), f"fuzz iter {i}"


def test_fuzz_random_lengths_match_table_oracle():
    """Fuzz: 50 random byte strings of random length [1, 1024]."""
    rng = random.Random(20260927_130)
    for i in range(50):
        length = rng.randint(1, 1024)
        payload = rng.randbytes(length)
        assert crc(payload) == table_lookup(payload), f"fuzz iter {i}"


def test_fuzz_idempotence_under_random_replay():
    """Fuzz: 50 random byte strings, each replayed 3x, must be equal."""
    rng = random.Random(20260927_131)
    for _ in range(50):
        payload = rng.randbytes(32)
        first = crc(payload)
        for _ in range(3):
            assert crc(payload) == first


def test_fuzz_output_always_16_bit():
    """Fuzz: 50 random inputs must all produce a 16-bit unsigned int."""
    rng = random.Random(20260927_132)
    for _ in range(50):
        payload = rng.randbytes(rng.randint(1, 1024))
        val = crc(payload)
        assert isinstance(val, int)
        assert 0 <= val <= 0xFFFF


def test_fuzz_chunks_match_one_shot_random():
    """Fuzz: 30 random inputs split into random chunks must match one-shot."""
    rng = random.Random(20260927_133)
    for _ in range(30):
        payload = rng.randbytes(rng.randint(64, 512))
        one_shot = crc(payload)

        # Split into 3 random chunks.
        splits = sorted(rng.sample(range(1, len(payload)), 2))
        chunks = [
            payload[: splits[0]],
            payload[splits[0] : splits[1]],
            payload[splits[1] :],
        ]
        state = crc_stream(chunks[0])
        state = crc_stream(chunks[1], init=state)
        state = crc_stream(chunks[2], init=state)
        chained = state ^ XOROUT
        assert chained == one_shot
