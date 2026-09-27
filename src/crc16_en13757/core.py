"""CRC-16/EN-13757 reference (bit-by-bit, MSB-first).

Reference implementation transcribed from the RevEng CRC catalogue row
for "CRC-16/EN-13757" (Wireless M-Bus / OMS application-layer checksum
per EN 13757-3:2018 §6.2).

Parameters (RevEng canonical row):
    width  = 16
    poly   = 0x3D65    (un-reflected)
    init   = 0x0000
    refin  = False
    refout = False
    xorout = 0xFFFF
    check  = 0xC2B7    (CRC of ASCII "123456789")
"""

from __future__ import annotations

POLY: int = 0x3D65
INIT: int = 0x0000
XOROUT: int = 0xFFFF


def crc(data, init: int = INIT) -> int:
    """Return the CRC-16/EN-13757 of ``data`` (16-bit unsigned int, post-xorout).

    This is the canonical single-shot form: the final register state
    is XORed with xorout (0xFFFF) before being returned.

    For chaining CRCs across multiple blocks of a frame, use
    ``crc_stream`` instead — it returns the pre-xorout register state
    that callers can feed back as ``init``.

    Args:
        data: bytes-like input (bytes, bytearray, or memoryview).
        init: starting register value (default 0x0000). Masked to 16 bits.

    Returns:
        int in [0, 0xFFFF] (post-xorout).

    Raises:
        TypeError: if ``data`` is not a bytes-like object. The error
            message names the offending argument type so callers can
            diagnose without a traceback.

    Conforms to EN 13757-3:2018 §6.2 (Wireless M-Bus / OMS) and the
    RevEng catalogue "CRC-16/EN-13757" entry.
    """
    return _crc_raw(data, init) ^ XOROUT


def _crc_raw(data, init: int = INIT) -> int:
    """Internal register-state helper. Returns the pre-xorout state.

    Exposed (single underscore) for ``crc_stream`` chaining and for the
    table-driven ``table_lookup`` equivalence tests. Callers normally
    use ``crc`` instead, which applies xorout.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"crc() expected bytes-like, got {type(data).__name__}"
        )
    crc_reg = init & 0xFFFF
    for byte in data:
        crc_reg ^= byte << 8
        for _ in range(8):
            if crc_reg & 0x8000:
                crc_reg = ((crc_reg << 1) ^ POLY) & 0xFFFF
            else:
                crc_reg = (crc_reg << 1) & 0xFFFF
    return crc_reg


def crc_stream(data, init: int = INIT) -> int:
    """Stream-friendly CRC for multi-block frames.

    Returns the pre-xorout register state, suitable for chaining:
        state = crc_stream(block1)
        state = crc_stream(block2, init=state)
        final_crc = state ^ XOROUT

    For a single-shot CRC with xorout applied, use ``crc`` instead.

    Raises:
        TypeError: if ``data`` is not a bytes-like object.
    """
    return _crc_raw(data, init)
