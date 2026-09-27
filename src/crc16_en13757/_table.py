"""256-entry table for table-driven CRC-16/EN-13757.

Used by ``table_lookup`` for benchmarking only; the reference
``core.crc`` uses the bit-by-bit loop.

The table is computed once at import time from the RevEng polynomial
0x3D65 using the standard normal-form (un-reflected, MSB-first) table
generation algorithm.
"""

from __future__ import annotations

from .core import POLY

_TABLE = [
    ((i << 8) ^ 0) & 0xFFFF
    for i in range(256)
]
for i in range(256):
    crc = _TABLE[i]
    for _ in range(8):
        if crc & 0x8000:
            crc = ((crc << 1) ^ POLY) & 0xFFFF
        else:
            crc = (crc << 1) & 0xFFFF
    _TABLE[i] = crc

TABLE: tuple[int, ...] = tuple(_TABLE)
"""256-entry lookup table for CRC-16/EN-13757 (poly=0x3D65)."""


def table_lookup(data, init: int = 0x0000) -> int:
    """Table-driven CRC-16/EN-13757. Identical output to ``core.crc``.

    Provided for benchmarking against the bit-by-bit reference and
    against `crcmod`. NOT the canonical implementation — use
    ``crc16_en13757.crc`` for the contract test.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"table_lookup() expected bytes-like, got {type(data).__name__}"
        )
    crc_reg = init & 0xFFFF
    for byte in data:
        crc_reg = ((crc_reg << 8) ^ TABLE[((crc_reg >> 8) ^ byte) & 0xFF]) & 0xFFFF
    return crc_reg ^ 0xFFFF
