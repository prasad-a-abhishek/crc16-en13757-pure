"""CRC-16/EN-13757 -- pure-Python reference implementation."""

from __future__ import annotations

from ._table import TABLE, table_lookup
from .core import INIT, POLY, XOROUT, crc, crc_stream

__version__ = "0.1.0"


class Crc16En13757:
    """Object-oriented streaming wrapper around ``crc_stream``.

    For multi-block frames, call ``update(chunk)`` repeatedly and read
    ``value`` for the running CRC (post-xorout). Resets to init=0x0000
    by default.

    >>> c = Crc16En13757()
    >>> c.update(b"123456789")
    >>> hex(c.value)
    '0xc2b7'
    """

    __slots__ = ("_reg",)

    def __init__(self, init: int = INIT) -> None:
        self._reg: int = init & 0xFFFF

    def update(self, data) -> None:
        """Feed ``data`` (bytes-like) into the running CRC."""
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError(
                f"Crc16En13757.update expected bytes-like, "
                f"got {type(data).__name__}"
            )
        self._reg = crc_stream(data, init=self._reg)

    @property
    def value(self) -> int:
        """Current CRC value (register_state ^ xorout)."""
        return self._reg ^ XOROUT

    def reset(self, init: int = INIT) -> None:
        """Reset the running register to ``init`` (default 0x0000)."""
        self._reg = init & 0xFFFF


__all__ = [
    "crc",
    "crc_stream",
    "table_lookup",
    "Crc16En13757",
    "POLY",
    "INIT",
    "XOROUT",
    "TABLE",
]
