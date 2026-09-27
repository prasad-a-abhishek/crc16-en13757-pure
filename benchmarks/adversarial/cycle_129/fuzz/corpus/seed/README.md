# cycle_129 / Seed corpus

Deterministic (no-PRNG) seed inputs covering:

1. **RevEng canonical** (empty, `b'123456789'`, single-byte cases, 256-byte sweep,
   1000x0xFF, 4 KiB zeros, 1 MiB zeros).
2. **EN-13757 / Wireless M-Bus spec patterns** (4-byte short frame, 16-byte long frame,
   255-byte max-frame, SND-NKE / REQ-UD2 control frames, single-byte ACK 0xE5).
3. **Cross-cycle sibling canonical** (modbus `b'123456789'`, ccitt `b'123456789'`).
4. **Mutation operators** (high-bit flip at every byte position of `b'123456789'`,
   byte insertion of 0x00 at every position, byte deletion of every byte).

Each surface's `corpus/` is symlinked to this directory so all surfaces see
identical inputs.
