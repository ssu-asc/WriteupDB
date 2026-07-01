#!/usr/bin/env python3
"""Recover the registration code for Dreamhack Wargame `times`."""

from __future__ import annotations

from struct import pack, unpack


TARGET = bytes.fromhex(
    "660c4c86a62c1c9c1c661c2c9c6ca6cca66c6caca6a6864c"
    "2c46ec8cec468c9c4cecc6664c46864c"
)


def bit_reverse32(value: int) -> int:
    value = ((value << 1) & 0xAAAAAAAA) | ((value >> 1) & 0x55555555)
    value = ((value << 2) & 0xCCCCCCCC) | ((value >> 2) & 0x33333333)
    value = ((value << 4) & 0xF0F0F0F0) | ((value >> 4) & 0x0F0F0F0F)
    value = ((value << 8) & 0xFF00FF00) | ((value >> 8) & 0x00FF00FF)
    return ((value << 16) | (value >> 16)) & 0xFFFFFFFF


def main() -> None:
    out = bytearray()

    for offset in range(0, len(TARGET), 4):
        block = unpack("<I", TARGET[offset : offset + 4])[0]
        out.extend(pack("<I", bit_reverse32(block)))

    print(out.decode())


if __name__ == "__main__":
    main()
