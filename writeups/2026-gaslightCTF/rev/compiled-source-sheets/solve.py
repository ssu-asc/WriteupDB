#!/usr/bin/env python3
"""
gaslightCTF 2026 - Compiled Source Sheets (rev)

The challenge ships handout/vm.html, a copy of the "x86CSS" project
(a real 8086 CPU emulator implemented purely in CSS custom properties
and @property/if()/style() features - runs in Chromium only, hence
the "Spectre-proof / race-condition free / runs on every OS[1]" joke).

The emulated machine's RAM is embedded directly in the CSS as a series
of @property --mN { initial-value: X; } declarations (one per byte,
N = memory address). Address 0x100 is where the "program" is loaded
(matches the initial --IP value of 256), so we can just read those
values out with a regex, dump them as a flat binary, and disassemble
it as 16-bit real-mode x86 with capstone.
"""
import re
import capstone

HTML = "challenges/2026-gaslightCTF/rev/handout/vm.html"

def extract_memory():
    text = open(HTML).read()
    pattern = re.compile(
        r'@property --m(\d+)\s*\{\s*syntax:\s*"<integer>";\s*initial-value:\s*(-?\d+);',
        re.S,
    )
    d = {int(i): int(v) for i, v in pattern.findall(text)}
    size = 1536  # 0x600, matches the "0x600 bytes (1.5kB) of memory" note in the page FAQ
    mem = bytearray(size)
    for i in range(size):
        mem[i] = d.get(i, 0) & 0xFF
    return bytes(mem)


def disasm(mem, start=0x100, length=0x1a0):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    for insn in md.disasm(mem[start:start + length], start):
        print(f"{insn.address:04x}: {insn.mnemonic} {insn.op_str}")


def cstr(mem, addr):
    end = mem.index(b"\x00", addr)
    return mem[addr:end]


def solve_buffer():
    """
    The password checker reads up to 10 chars into a stack buffer
    buf[0..9] (bp-10 .. bp-1), requires an even length <= 8, and only
    buf[0..7] are validated - a chain of xor/and/or/cmp checks tying
    pairs of bytes together. Solved by symbolic re-simulation with a
    fixed candidate (found via a small z3 model, byte-per-byte 8-bit
    bitvectors constrained by each check) and verified by literally
    replaying the same instruction sequence in Python.
    """
    buf = b"2QY90H6F"
    b0, b1, b2, b3, b4, b5, b6, b7 = buf

    def m8(x):
        return x & 0xFF

    dl = b6
    ah = b2
    al = m8(dl ^ ah)
    assert al == 0x6F

    dh = b3
    cl = b7
    assert (dh & cl) == 0

    al = m8(dh | cl)
    assert al == 0x7F

    al = m8(dl | dh)
    assert al == 0x3F

    ch = b1
    bl = b5
    al = m8(ch & bl)
    assert al == 0x40

    al = m8(ah ^ bl)
    assert al == 0x11

    al = m8(ah ^ ch)
    assert al == 8

    al = b4
    bh = m8(ch & al)
    assert bh == 0x10

    bh = m8(ah & ch)
    temp = bh
    assert bh == 0x51

    bh = dl
    bh = m8(bh ^ b0)
    assert bh == 4

    bh = cl
    bh = m8(bh | al)
    assert bh == 0x76

    bh = ah
    bh = m8(bh | cl)
    assert bh == 0x5F

    bh = dh
    bh = m8(bh | al)
    assert bh == 0x39

    bl = m8(bl ^ dh)
    assert bl == 0x71

    ch = m8(ch & dl)
    assert ch == 0x10

    cl = m8(cl ^ al)
    assert cl == 0x76

    cl = b0
    ch = dh
    ch = m8(ch & cl)
    assert ch == 0x30

    ch = ah
    ch = m8(ch ^ al)
    assert ch == 0x69

    assert temp == 0x51

    ah = m8(ah | al)
    assert ah == 0x79

    al = m8(al ^ cl)
    assert al == 2

    dl = m8(dl ^ dh)
    assert dl == 0xF

    return buf


if __name__ == "__main__":
    mem = extract_memory()
    disasm(mem)

    parts = [0x30A, 0x313, 0x31C, 0x325]  # "gaslight" "CTF{ch3c" "k_0ut_ly" "ra-horse"
    prefix = b"".join(cstr(mem, a) for a in parts).decode()

    buf = solve_buffer()
    flag = f"{prefix}!!_{buf.decode()}}}"
    print(flag)
