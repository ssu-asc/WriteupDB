#!/usr/bin/env python3
"""
sands_of_nizwa - Clash_of_Cybers_I (rev)

The binary implements an 11-round custom bytecode VM. Each round decodes
its own instruction stream from a fixed 165-byte table (11 rounds x 15
bytes/round) using a "round key" that is only known concretely at round 0
(a fixed constant, since the anti-debug check returns 0 on a normal run).
Every round's decoded instruction sequence depends only on that round's
key (constant for the whole round) -- not on the actual input byte values
-- so for any candidate key value the control flow is fully deterministic
and can be simulated in pure Python. Wrong input bytes almost always
produce an invalid opcode within 1-2 fetches, so a simple backtracking
search (26/95-way branching per newly-read input position) finds the
unique solution almost instantly.
"""

TABLE = bytes.fromhex(
    "1ce4564fd5b4805766084c3edd2c62cee87668b36bdf466ae682f49cb72b114"
    "22da737a3ac989e98ac9473a4ead8ad86925d62c75053b918ab767fdcbcd786"
    "b8bd7cb35773b3c09230f1d3de3bba9c8662f9bca7c5353cbe30fdbde4adff1"
    "8e2628aea70c2f18c838ff41b1d5c5c3dd4f86441860adddcc40d945ae880f2"
    "1b45fd01eb8902302728bad24383b85d805feaa11a05b158c4e27d13ad981cd"
    "39ca3f74f8e3200"
)
assert len(TABLE) == 165

INIT_KEY = 0xC0DEC0DE   # round-0 key when not being ptrace'd (TracerPid == 0)
LEN = 11
NEG_GOLDEN = (-0x61c8864f) & 0xFFFFFFFF
TARGET = 0x47EC6547


def rotl8(v, c):
    c &= 7
    v &= 0xFF
    return ((v << c) | (v >> (8 - c))) & 0xFF if c else v


def rotl32(v, c):
    c &= 0x1F
    v &= 0xFFFFFFFF
    return ((v << c) | (v >> (32 - c))) & 0xFFFFFFFF if c else v


def fetch(round_, pos, key):
    idx = round_ * 15 + pos
    if idx >= len(TABLE):
        return None
    partA = ((round_ * 0x27 + pos * 0x13) & 0xFF) ^ TABLE[idx]
    shift1 = (pos & 3) * 8
    keybyte = (key >> shift1) & 0xFF
    sil_raw = (((0x3D * pos) & 0xFF) + keybyte) & 0xFF
    rot = ((pos % 7) + 1) & 7
    return partA ^ rotl8(sil_raw, rot)


class Fail(Exception):
    pass


class NeedByte(Exception):
    def __init__(self, pos):
        self.pos = pos


def run(input_arr):
    key = INIT_KEY
    ebp_low = 0
    r12 = 0
    flag = 1  # length == 11
    for round_ in range(11):
        r9 = 0
        ebx = key
        while True:
            if r9 > 14:
                raise Fail()
            opcode = fetch(round_, r9, key)
            if opcode is None:
                raise Fail()
            if opcode == 0:
                break
            if opcode not in (0xC3, 0xA1, 0xB2, 0xD4, 0xE5, 0xF6, 0x97):
                raise Fail()
            operand = fetch(round_, r9 + 1, key)
            if operand is None:
                raise Fail()
            if opcode == 0xC3:
                ebp_low = (ebp_low + operand) & 0xFF
            elif opcode == 0xA1:
                pos = operand & 0xFF
                if pos >= LEN:
                    raise Fail()
                r12 = pos
                if input_arr[pos] is None:
                    raise NeedByte(pos)
                ebp_low = input_arr[pos] & 0xFF
            elif opcode == 0xB2:
                shift = (operand & 3) * 8
                ebp_low = (ebp_low ^ ((key >> shift) & 0xFF)) & 0xFF
            elif opcode == 0xD4:
                ebp_low = rotl8(ebp_low, operand & 7)
            elif opcode == 0xE5:
                ebp_low = (ebp_low ^ (operand & 0xFF)) & 0xFF
            elif opcode == 0xF6:
                flag &= int(operand == ebp_low)
            elif opcode == 0x97:
                if input_arr[r12] is None:
                    raise NeedByte(r12)
                inp_byte = input_arr[r12] & 0xFF
                val = (inp_byte * NEG_GOLDEN) & 0xFFFFFFFF
                val ^= (ebp_low * 0x45D9F3B) & 0xFFFFFFFF
                val ^= key
                val ^= operand
                ebx = rotl32(val & 0xFFFFFFFF, (round_ + 3) & 0x1F)
            r9 += 2
        key = ebx & 0xFFFFFFFF
    return (key == TARGET) and bool(flag)


def solve():
    arr = [None] * LEN
    charset = list(range(0x20, 0x7F))

    def backtrack():
        try:
            return run(arr)
        except NeedByte as nb:
            pos = nb.pos
            for c in charset:
                arr[pos] = c
                if backtrack():
                    return True
                arr[pos] = None
            return False
        except Fail:
            return False

    if backtrack():
        return bytes(arr)
    return None


if __name__ == "__main__":
    key = solve()
    print("KEY:", key.decode() if key else None)
