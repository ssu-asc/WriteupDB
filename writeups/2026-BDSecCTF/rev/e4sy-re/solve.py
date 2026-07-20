def rol8(x, r):
    r &= 7
    return ((x << r) | (x >> (8 - r))) & 0xFF

def ror8(x, r):
    r &= 7
    return ((x >> r) | (x << (8 - r))) & 0xFF

expected_0 = bytes.fromhex("0c61e46d5a59d8a6721995ad08245a2be3601a2ec78ae00c")
expected_1 = bytes.fromhex("bfe3277645807cf814abe0ca4e6f30318db7c77af0c8d3fcf88d")
expected_2 = bytes.fromhex("2e0e6a0a7609213ad51add7d79210d653d847d84 9159e8fdcdcca8306c".replace(" ",""))
expected_3 = bytes.fromhex("2305791b6cc1840f88b27debao7ef432".replace("o","0") + "")
# rebuild expected_3 carefully
expected_3 = bytes.fromhex(
    "23"+"05"+"79"+"1b"+"6c"+"c1"+"84"+"0f"+"88"+"b2"+"7d"+"eb"+"a0"+"7e"+"f4"+"32"+
    "c6"+"f5"+"70"+"c1"+"c5"+"26"+"bf"+"16"+"dd"+"42"+"36"+"3a"+"6a"+"6a"+"45"+"17"+
    "f4"+"4c"+"cd"+"84"+"ae"+"27"+"8c"+"c8"+"38"
)

print(len(expected_0), len(expected_1), len(expected_2), len(expected_3))

key_part_b_4 = bytes.fromhex("5b75b47bcb5d73e6")
key_part_a_5 = bytes.fromhex("19a4c7526e019bf0")

# --- branch 0x18 (24 bytes) ---
def solve_18():
    out = expected_0
    state = 0x6b
    inp = bytearray(24)
    for i in range(24):
        xorkey = (0x55 + 0x11*i) & 0xFF
        rot_target = out[i]  # = ROL8(state+bVar17,3)
        pre_rotate = ror8(rot_target, 3)
        bVar17 = (pre_rotate - state) & 0xFF
        inp[i] = bVar17 ^ xorkey
        state = out[i]
    return bytes(inp)

# --- branch 0x1a (26 bytes) ---
def solve_1a():
    out = expected_1
    inp = bytearray(26)
    for i in range(26):
        pos = (i*5) % 26
        state = (0x3d + 7*i) & 0xFF
        rot = (i % 5 + 1) & 7
        temp = rol8(out[pos], rot)
        inp[i] = temp ^ state
    return bytes(inp)

# --- branch 0x1d (29 bytes) ---
def solve_1d():
    out = expected_2
    inp = bytearray(29)
    for i in range(29):
        salt = (0x21 + 3*i) & 0xFF
        temp = ror8(out[i] ^ 0xa7, 2)  # since out = ROL8(x,2) => x = ROR8(out,2), but out computed as ROL then result also xored with 0xa7 first? check order
        val = (temp - salt) & 0xFF
        inp[i] = val
    return bytes(inp)

# --- branch 0x29 (41 bytes) ---
def solve_29():
    out = expected_3
    inp = bytearray(41)
    for i in range(41):
        pos = (13*i) % 41
        key_idx = i & 7
        add_val = ((11*i) & 0xFF) ^ 0x23
        rot = (i % 7 + 1) & 7
        pre_add = (out[pos] - add_val) & 0xFF
        xor_byte = ror8(pre_add, rot)
        inp[i] = xor_byte ^ key_part_a_5[key_idx] ^ key_part_b_4[key_idx]
    return bytes(inp)

for name, fn in [("0x18/24", solve_18), ("0x1a/26", solve_1a), ("0x1d/29", solve_1d), ("0x29/41", solve_29)]:
    try:
        r = fn()
        print(name, r)
    except Exception as e:
        print(name, "ERR", e)
