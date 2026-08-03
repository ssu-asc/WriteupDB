#!/usr/bin/env python3
def rol(x, n, bits=8):
    x &= 0xff
    return ((x << n) | (x >> (bits - n))) & 0xff

def ror(x, n, bits=8):
    x &= 0xff
    return ((x >> n) | (x << (bits - n))) & 0xff

# .vault section @ 0x4020c0, 64 bytes total
D = bytes([
    0x4e, 0x52, 0x44, 0x30, 0x01, 0x36, 0x27, 0x00,
    0x37, 0x20, 0xb1, 0xc4, 0x8d, 0xe4, 0xb3, 0x1b,
    0xf6, 0xaf, 0x2b, 0xda, 0xc2, 0x4a, 0x62, 0x5a,
    0x6e, 0x47, 0xaf, 0x17, 0x20, 0x00, 0x00, 0x00,
])
E = bytes([
    0x9b, 0x12, 0xa2, 0x0b, 0xe8, 0xc4, 0xe2, 0xed,
    0xc9, 0x4e, 0x23, 0x58, 0xfb, 0x44, 0xae, 0xe6,
    0x57, 0xe6, 0x74, 0x99, 0x61, 0x5b, 0xdf, 0x0f,
    0x8a, 0x4d, 0xf7, 0x1a, 0xad, 0xe9, 0x85, 0x52,
])

# three target arrays derived from D, used by the three comparison loops
A = [(D[i + 4] ^ ((0xa5 - 9 * i) & 0xff)) & 0xff for i in range(8)]

B = []
for i in range(8):
    c = (D[i + 12] - 11 * i) & 0xff
    B.append(((c - 7) & 0xff) ^ 0x5c)

C = [(ror(D[i + 20], 1) ^ ((0x33 + 4 * i) & 0xff)) & 0xff for i in range(8)]

P = [0] * 24

# check 1 -> recovers P[0:8] from A[]
for i in range(8):
    key = (0x21 + 0xd * i) & 0xff
    add = (3 + 7 * i) & 0xff
    plain = ror(A[i], 1)
    P[i] = ((plain - add) & 0xff) ^ key

# check 2 -> recovers P[8:16] from B[] (needs P[0:8])
for k in range(8):
    key = (0x5a - 3 * k) & 0xff
    lo = (3 + k) & 7
    val = ror(B[k], 2) ^ key
    P[8 + k] = (val - 0x14 - (3 + k) - P[lo]) & 0xff

# check 3 -> recovers P[16:24] from C[] (needs P[8:16])
for m in range(8):
    v = ror(C[m], 3)
    tmp = (v - 0x33 - 5 * m) & 0xff
    P[16 + m] = tmp ^ P[15 - m]

phrase = bytes(P).decode()
print("alignment phrase:", phrase)

# final transform: phrase (cyclic index) XOR-mixed with E[] produces the flag
flag = []
key_byte = 0xa9
add = 0x17
rot_idx = 7
for n in range(32):
    idx = n % 24
    target = E[n] ^ key_byte
    mixed = (P[idx] + add) & 0xff
    rot_src = P[rot_idx % 24]
    fb = mixed ^ target ^ rol(rot_src, 1)
    flag.append(fb & 0xff)
    key_byte = (key_byte - 3) & 0xff
    add = (add + 0x11) & 0xff
    rot_idx += 5

print("flag:", bytes(flag).decode())
