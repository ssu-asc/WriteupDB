#!/usr/bin/env python3
"""
baseball - custom-alphabet Base64 solver

The `baseball` binary is a Base64 encoder that reads a 64-char permutation
("table") as its first argument. We are NOT given the table, but we are given
a known plaintext/ciphertext pair (text_in.txt -> text_out.txt) plus the
encoded flag (flag_out.txt).

Aligning the standard Base64 of the known plaintext against text_out lets us
recover the alphabet permutation, which we then apply to decode flag_out.txt.
"""
import base64

STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

pt = open("text_in.txt", "rb").read()
ct = open("text_out.txt").read().strip()
flag_ct = open("flag_out.txt").read().strip()

# Standard base64 of the known plaintext
b64 = base64.b64encode(pt).decode()
assert len(b64) == len(ct), "length mismatch -> not a plain base64 transform"

# Recover mapping: custom_char -> 6-bit index (via standard alphabet position)
inv = {}
for s, c in zip(b64, ct):
    if s == "=" or c == "=":
        continue
    inv[c] = STD.index(s)

# Decode the flag through the recovered alphabet
bits = "".join(format(inv[ch], "06b") for ch in flag_ct if ch != "=")
out = bytearray(int(bits[i:i + 8], 2) for i in range(0, len(bits) - len(bits) % 8, 8))

print("recovered alphabet entries:", len(inv))
print("FLAG: DH{%s}" % out.decode())
