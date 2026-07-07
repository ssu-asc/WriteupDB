#!/usr/bin/env python3
import hashlib
import struct
import sys
from pathlib import Path


IMAGE_BASE_DEFAULT = 0x140000000


def rol32(value, count):
    value &= 0xFFFFFFFF
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def parse_sections(data):
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("not a PE file")

    machine, section_count, _, _, _, opt_size, _ = struct.unpack_from(
        "<HHIIIHH", data, pe_offset + 4
    )
    if machine != 0x8664:
        raise ValueError(f"unexpected machine: 0x{machine:04x}")

    opt_offset = pe_offset + 24
    magic = struct.unpack_from("<H", data, opt_offset)[0]
    if magic != 0x20B:
        raise ValueError(f"unexpected optional header magic: 0x{magic:04x}")

    image_base = struct.unpack_from("<Q", data, opt_offset + 24)[0]
    section_offset = opt_offset + opt_size
    sections = {}
    for i in range(section_count):
        off = section_offset + 40 * i
        name = data[off:off + 8].split(b"\0", 1)[0].decode()
        virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from(
            "<IIII", data, off + 8
        )
        sections[name] = {
            "rva": virtual_address,
            "virtual_size": virtual_size,
            "raw_size": raw_size,
            "raw_ptr": raw_ptr,
        }
    return image_base or IMAGE_BASE_DEFAULT, sections


def section_bytes(data, section):
    raw = data[section["raw_ptr"]:section["raw_ptr"] + section["raw_size"]]
    size = section["virtual_size"]
    if len(raw) < size:
        raw += b"\0" * (size - len(raw))
    return raw[:size]


def read_rva(data, sections, rva, size):
    for section in sections.values():
        start = section["rva"]
        end = start + max(section["virtual_size"], section["raw_size"])
        if start <= rva < end and rva + size <= end:
            offset = section["raw_ptr"] + (rva - start)
            return data[offset:offset + size]
    raise ValueError(f"RVA 0x{rva:x} is not inside a section")


def init_sbox():
    key = b"L0i_Y3u_Kh0_N0i"
    sbox = list(range(256))
    j = (sbox[0] + 0x4C) & 0xFF
    sbox[0], sbox[j] = sbox[j], sbox[0]

    for i in range(1, 256):
        x = sbox[i]
        j = (x + key[i % 15] + j) & 0xFF
        sbox[i], sbox[j] = sbox[j], x

    return sbox


def recover_username(const_6260, qword_63f0):
    sbox = init_sbox()
    rax = 0
    for offset in [0x42, 0x3D, 0x38, 0x33, 0x2E, 0x29, 0x24, 0x1F]:
        rax = (rax << 8) | sbox[offset]

    first = (struct.unpack("<Q", qword_63f0)[0] ^ rax).to_bytes(8, "little")
    rest = bytes(
        const_6260[i] ^ sbox[0x47 + 5 * (i - 8)]
        for i in range(8, 15)
    )
    return (first + rest).decode()


def mix_state(username, debug_mask):
    sbox = init_sbox()
    r12 = 0
    edi = 0xA5A5F00D
    r8 = ((debug_mask & 0xFF) * 0x01010101) ^ 0x4C594B4E
    r9 = 0xAE054FB9
    r11 = 0x43544632

    while True:
        for ch in username:
            r10 = sbox[(ch + r12) & 0xFF]

            eax = rol32(r8 ^ r10, 5)
            r8 = (eax + r11) & 0xFFFFFFFF

            eax = rol32((r10 + r11) & 0xFFFFFFFF, 11)
            r11 = (eax ^ r9) & 0xFFFFFFFF

            eax = rol32(((r10 * 0x9E3779B1) & 0xFFFFFFFF) ^ r9, 17)
            r9 = (eax + edi) & 0xFFFFFFFF

            eax = rol32((sbox[r8 & 0xFF] + edi) & 0xFFFFFFFF, 3)
            edi = (eax ^ r8) & 0xFFFFFFFF

        r12 += 7
        if r12 == 0x15:
            break

    for _ in range(4):
        r8 = (r8 + edi) & 0xFFFFFFFF
        r11 = (r11 ^ rol32(r8, 7)) & 0xFFFFFFFF
        r9 = (r9 + r11) & 0xFFFFFFFF
        edi = (edi ^ rol32(r9, 13)) & 0xFFFFFFFF

    return r8, r11, r9, edi


def make_license(username, debug_mask=0):
    d0, d1, d2, d3 = mix_state(username.encode(), debug_mask)
    w0 = (d0 >> 16) & 0xFFFF
    w1 = (d1 ^ d0) & 0xFFFF
    w2 = (d1 >> 16) & 0xFFFF
    w3 = ((d2 & 0xFFFF) ^ (d3 & 0xFFFF)) & 0xFFFF
    w4 = ((d2 >> 16) ^ ((w0 + w1 + w2 + w3) & 0xFFFF)) & 0xFFFF
    return "-".join(f"{word:04X}" for word in [w0, w1, w2, w3, w4])


def decrypt_flag(data, sections, username, license_key, debug_mask=0):
    text_hash = hashlib.sha256(section_bytes(data, sections[".text"])).digest()
    seed = hashlib.sha256(
        username.encode()
        + b"\x1f"
        + license_key.encode()
        + b"\x1f"
        + text_hash
        + bytes([debug_mask])
    ).digest()

    keystream = b"".join(
        hashlib.sha256(seed + struct.pack("<I", counter)).digest()
        for counter in range(3)
    )
    ciphertext = read_rva(data, sections, 0x6280, 96)
    plaintext = bytes(c ^ k for c, k in zip(ciphertext, keystream))
    flag = plaintext.split(b"\0", 1)[0]
    check = hashlib.sha256(b"LYKN2026" + flag).digest()
    return text_hash, flag.decode(), struct.unpack("<Q", check[:8])[0]


def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} KeygenMe.exe")

    data = Path(sys.argv[1]).read_bytes()
    _, sections = parse_sections(data)

    const_6260 = read_rva(data, sections, 0x6260, 16)
    qword_63f0 = read_rva(data, sections, 0x63F0, 8)
    username = recover_username(const_6260, qword_63f0)
    license_key = make_license(username, debug_mask=0)
    text_hash, flag, check = decrypt_flag(data, sections, username, license_key)

    print(f"username: {username}")
    print(f"license: {license_key}")
    print(f"text_sha256: {text_hash.hex()}")
    print(f"flag: {flag}")
    print(f"check_first8_le: 0x{check:016x}")


if __name__ == "__main__":
    main()
