import pefile
import struct
import hashlib

# KeygenMe.exe - LYKNCTF 2026 rev/Cr4ck 1
# Username: th3_LYKN_v3nd0r
# License: 7211-57C4-CD96-CC26-5B67
# FLAG: LYKNCTF{k3yg3n_h3ll_s3lfh4sh_4ntidbg_h1dd3n_us3r_2026}

BINARY = "KeygenMe.exe"
KEY_RC4 = b"L0i_Y3u_Kh0_N0i"


def rotl32(x, n):
    x &= 0xFFFFFFFF
    n &= 0x1f
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def u32(x):
    return x & 0xFFFFFFFF


def build_sbox():
    S = list(range(256))
    j = (S[0] + KEY_RC4[0]) & 0xff
    S[0], S[j] = S[j], S[0]
    prev_j = j
    for i in range(1, 256):
        Si = S[i]
        new_j = (KEY_RC4[i % len(KEY_RC4)] + Si + prev_j) & 0xff
        S[i], S[new_j] = S[new_j], S[i]
        prev_j = new_j
    return S


def rva_to_data(pe, rva, size):
    for section in pe.sections:
        if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
            offset = rva - section.VirtualAddress
            return section.get_data()[offset:offset + size]
    return None


def compute_expected_username(pe):
    S = build_sbox()
    DAT_1400063f0 = struct.unpack('<Q', rva_to_data(pe, 0x63f0, 8))[0]
    DAT_140006260 = list(rva_to_data(pe, 0x6260, 16))

    concat_val = 0
    for b in [S[0x42], S[0x3d], S[0x38], S[0x33], S[0x2e], S[0x29], S[0x24], S[0x1f]]:
        concat_val = (concat_val << 8) | b
    xored = DAT_1400063f0 ^ concat_val
    username_bytes = list(struct.pack('<Q', xored))

    pcVar3_offset = 0
    for lVar2 in range(8, 15):
        username_bytes.append(DAT_140006260[lVar2] ^ S[pcVar3_offset + 0x47])
        pcVar3_offset += 5

    try:
        username_bytes = username_bytes[:username_bytes.index(0)]
    except ValueError:
        pass
    return bytes(username_bytes)


def compute_license_key(username_bytes):
    S = build_sbox()
    uVar2 = 0xa5a5f00d
    uVar8 = 0xae054fb9
    uVar10 = 0x43544632
    uVar5 = u32(0x4c594b4e)  # debug_flag=0

    iVar11 = 0
    while iVar11 != 0x15:
        for byte_val in username_bytes:
            idx = (byte_val + iVar11) & 0xff
            uVar9 = S[idx]
            iVar7 = u32(uVar10)
            uVar1 = rotl32(u32(uVar5) ^ uVar9, 5)
            uVar5 = u32(uVar1 + iVar7)
            uVar1 = rotl32(u32(uVar9 + iVar7), 0xb)
            uVar10 = u32(uVar1 ^ u32(uVar8))
            uVar1 = rotl32(u32(uVar9 * 0x9e3779b1) ^ u32(uVar8), 0x11)
            uVar8 = u32(uVar1 + uVar2)
            uVar2 = rotl32(u32(S[u32(uVar5) & 0xff] + uVar2), 3)
            uVar2 = u32(uVar2 ^ u32(uVar5))
        iVar11 += 7

    for _ in range(4):
        iVar7 = u32(uVar8)
        uVar6 = u32(uVar10)
        uVar1 = u32(u32(uVar5) + uVar2)
        uVar5 = uVar1
        uVar1 = rotl32(uVar1, 7)
        uVar10 = u32(uVar6 ^ uVar1)
        uVar1 = u32(iVar7 + (uVar6 ^ uVar1))
        uVar8 = uVar1
        uVar1 = rotl32(uVar1, 0xd)
        uVar2 = u32(uVar2 ^ uVar1)

    a, b, c, d = u32(uVar5), u32(uVar10), u32(uVar8), u32(uVar2)
    local_38 = (((a ^ b) << 32) | (a >> 16)) & 0xffffffffffff
    uStack_30 = (((d ^ c) << 32) | (b >> 16)) & 0xffffffffffff
    local_28 = ((a >> 16) + (b >> 16) + ((a ^ b) & 0xffff) + ((d ^ c) & 0xffff) ^ (c >> 16)) & 0xffff
    mem = struct.pack('<QQI', local_38, uStack_30, local_28)
    groups = [struct.unpack_from('<Q', mem.ljust(24, b'\x00'), i * 4)[0] & 0xffff for i in range(5)]
    return '-'.join(f"{g:04X}" for g in groups)


def solve(binary_path):
    pe = pefile.PE(binary_path)

    encrypted_flag = rva_to_data(pe, 0x6280, 0x60)

    for section in pe.sections:
        if section.Name.rstrip(b'\x00') == b'.text':
            text_bytes = section.get_data()[:section.Misc_VirtualSize]
            break

    h_text = hashlib.sha256(text_bytes).digest()
    username = compute_expected_username(pe)
    license_key = compute_license_key(username)

    outer_input = username + b'\x1f' + license_key.encode() + b'\x1f' + h_text + b'\x00'
    H1 = hashlib.sha256(outer_input).digest()

    local_348 = b''.join(hashlib.sha256(H1 + bytes([i, 0, 0, 0])).digest() for i in range(3))

    flag_bytes = bytes(a ^ b for a, b in zip(encrypted_flag, local_348))
    flag = flag_bytes[:flag_bytes.index(0)].decode('ascii')

    print(f"Username:    {username.decode()}")
    print(f"License key: {license_key}")
    print(f"FLAG:        {flag}")
    return flag


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else BINARY
    solve(path)
