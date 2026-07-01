#!/usr/bin/env python3
"""
SekaiCTF 2026 - Untitled Encore (rev)
Solver: reconstruct valid 40-byte chart by reversing Branch B constraints.
"""
import ctypes
import struct

BINARY = "untitled-encore.exe"

# ─── Extract eBPF .rodata instruction stream ──────────────────────────────────

def extract_instr_stream(data):
    ebpf_off = 0xcf00
    ebpf = data[ebpf_off:ebpf_off+0x2000]
    e_shoff      = struct.unpack_from('<Q', ebpf, 0x28)[0]
    e_shentsize  = struct.unpack_from('<H', ebpf, 0x3a)[0]
    e_shnum      = struct.unpack_from('<H', ebpf, 0x3c)[0]
    e_shstrndx   = struct.unpack_from('<H', ebpf, 0x3e)[0]
    shstr_off    = e_shoff + e_shstrndx * e_shentsize
    shstr_offset = struct.unpack_from('<Q', ebpf, shstr_off + 0x18)[0]
    strtab       = ebpf[shstr_offset:]

    rodata = None
    for i in range(e_shnum):
        sh_off    = e_shoff + i * e_shentsize
        sh_name   = struct.unpack_from('<I', ebpf, sh_off)[0]
        sh_offset = struct.unpack_from('<Q', ebpf, sh_off + 0x18)[0]
        sh_size   = struct.unpack_from('<Q', ebpf, sh_off + 0x20)[0]
        name = strtab[sh_name:strtab.index(b'\x00', sh_name)].decode()
        if name == '.rodata':
            rodata = bytes(ebpf[sh_offset:sh_offset+sh_size])

    # Find 14-byte signature (DAT_14000e6d8) in rodata
    rdata_va, rdata_file = 0x14000e000, 0xc800
    pat = data[rdata_file + (0x14000e6d8 - rdata_va):
               rdata_file + (0x14000e6d8 - rdata_va) + 14]
    pos = rodata.find(pat)
    lVar7 = 14 + pos
    assert rodata[lVar7] == 0x02
    size     = (rodata[lVar7+3] << 8) | rodata[lVar7+2]
    data_off = rodata[lVar7+1] + 3 + (lVar7+1)
    return rodata[data_off:data_off+size]

# ─── Decode one 4-byte group ──────────────────────────────────────────────────

def decode_group(i, stream):
    uVar17 = i * 4
    b = stream[uVar17:uVar17+4]
    c = ctypes.c_int8(uVar17).value
    return (
        (b[0] ^ ctypes.c_uint8(c * 0x11 + 0xa3).value) & 0xff,
        (b[1] ^ ctypes.c_uint8(c * 0x1d + 0x11).value) & 0xff,
        (b[2] ^ ctypes.c_uint8(c * 0x1f + 0x7b).value) & 0xff,
        (b[3] ^ ctypes.c_uint8(c * 0x25 - 0x3b).value) & 0xff,
    )

def rotl32(v, n):
    v &= 0xFFFFFFFF; n &= 31
    return ((v << n) | (v >> (32-n))) & 0xFFFFFFFF

# ─── Compute uVar14 after Branch A (groups 0-11) ─────────────────────────────

def compute_after_branch_a(stream):
    pvVar7 = bytes.fromhex('250039041d6ae57f28000000')
    uVar14 = 0x31c3f00d
    for i in range(12):
        d0, d1, d2, d3 = decode_group(i, stream)
        assert d0 == 0x21 and pvVar7[d1] == d2
        uVar14 = ctypes.c_uint32(((d2 + uVar14) ^ d3) * 0x21 + d1).value
    return uVar14

# ─── Collect Branch B constraints ────────────────────────────────────────────

def collect_branch_b(stream):
    entries = []
    for i in range(12, 32):
        d0, d1, d2, d3 = decode_group(i, stream)
        assert d0 == 0x44
        entries.append((d1, d2, d3))  # (note_idx, d2_exp, d3_exp)
    return entries

# ─── Backtracking solver ──────────────────────────────────────────────────────

def candidates(n, uVar14, d2_exp, d3_exp):
    sVar9 = (n & 7) + 1
    out = []
    for bVar1 in range(3, 17):
        for lane in range(5):
            for kind in range(3):
                bVar15 = (lane - n) & 1
                for bVar16 in range(2):
                    bVar2 = lane | (kind << 3) | (bVar16 << 5) | (bVar15 << 6)
                    val = ctypes.c_uint32(bVar1*0x1f + bVar2*0x11 + uVar14 + n*0x49).value & 0xffff
                    bVar10 = (val >> 8) ^ (val & 0xff)
                    if bVar10 != d2_exp: continue
                    new_h = ctypes.c_uint32((uVar14 ^ val) + ((bVar2 << 8)|bVar1) + bVar10).value
                    new_h = rotl32(new_h, sVar9)
                    if (new_h & 0xff) != d3_exp: continue
                    out.append((bVar2, bVar1, new_h))
    return out

def solve(branch_b, uVar14_init):
    chart = [0] * 40
    def dfs(step, uVar14):
        if step == len(branch_b): return True
        n, d2_exp, d3_exp = branch_b[step]
        for bVar2, bVar1, new_h in candidates(n, uVar14, d2_exp, d3_exp):
            chart[n*2] = bVar2
            chart[n*2+1] = bVar1
            if dfs(step+1, new_h): return True
        return False
    return bytes(chart) if dfs(0, uVar14_init) else None

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    with open(BINARY, 'rb') as f:
        data = f.read()

    stream      = extract_instr_stream(data)
    uVar14_init = compute_after_branch_a(stream)
    branch_b    = collect_branch_b(stream)
    chart       = solve(branch_b, uVar14_init)

    if chart is None:
        print("No solution found.")
        return

    print("Chart:", chart.hex())
    print(f"\nRun:  {BINARY} --check-chart {chart.hex()}")

if __name__ == "__main__":
    main()
