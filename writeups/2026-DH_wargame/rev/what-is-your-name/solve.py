import pefile
import struct
import glob

order = {}
key = {}

for fn in sorted(glob.glob('*.exe')):
    pe = pefile.PE(fn)

    # offset 1109 (0-index 1108) sits in .text, RVA = 0x1000 + (1108 - 0x400)
    rva_order = 0x1000 + (1108 - 0x400)
    n = struct.unpack('<i', pe.get_data(rva_order, 4))[0]

    # offset 113153 (0-index 113152) is the Caesar shift key baked into .data (RVA 0x1d000)
    k = struct.unpack('<i', pe.get_data(0x1d000, 4))[0]

    name = fn.split('.exe')[0]
    order[n] = name
    key[n] = k

flag = ''
for i in range(1, 12):
    name, k = order[i], key[i]
    flag += ''.join(chr(ord(c) + k) for c in name)

print(flag)
