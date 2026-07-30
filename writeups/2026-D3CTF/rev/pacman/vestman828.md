---
ctf_name: "2026-D3CTF"
challenge_name: "pacman"
category: "rev"
difficulty: "medium"
author: "vestman828"
date: "2026-07-26"
tags: [rev]
---

# pacman

## 문제 설명

> 2026-D3CTF의 pacman 문제입니다. Rev입니다.

## 풀이

### 분석

주어진 `pacman.ipa`는 iOS 애플리케이션 패키지입니다. 압축을 풀면 ARM64 Mach-O 실행 파일이 나오며, App Store encryption의 `cryptid`가 0이어서 별도 dumping 없이 정적 분석할 수 있습니다.

겉으로는 Pac-Man 게임에서 10000점을 획득해야 하는 것처럼 보이지만, 실제 플래그 생성 과정은 다음과 같습니다.

1. 게임 상태를 56바이트 snapshot으로 만듭니다.
2. snapshot의 점수, bean 수, 이동 수, 시간과 hash를 검증합니다.
3. 72개 record로 구성된 custom VM을 289단계 실행합니다.
4. VM의 최종 64비트 상태를 RC4 key로 사용합니다.
5. 바이너리에 포함된 40바이트 ciphertext를 복호화합니다.

snapshot 검증 함수는 `score >= 10000`, `score == beans * 10`, `moves >= beans` 등의 조건을 확인합니다. 그러나 입력은 단순한 메모리 구조체이므로 실제 게임을 플레이하는 대신 조건을 만족하는 값을 직접 구성했습니다.

```python
vals64 = [
    0x1111111111111111,
    0x2222222222222222,
    0x3333333333333333,
    10000 * 10_000_000,
]
vals32 = [1000, 10000, 1000, 100, 8, 20]
snapshot = struct.pack("<4Q6I", *vals64, *vals32)
```

VM record는 24바이트이며 tag에 따라 서로 다른 handler가 실행됩니다. 이 처리는 Mach port와 4개의 actor thread로 분산되어 있어 iOS 환경 전체를 재현하기가 번거롭습니다. VM을 Python으로 다시 작성할 경우 32/64비트 truncation이나 구조체 offset을 틀릴 위험도 큽니다.

그래서 Unicorn으로 원본 ARM64 코드를 실행하고, iOS에 의존하는 Mach actor RPC만 로컬 handler 호출로 치환했습니다. `pthread_mutex_*`, `pthread_once`, `mach_absolute_time`, `mach_timebase_info`, `__udivti3`도 필요한 동작만 hook했습니다. 각 actor handler 역시 Python으로 재구현하지 않고 별도 Unicorn instance에서 원본 코드를 실행했습니다.

VM이 terminal 상태에 도달하면 최종 64비트 상태를 little-endian 8바이트 RC4 key로 사용합니다. `0x10000b3a0`에 저장된 40바이트 ciphertext를 복호화하여 플래그를 얻었습니다.

### 익스플로잇

핵심은 Mach-O segment를 Unicorn에 mapping하고 RPC 함수 주소를 hook하여 원본 handler로 dispatch하는 것입니다. 전체 구현은 `solve.py`에 있습니다.

```python
BASE = 0x100000000
STACK = 0x700000000
HEAP = 0x600000000

uc.mem_map(BASE, 0x20000)
uc.mem_write(BASE, macho[:0x14000])
uc.mem_map(STACK, 0x20000)
uc.mem_map(HEAP, 0x20000)

handlers = {
    0x71C3: 0x100005F18,
    0xC4A7: 0x100006100,
    0xA913: 0x100006290,
    0x39E1: 0x100006290,
}

# 검증 조건을 만족하는 snapshot을 직접 전달
snapshot = struct.pack(
    "<4Q6I",
    0x1111111111111111,
    0x2222222222222222,
    0x3333333333333333,
    10000 * 10_000_000,
    1000, 10000, 1000, 100, 8, 20,
)
```

```bash
python3 -m pip install unicorn
python3 solve.py
```

실행하면 VM이 289단계를 완료하고 다음 결과를 출력합니다.

```text
ok: 1
output: b'd3ctf{GoOdjob!!!Y0u_@re_be5t_P4c-Man!!!}'
```

## 플래그

```text
d3ctf{GoOdjob!!!Y0u_@re_be5t_P4c-Man!!!}
```

## 배운 점

플랫폼 전용 IPC와 난독화가 결합된 문제에서는 전체 실행 환경을 재현하는 것보다 핵심 계산을 수행하는 원본 코드만 에뮬레이션하는 편이 효율적입니다. 외부 의존 계층만 hook하면 직접 재구현에서 생기는 미세한 연산 차이도 피할 수 있습니다.
