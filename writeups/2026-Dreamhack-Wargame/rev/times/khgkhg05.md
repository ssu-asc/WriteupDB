---
ctf_name: "Dreamhack-Wargame"
challenge_name: "times"
category: "rev"           # web / pwn / rev / crypto / misc
difficulty: "medium"      # easy / medium / hard / insane
author: "khgkhg05"
date: "2026-06-30"
points:
tags: [ELF, PIE, init_array, ptrace, anti-debugging, bit-reversal, srand]
---

# 문제명

times

## 문제 설명

> 주어진 `times` 바이너리에서 올바른 registration code를 찾아 등록에 성공한다.

- 문제 파일: `times`
- 파일 형식: 64-bit Linux ELF PIE, stripped
- 주요 함수: `time`, `srand`, `rand`, `ptrace`, `memcmp`

## 풀이

### 분석

프로그램을 현재 시간에 그대로 실행하면 `main()`까지 도달하지 못하고 다음 메시지만 출력한다.

```text
Not yet !!! Please wait more time.
```

이는 `.init_array`에 등록된 초기화 함수 때문이다. 해당 함수는 `main()`보다 먼저 실행되며, 먼저 현재 시간을 검사한다.

```c
if (time(NULL) <= 0x71ca77ff)
{
    puts("Not yet !!! Please wait more time.");
    exit(0);
}
```

`0x71ca77ff`는 UTC 기준 `2030-06-30 23:59:59`이다. 따라서 현재 시점에는 시간 조건을 우회해야 실제 검증 루틴을 볼 수 있다.

같은 초기화 함수에는 anti-debug 로직도 있다.

```c
ret = ptrace(PTRACE_TRACEME, 0, 0, 0);
word_4048 ^= (ret + 1) * 0x4d2;
```

초기 `word_4048` 값은 `0x04d2`이다. 정상 실행에서는 `ptrace(PTRACE_TRACEME)`가 `0`을 반환하므로 `word_4048 ^= 0x04d2`가 되어 최종 값은 `0`이 된다. 반대로 디버거가 붙은 상태에서는 `ptrace`가 실패해 `-1`을 반환하므로 `(ret + 1) * 0x4d2`가 `0`이 되고, `word_4048`은 원래 값인 `0x04d2`로 남는다.

`main()`의 전체 검증 흐름은 다음과 같다.

```c
input = strdup(argv[1]);
len = strlen(input);

srand(time(NULL));
random_number = rand() + rand();
md5(random_number, table);

for (i = 0; i < len; i++)
    for (j = 0; j < 4; j++)
        input[i] ^= table[(4 * i + j) & 0xf];

for (i = 0; i < len / 2; i++)
    *(uint16_t *)&input[2 * i] ^= word_4048;

srand(time(NULL));
random_number = rand() + rand();
md5(random_number, table);

for (i = 0; i < len; i++)
    for (j = 0; j < 4; j++)
        input[i] ^= table[(4 * i + j) & 0xf];

for (i = 0; i < len / 4; i++)
    *(uint32_t *)&input[4 * i] = bit_reverse32(*(uint32_t *)&input[4 * i]);

if (!memcmp(input, target, 0x29))
    puts("Registration done !");
```

처음 보면 `time()` 기반 난수가 두 번 들어가서 실행 시점 의존처럼 보인다. 하지만 두 `srand(time(NULL))` 호출은 바로 이어서 실행되므로 같은 초 안에서는 같은 seed가 들어간다. 따라서 첫 번째 MD5 table XOR과 두 번째 MD5 table XOR은 서로 상쇄된다.

정상 실행에서는 초기화 함수 때문에 `word_4048`도 `0`이 된다. 결국 실제로 남는 변환은 마지막 32비트 단위 bit-reversal뿐이다.

### `sub_174A`

마지막에 호출되는 `sub_174A()`는 다음과 같은 형태이다.

```c
x = ((x << 1) & 0xaaaaaaaa) | ((x >> 1) & 0x55555555);
x = ((x << 2) & 0xcccccccc) | ((x >> 2) & 0x33333333);
x = ((x << 4) & 0xf0f0f0f0) | ((x >> 4) & 0x0f0f0f0f);
x = ((x << 8) & 0xff00ff00) | ((x >> 8) & 0x00ff00ff);
x = rol32(x, 16);
```

1비트, 2비트, 4비트, 8비트 단위로 차례대로 위치를 바꾼 뒤 16비트 rotate를 수행한다. 즉 32비트 값 전체의 bit order를 뒤집는 함수이다. bit-reversal은 한 번 더 적용하면 원래 값으로 돌아오므로 self-inverse이다.

비교 대상은 `.data`의 `0x4020`부터 시작한다.

```text
66 0c 4c 86 a6 2c 1c 9c 1c 66 1c 2c 9c 6c a6 cc
a6 6c 6c ac a6 a6 86 4c 2c 46 ec 8c ec 46 8c 9c
4c ec c6 66 4c 46 86 4c
```

`memcmp()` 길이는 `0x29`로 41바이트지만, 실제 고정 target은 40바이트이다. 바로 뒤의 1바이트는 `word_4048`의 하위 바이트와 겹친다. 정상 실행에서 `word_4048`가 `0`으로 바뀌므로, 길이 40인 입력의 NUL terminator가 41번째 비교 바이트를 만족한다.

### 익스플로잇

따라서 풀이 방법은 단순하다.

1. `.data`의 고정 target 40바이트를 가져온다.
2. 4바이트 little-endian 블록마다 `bit_reverse32()`를 한 번 더 적용한다.
3. 나온 40바이트 ASCII 문자열을 registration code로 사용한다.

풀이 코드는 다음과 같다.

```python
from struct import pack, unpack

TARGET = bytes.fromhex(
    "660c4c86a62c1c9c1c661c2c9c6ca6cca66c6caca6a6864c"
    "2c46ec8cec468c9c4cecc6664c46864c"
)

def bit_reverse32(value):
    value = ((value << 1) & 0xAAAAAAAA) | ((value >> 1) & 0x55555555)
    value = ((value << 2) & 0xCCCCCCCC) | ((value >> 2) & 0x33333333)
    value = ((value << 4) & 0xF0F0F0F0) | ((value >> 4) & 0x0F0F0F0F)
    value = ((value << 8) & 0xFF00FF00) | ((value >> 8) & 0x00FF00FF)
    return ((value << 16) | (value >> 16)) & 0xFFFFFFFF

out = bytearray()
for offset in range(0, len(TARGET), 4):
    block = unpack("<I", TARGET[offset : offset + 4])[0]
    out.extend(pack("<I", bit_reverse32(block)))

print(out.decode())
```

실행 결과는 다음과 같다.

```text
a20f984e48f83e69566e2aee17b491b7fc722ab2
```

시간 조건 때문에 원본 바이너리를 현재 시간에 그대로 검증할 수는 없다. 원본은 유지하고 `/tmp` 복사본에서 시간 검사 분기 한 바이트만 `jg`에서 `jmp`로 바꿔 검증했다.

```text
$ /tmp/times_check a20f984e48f83e69566e2aee17b491b7fc722ab2
Welcome to registration center
Registration done !
```

## 플래그

```text
DH{REDACTED}
```

## 추가 파일

| 파일 | 설명 |
|------|------|
| `solve.py` | target 40바이트를 32비트 bit-reversal로 되돌려 registration code를 출력하는 스크립트 |
| `times` | 문제 원본 ELF 바이너리 |

## 배운 점

`.init_array`에 있는 코드는 `main()`보다 먼저 실행되므로, 전역 값이 정적 분석 시점과 런타임에서 달라질 수 있다. 이 문제에서는 `ptrace` 결과에 따라 `word_4048` 값이 달라지고, 정상 실행에서는 오히려 XOR key가 `0`이 된다.

또한 `time()` 기반 난수처럼 보이는 값도 두 번 같은 방식으로 XOR되면 상쇄될 수 있다. 난수 사용 여부만 볼 것이 아니라, 최종 식에서 어떤 항이 실제로 남는지 정리하는 것이 중요하다.
