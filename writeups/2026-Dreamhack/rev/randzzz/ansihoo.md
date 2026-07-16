---
ctf_name: "2026-Dreamhack"
challenge_name: "randzzz"
category: "rev"           # web / pwn / rev / crypto / misc
difficulty: "medium"      # easy / medium / hard / insane
author: "ansihoo"
date: "2026-07-07"
points: 500
tags: [rand, glibc]
---

# 문제명
 - randzzz
## 문제 설명

> rand() 값을 맞추면 플래그를 보여주는 바이너리. zip으로 배포된 ELF 실행 파일(chall) 하나만 주어짐.

- 파일: `chall` (x86-64 PIE, dynamically linked, not stripped)

## 풀이

### 분석

`main()`은 다음 순서로 동작한다.

1. `sleep(1)` 후 "fall asleep from now on." 출력.
2. `rand()` 호출(1번째) 결과 + 1을 `sleep()` 인자로 사용 → `sleep(rand()+1)`.
3. `rand()`를 2번 더 호출하지만 결과를 버림(더미 호출, 페이크).
4. "Can you guess the rand num?: " 출력 후 `scanf("%d", &guess)`로 정수 입력받음.
5. `rand()`(4번째 호출)의 `% 10` 값과 `guess`를 비교, 일치하면 28바이트 배열을 `get_flag(byte, guess)`로 디코딩해 버퍼에 채움.
6. `rand()`(5번째 호출)의 `% 10` 값과 동일한 `guess`를 다시 비교, 일치하면 36바이트 배열을 같은 방식으로 디코딩해 버퍼 뒷부분에 채움.
7. 마지막에 `printf("DH{%s}", buffer)`.

`get_flag(c, key)`:
- `isdigit(c)`이면 고정된 치환(캐스터 시프트형 digit map)을 적용.
- 아니면 `((c >> key) | (c << (8-key)))` 형태의 비트 회전 후, 부호 있는 정수로 봤을 때 음수면 `+0x68` 보정.

### 취약점

- 첫 `sleep(rand()+1)`이 사실상 20억 초(약 57년) 대기라서 실제로 실행해서는 절대 풀 수 없음 → 정적 분석 전용으로 설계된 문제.
- `srand()` 호출이 바이너리 어디에도 없음(임포트 심볼, `.init_array`에도 없음) → glibc `rand()`는 항상 시드 1의 기본 결정론적 시퀀스로 시작. 즉 실제로 실행하지 않아도 `rand()` 값을 100% 예측 가능.
- 두 번의 검증(`rand()%10 == guess`)이 같은 `guess` 값을 재사용하므로 한 번의 실행으로는 두 절반을 동시에 얻을 수 없지만, 정적 분석으로는 각 절반에 필요한 key를 독립적으로 계산해 오프라인 복호화 가능.

### 익스플로잇

1. glibc 기본 시드(시드 미설정 시 시드=1과 동일) `rand()` 시퀀스를 직접 컴파일해 확인:
   `1804289383, 846930886, 1681692777, 1714636915, 1957747793, ...`
2. 4번째 값 `1714636915 % 10 = 5` → 28바이트 배열 복호화 key.
3. 5번째 값 `1957747793 % 10 = 3` → 36바이트 배열 복호화 key.
4. `get_flag`의 실제 기계어(비트 회전 + digit map)를 추출해 Python `mmap` + `ctypes`로 JIT 실행, 원본 바이너리와 동일한 연산을 재현.
5. 각 배열에 해당 key로 `get_flag`를 적용해 두 결과를 이어붙임.

```python
import mmap, ctypes

code = bytes.fromhex(
    "55" "4889e5" "4883ec20" "897dec" "8975e8"
    "8b45e8" "8b55ec" "89c1" "d3ea" "89d0" "8945f8"
    "b808000000" "2b45e8" "8b55ec" "89c1" "d3e2" "89d0" "8945f4"
    "8b45f8" "0b45f4" "8945f0" "837df000" "7908"
    "8b45f0" "83c068" "eb03" "8b45f0" "c9" "c3"
)
m = mmap.mmap(-1, len(code), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
m.write(code)
func = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_int32, ctypes.c_int32)(
    ctypes.addressof(ctypes.c_char.from_buffer(m))
)

digit_map = {0x30:0x36,0x31:0x34,0x32:0x32,0x33:0x30,0x34:0x38,
             0x35:0x36,0x36:0x34,0x37:0x32,0x38:0x30,0x39:0x38}

def get_flag(byte_val, key):
    if 0x30 <= byte_val <= 0x39:
        return digit_map[byte_val]
    sc = byte_val if byte_val < 128 else byte_val - 256
    return func(sc, key) & 0xFF

arr1 = bytes.fromhex("6c394c36392c6c38" "394c4cac38333830" "34cccc4c35303335" "ac376ccc")
arr2 = bytes.fromhex("35130b333838321b" "33231b362323330b" "130b37380b1b3923" "3335333934353833" "36392b38")

out1 = bytes(get_flag(b, 5) for b in arr1)   # rand4 % 10 = 5
out2 = bytes(get_flag(b, 3) for b in arr2)   # rand5 % 10 = 3
print("DH{" + (out1 + out2).decode() + "}")
```

## 플래그

```
DH{c8b48ac08bbe00068ffb6606e2cf6ba0002c0dc4dd0aba20ac8d0608860048e0}
```

## 배운 점

- `srand()`가 없는 바이너리는 `rand()` 시퀀스가 시드=1 기준으로 완전히 결정론적이라 정적 분석만으로 예측 가능하다.
- `sleep()`에 난수를 넣는 트릭은 "실행해서 풀지 말고 분석해서 풀라"는 신호일 수 있다.
- 디스어셈블만으로 애매한 비트 연산(부호 확장, 시프트 보정 등)은 직접 기계어를 추출해 `mmap`+`ctypes`로 JIT 실행하면 수동 계산 실수를 없앨 수 있다.
- 결과 문자열이 "이상하게" 보여도 전부 유효한 hex 문자(0-9a-f)이고 길이가 64면, 그 자체가 정답(해시 형태 플래그)일 가능성을 먼저 의심해야 한다.
