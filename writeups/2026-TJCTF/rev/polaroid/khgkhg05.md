---
ctf_name: "TJCTF 2026"
challenge_name: "polaroid"
category: "rev"
difficulty: "easy"
author: "khgkhg05"
date: "2026-05-15"
tags: [Mach-O, XOR, image]
---

# polaroid

## 문제 설명

> 문제 설명은 별도로 확인하지 못했다.

- 제공 파일: `polaroid`
- 실행 파일 내부에 암호화된 PNG가 들어 있고, 올바른 비밀번호를 입력하면 `flag.png`가 생성되는 문제다.

## 풀이

IDA로 Decompile한 뒤, 분석을 용이하게 하기 위해 새로운 C 프로그램으로 복원하였다.
해당 파일은 `polaroid.c`이다.

`polaroid.c`를 Linux 환경에서 다시 컴파일한 실행 파일은 `polaroid.exec`이고, 이를 실행하여 생성한 결과 파일은 `flag.png`이다.

### 분석

먼저 `file`로 바이너리 형식을 확인했다.

```bash
$ file polaroid
polaroid: Mach-O 64-bit arm64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>
```

Linux ELF가 아니라 macOS arm64 Mach-O 파일이므로 WSL에서는 원본 파일을 바로 실행하기 어렵다.
따라서 정적 분석으로 주요 로직을 확인하고, 동일한 로직을 `polaroid.c`로 재현하였다.

`strings`를 보면 실행 흐름을 짐작할 수 있는 문자열들이 바로 나온다.

```text
usage: %s <password>
nope
flag.png
developed flag.png
```

즉 프로그램은 인자로 비밀번호를 받고, 틀리면 `nope`를 출력하며, 맞으면 `flag.png`를 생성하는 구조다.

`polaroid.c`에서 핵심 로직은 다음과 같다.

```c
const char *password = argv[1];
int len = strlen(password);

if (len != 17 || memcmp(password, "exposeTheNegative", len)) {
    puts("nope");
    return 1;
}

flag_file = fopen("flag.png", "wb");

for (unsigned long long i = 0; i != 6324; i++)
    fputc(password[(unsigned int)i % 0x11U] ^ encrypted[i], flag_file);

fclose(flag_file);
puts("developed flag.png");
```

비밀번호 검사는 난독화되어 있지 않고, `memcmp` 대상 문자열이 그대로 들어 있다.

```text
exposeTheNegative
```

길이 조건도 `17`이고, `0x11` 역시 17이다.
그러므로 이 문자열이 그대로 PNG 복호화 키로 재사용된다.

### 취약점

이 문제의 핵심은 암호화 방식이 단순 반복 XOR이라는 점이다. 프로그램은 입력한 비밀번호를 검증한 뒤, 동일한 문자열을 17바이트 주기로 반복하면서 내장된 `encrypted` 배열과 XOR한다.

```text
plain[i] = encrypted[i] ^ key[i % 17]
```

게다가 키가 비교 문자열로 바이너리 안에 평문으로 존재한다. 따라서 복잡한 암호 분석 없이 비교 문자열을 찾는 것만으로 복호화 키를 얻을 수 있다.

### 익스플로잇

바이너리에서 확인한 키 `exposeTheNegative`를 사용하면 된다.
원본은 Mach-O arm64라 WSL에서 바로 실행하기 어렵기 때문에, 복원한 `polaroid.c`를 Linux에서 다시 컴파일하여 `polaroid.exec`를 만들었다.

```bash
$ ./polaroid.exec exposeTheNegative
developed flag.png
```

실행 후 생성된 파일을 확인하면 정상적인 PNG 파일이다.

```bash
$ file flag.png
flag.png: PNG image data, 700 x 140, 8-bit/color RGB, non-interlaced

$ sha256sum flag.png
162233858ff8034cdde1c31143a449b5bf92fad1b0475e0969273a4506aa669c  flag.png
```

동일한 동작을 Python으로 쓰면 다음처럼 정리할 수 있다.
`encrypted`에는 바이너리에서 추출한 6324바이트 배열을 넣으면 된다.

이미지를 열면 플래그가 거꾸로 그려져 있다. 180도 돌려서 읽으면 플래그를 얻을 수 있다.

## 플래그

```text
tjctf{REDACTED}
```

## 배운 점

파일 이름과 메시지가 `polaroid`, `developed flag.png`, `exposeTheNegative`처럼 사진 현상 과정을 계속 암시하고 있었다. 리버싱 관점에서는 `strings`로 입출력 문자열과 비교 문자열을 먼저 훑는 것만으로도 전체 구조를 빠르게 잡을 수 있었고, 반복 XOR로 파일을 복호화할 때는 키 길이와 모듈러 인덱싱을 확인하면 재현이 간단해진다는 점을 다시 확인했다.
