---
ctf_name: "Dreamhack"
challenge_name: "Simple Crack me"
category: "rev"           # web / pwn / rev / crypto / misc
difficulty: "easy"        # easy / medium / hard / insane
author: "ssong17"
date: "2026-07-28"
points: 20
tags: [태그1, 태그2]
---

# Simple Crack me

## 문제 설명

**Exercise: Simple Crack Me에서 실습하는 문제입니다.**

이 문제는 사용자에게 숫자를 받아 정해진 방법으로 입력값을 검증하여 correct 또는 wrong을 출력하는 프로그램이 주어집니다.

해당 바이너리를 분석하여 correct를 출력하는 10진수 양수 값을 찾으세요!

플래그는 `DH{정답이되는10진수양수값}` 입니다.

예시) 입력값이 `12345678`일 경우 플래그는 `DH{12345678}` 입니다.

- 문제 URL / 파일 등 접속 정보: 첨부 바이너리

## 풀이

### 분석

WSL에서 바이너리를 실행해보니 입력 → 검증 값 형태로 동작하는 것을 확인했다. 바로 Ghidra로 분석을 시작했다.

프로젝트를 만들고 바이너리를 불러온 뒤 자동 분석 옵션을 실행해 디컴파일 결과를 확인했다.

`.rodata` 섹션에서 `Correct`, `Wrong` 문자열을 확인했고, 이 문자열을 출력해주는 함수를 살펴보니 아래와 같은 형태로 이루어져 있었다.

```c
bool FUN_00401ad5(void)
{
  long in_FS_OFFSET;
  bool bVar1;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_14 = 0;
  FUN_0040bb20(&DAT_004b6004,&local_14);
  bVar1 = local_14 != 0x13371337;
  if (bVar1) {
    FUN_0040b990("%x is wrong x(\n",local_14);
  }
  else {
    FUN_0041a400("Correct!");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    FUN_0045a420();
  }
  return bVar1;
}
```

### 취약점

`local_14`에 사용자 입력값을 받아온 뒤, 이 값이 `0x13371337`과 같지 않으면 `Wrong`, 같으면 `Correct`를 출력하는 매우 단순한 비교 로직이었다. 즉 검증 로직이 하드코딩된 단일 상수와의 비교로만 이루어져 있어, 바이너리 분석만으로 정답 값을 바로 알아낼 수 있는 구조였다.

### 익스플로잇

비교 대상 상수 `0x13371337`을 10진수로 변환하면 다음과 같다.

```
0x13371337 = 322376503
```

이 값을 프로그램 실행 시 입력값으로 넣으면 `local_14`가 `0x13371337`과 일치하게 되어 `Correct!`가 출력된다.

## 플래그

```
DH{322376503}
```

## 배운 점

.