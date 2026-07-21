---
ctf_name: "Dreamhack"
challenge_name: "Simple Patch Me"
category: "rev"           # web / pwn / rev / crypto / misc
difficulty: "medium"      # easy / medium / hard / insane
author: "ssong17"
date: "2026-07-21"
points: 30
tags: [태그1, 태그2]
---

# 문제명

## 문제 설명

이 문제는 실제 시간으로 365일이 흐르면 플래그를 출력하는 프로그램이 주어집니다.

프로그램을 패치하여 플래그를 획득하세요!

- 문제 URL / 파일 등 접속 정보: html 파일

## 풀이

### 분석

프로젝트를 만들고 바이너리를 불러온 뒤 자동 분석 옵션을 실행하면 Ghidra가 코드를 디컴파일해서 보여준다. entry 함수를 보면 다음과 같이 `__libc_start_main`을 호출하는 구조였다.

```c
void processEntry(undefined8 param_1, undefined8 param_2)
{
  undefined1 auStack_8 [8];
  __libc_start_main(FUN_0040127b, param_2, &stack0x00000008, 0, 0, param_1, auStack_8);
  do {
    /* WARNING: Do nothing block with infinite loop */
  } while (true);
}
```

`__libc_start_main`은 실제 `main` 함수를 실행하기 전 초기화를 담당하는 함수로, 첫 번째 인자로 실제 main 함수의 주소(`FUN_0040127b`)를 받는다. 즉 `FUN_0040127b`가 이 프로그램의 진짜 `main`이다.

`FUN_0040127b`의 디컴파일 결과는 다음과 같았다.

```c
undefined8 FUN_0040127b(void)
{
  puts("I will show you the flag after 1 year :p");
  DAT_0040404c = 0;
  while (DAT_0040404c < 0x2238) {
    FUN_004010a0(0xe10);
    DAT_0040404c = DAT_0040404c + 1;
    if (DAT_0040404c == 1) {
      puts("1 hour passed");
    } else {
      printf("%u hours passed\n", (ulong)DAT_0040404c);
    }
    if (DAT_0040404c % 0x18 == 0) {
      if (DAT_0040404c == 0x18) {
        puts("1 day has paased.");
      } else {
        printf("%u days have passed.\n", (ulong)(DAT_0040404c % 0x18));
      }
    }
  }
  printf("Great xD 1 year has passed! The flag is: ");
  FUN_00401196();
  return 0;
}
```

`DAT_0040404c`가 시간(시 단위)을 세는 카운터이고, `0x2238`(= 8760, 365일×24시간)이 될 때까지 반복문을 돌며 `FUN_004010a0`을 호출한다.

```c
void FUN_004010a0(uint param_1)
{
  sleep(param_1);
  return;
}
```

인자로 넘어오는 `0xe10`은 3600(초)이며, 즉 매 반복마다 1시간(=3600초)씩 `sleep`한 뒤 카운터를 1 증가시키는 구조다. 결국 이 프로그램은 `sleep(3600)`을 8760번 반복해야(=정확히 365일) 플래그를 출력하도록 만들어져 있었다.

### 취약점

이 프로그램의 "1년 대기" 로직은 클라이언트(로컬) 바이너리 안에 그대로 노출되어 있고, 서버 검증이나 별도의 무결성 체크가 없다. 따라서 사용자가 디스어셈블러로 바이너리를 열어 조건문과 카운터, sleep 인자를 직접 확인하고 수정(패치)할 수 있다.

또한 플래그 생성부(`FUN_00401196`)가 `DAT_0040404c` 값을 이용해 플래그 문자열을 복호화/생성하는 구조였는데, 이 값이 정확히 "365일에 해당하는 값"일 때만 올바른 플래그가 나오도록 되어 있었다. 즉 카운터 값을 무작정 크게 바꿔치기하면(예: 3천만 초를 한 번에 대입) 로직이 깨져 세그폴트가 나거나 플래그 문자열이 깨진 값으로 출력된다는 점도 취약점이자 함정이었다 — 결국 "반복 횟수(조건값)나 sleep 시간을 줄이되, 실제로 반복문을 정상적으로 끝까지 돌려야" 올바른 플래그가 나오는 구조였다.

### 익스플로잇

처음에는 `DAT_0040404c`의 증가값 자체를 아주 큰 값(예: 31,536,000 → `0x1e13380`)으로 한 번에 바꿔봤지만, 이 경우:
- 세그멘테이션 폴트가 나거나
- `Great xD 1 year has passed!` 메시지 뒤에 깨진(비정상) 플래그 문자열이 출력되는 문제가 발생했다.

이는 플래그 생성 로직이 `DAT_0040404c`가 "정확히 365일 분량의 값"일 때만 올바르게 동작하도록 만들어져 있었기 때문이었다. 즉 카운터를 임의의 큰 값으로 점프시키는 방식은 통하지 않았다.

그래서 방향을 바꿔, 반복문의 종료 조건(`0x2238`) 자체를 작은 값으로 패치하고, `sleep`에 들어가는 인자도 `0xe10`(3600초) 대신 작은 값으로 줄여서 **반복문을 실제로 끝까지 정상 실행**시키는 방식을 택했다.

sleep(3600) -> sleep(0x3c) // 60초로 축소


`0x3c`(60초) 정도로 줄였을 때는 프로그램의 로직이 깨지지 않고 정상적으로 8760회 반복을 마쳤고, 최종적으로 아래와 같이 올바른 플래그를 얻을 수 있었다.

8760 hours passed
0 days have passed.
Great xD 1 year has passed! The flag is: DH{6ad0f80a0448aee5e8615fbdea9c2775}

## 플래그

```
DH{6ad0f80a0448aee5e8615fbdea9c2775}
```

## 배운 점

.
