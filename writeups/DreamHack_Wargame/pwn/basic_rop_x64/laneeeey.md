---
ctf_name: "DreamHack_Wargame"
challenge_name: "basic_rop_x64"
category: "pwn"           # web / pwn / rev / crypto / misc
difficulty: "easy"      # easy / medium / hard / insane
author: "laneeeey"
date: "2026-08-04"
points: 21
tags: [ROP, ret2libc]
---

# 문제명

## 문제 설명

Description
이 문제는 서버에서 작동하고 있는 서비스(basic_rop_x64)의 바이너리와 소스 코드가 주어집니다.
Return Oriented Programming 공격 기법을 통해 셸을 획득한 후, "flag" 파일을 읽으세요.
"flag" 파일의 내용을 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.

## 풀이

### 분석

소스코드 분석 결과
buf의 크기는 0x40, read()는 최대 0x400 만큼 입력을 받고 write로 buf에 사이즈 만큼 출력함을 알 수 있음

### 취약점

char buf[0x40] = {};
read(0, buf, 0x400);
여기에서 스택 버퍼 오버 플로우가 발생함.

buf 사이즈가 64 바이트이기 때문에 offset은 72 바이트임.

### 익스플로잇

1. 바이너리에서 필요한 gadget과 puts의 GOT, PLT, main 주소를 구함
2. 페이로드를 보내 puts의 libc 주소를 가져옴
3. puts 주소에서 offset을 빼서 libc base를 계산함
4. libc base를 이용해 system과 /bin/sh 주소를 계산함
5. 다시 페이로드를 보내서 system("/bin/sh") 호출함
6. 쉘 획득이 되어 cat flag로 플래그를 얻음

ex.py 코드 첨부.

## 플래그

```
flag{REDACTED}
```

## 배운 점

- ROP 기법을 이용한 익스플로잇을 작성하며 전체 동작 과정을 이해
- PLT, GOT, gadget, libc base 등 ROP에서 사용되는 개념 학습
- puts 주소를 유출하여 libc base를 계산하고 system("/bin/sh")를 호출하는 ret2libc 기법 학습
