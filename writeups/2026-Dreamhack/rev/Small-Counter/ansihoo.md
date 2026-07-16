---
ctf_name: "2026-Dreamhack"
challenge_name: "Small-Counter"
category: "rev"           # web / pwn / rev / crypto / misc
difficulty: "medium"      # easy / medium / hard / insane
author: "ansihoo"
date: "2026-07-13"
points: 500
tags: [cipher, patch]
---

# 문제명
- Small-Counter

## 문제 설명

> 문제 파일로 chall이라는 이름의 stripped되지 않은 64비트 ELF PIE 실행 파일 하나만 주어진다. 실행하면 10부터 1까지 카운트다운을 출력한 뒤, 특정 조건을 만족해야만 플래그를 계산해서 출력해주는 구조다. 별도의 서버나 네트워크 접속 정보는 없고, 로컬에서 바이너리를 분석해 플래그를 뽑아내면 되는 문제다.

## 풀이

### 분석

main은 카운터를 10에서 1까지 감소시키며, 카운터가 3일 때 인코딩된 69바이트 플래그 원본(IM{...})을 스택에 복사한다. 루프가 끝나면 카운터는 항상 0인데, 코드는 cmp [rbp-4], 5로 카운터가 5인지 확인한 뒤에만 flag_gen(buf, out, shift)을 호출한다. 즉 정상 실행으로는 절대 도달할 수 없는 분기다. 이 5는 동시에 flag_gen의 shift 인자이기도 하다.
flag_gen은 shift만큼 회전시킨 알파벳 테이블로 대소문자를 치환하는 시저 암호와, 숫자 문자에 (문자코드 * (shift+3)) mod 15 식을 적용하는 커스텀 변환을 조합한 인코딩이었다.

### 취약점

메모리 안전성 문제가 아니라 논리 결함이다. 카운터가 5에 도달 못 하도록 막아뒀을 뿐, 체크만 우회하고 shift=5만 맞춰주면 flag_gen이 조건 없이 정답을 계산해준다. 바이너리를 2바이트 패치해서 풀었다: cmp 비교값을 실제 런타임 값(0)으로 바꿔 분기를 통과시키고, 카운터를 edx로 옮기는 mov eax,[rbp-4]를 mov al,5로 바꿔 shift를 5로 고정. 패치된 바이너리 실행 결과 플래그 획득

### 익스플로잇

- cmp [rbp-4],5 -> cmp [rbp-4],0 : 실제 런타임 카운터 값(0)과 맞춰 jne 분기를 통과시킴
- mov eax,[rbp-4] -> mov al,5;nop : flag_gen에 넘어가는 shift 인자를 5로 고정

```python
import subprocess
 
SRC = "chall"
DST = "chall_patched"
 
data = bytearray(open(SRC, "rb").read())
 
# 1) cmp DWORD PTR [rbp-4], 5  ->  cmp DWORD PTR [rbp-4], 0
p1 = bytes.fromhex("837dfc05")
i1 = data.find(p1)
assert i1 != -1, "patch point 1 not found"
data[i1 + 3] = 0x00
 
# 2) mov eax,[rbp-4] -> mov al,5 ; nop
p2 = bytes.fromhex("8b45fc8945f88b55f8")
i2 = data.find(p2)
assert i2 != -1, "patch point 2 not found"
data[i2:i2 + 3] = bytes.fromhex("b00590")
 
open(DST, "wb").write(data)
 
import os
os.chmod(DST, 0o755)
 
out = subprocess.run([f"./{DST}"], capture_output=True, text=True)
print(out.stdout)
```

## 플래그

```
DH{389998e56e90e8eb34238948469cecd6dd89c04dce359c345e0b2f3ef9edc66a}
```

## 배운 점

체크 로직이 정상 실행 경로로 절대 통과할 수 없게 짜여 있어도, 그 체크가 지키려는 값(shift)이 결과 계산에 직접 쓰인다면 바이너리를 그 값만큼만 패치해서 우회할 수 있다는 걸 확인했다. 굳이 전체 로직을 에뮬레이션하거나 브루트포스할 필요 없이, 원본 바이너리의 연산 로직을 그대로 살리면서 분기 조건 몇 바이트만 바꾸는 최소 패치가 가장 빠른 풀이였다.
