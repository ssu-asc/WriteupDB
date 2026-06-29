---
ctf_name: "SekaiCTF 2026"
challenge_name: "oneline6ryp7o"
category: "crypto"           # web / pwn / rev / crypto / misc
difficulty: "easy"      # easy / medium / hard / insane
author: "minyoung13"
date: "2026-06-29"
points: 50
tags: [modulo, math]
---

# oneline6ryp7o

## 문제 설명

> how hard can six seven be

```
assert __import__('re').match('SEKAI{[67]{67}}$',flag:=input()) and not int.from_bytes(flag.encode())%~(6+~7)**67
```

- 한 줄의 Python 코드만 주어지며, 조건을 만족하는 플래그를 찾는 문제이다.

## 풀이

### 분석

1. 정규식을 보면 플래그의 형식은 다음과 같다.

    ```python
    re.match(r"SEKAI{[67]{67}}$", flag)
    ```

    즉, `SEKAI{`로 시작하여 `}`로 끝나고, 그 사이에 `6` 또는 `7`만 67개 형태인 문자열이어야 한다.

2. 두 번째 조건을 살펴보면 다음과 같다.

    ```python
    not int.from_bytes(flag.encode()) % ~(6+~7)**67
    ```

    % 연산자 뒤의 식을 계산하면 아래와 같다.

    ```python
    ~7 = -8
    6 + ~7 = -2
    (-2)**67 = -(2**67)
    ~(-(2**67)) = 2**67 - 1
    ```

    따라서 실제 조건은 아래와 동일하다.

    ```python
    int.from_bytes(flag.encode()) % (2**67 - 1) == 0
    ```

3. 이때 `int.from_bytes()`는 문자열을 256진수 정수로 변환한다.

    각 문자의 가중치는 256^k 이다.

    즉, S*256^73 + E*256^72 + ⋯ + 첫번째 (6or7)*256^67 + ⋯ + 마지막 (6or7)*256^1 + }*256^0 이다.
    

4. 구해야 하는 것은 x ≡ 0 (mod 2^67-1) 인 x이다.

    2^67 ≡ 1 (mod 2^67-1) 이므로, 2^e ≡ 2^(e mod 67) 이다.

    따라서 256^k를 계산할 때는 지수 8k를 67로 나눈 나머지로 고려하면 된다.

    256^k = 2^(8k) ≡ 2^(8k mod 67)

5. gcd(8,67) = 1 이므로 8k mod 67은 중복되지 않고, 0부터 66까지의 모든 값을 정확히 한 번씩 만들어낸다. 67개의 문자는 각각 서로 다른 비트를 하나씩 담당하게 된다.

6. '6' = 54, '7' = 55 로 1 차이나므로, 모든 문자를 '6'으로 놓은 뒤 필요한 위치만 '7'로 바꾸면 원하는 나머지를 만들 수 있다. (e.g. 첫 문자를 바꾸면 256^67만큼 증가한다.)

### 익스플로잇

먼저 모든 문자가 '6'인 문자열의 값을 계산한다.

```
base = int.from_bytes(b"SEKAI{" + b"6"*67 + b"}")
```

이때 base+delta ≡ 0이 되게 하기 위한 delta ≡ (-base) (mod 2^67-1). 

이 값을 67비트 이진수로 나타내면 어떤 위치를 '7'로 바꿔야 하는지가 나온다.

67개의 가중치가 모두 서로 다르므로 해는 유일하게 결정된다.

```python
import re

MOD = (1 << 67) - 1

prefix = b"SEKAI{"
suffix = b"}"

# 모든 문자를 '6'으로 둔 기본 문자열
base_flag = prefix + b"6" * 67 + suffix
base = int.from_bytes(base_flag) % MOD

# '6'들만 있을 때의 나머지를 상쇄해야 함
target = (-base) % MOD

flag = "SEKAI{"

# 첫번째 6or7의 가중치는 256^67, 마지막 6or7의 가중치는 256^1
for i in range(67):
    bit = (8 * (67 - i)) % 67
    flag += "7" if (target >> bit) & 1 else "6"

flag += "}"

print(flag)

assert re.match(r"SEKAI{[67]{67}}$", flag)
assert int.from_bytes(flag.encode()) % MOD == 0
```

## 플래그

```
SEKAI{6777676667666666677676776776777766777777777776777767777776677666666}
```

## 배운 점

- ~x = -(x+1) = -x-1 이다.
- `2^n-1` 모듈러에서는 `2^n ≡ 1`이라는 성질을 이용하면 큰 정수를 매우 단순하게 다룰 수 있다.