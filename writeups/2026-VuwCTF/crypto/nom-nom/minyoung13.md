---
ctf_name: "VuwCTF 2026"
challenge_name: "nom-nom"
category: "crypto"           # web / pwn / rev / crypto / misc
difficulty: "easy"      # easy / medium / hard / insane
author: "minyoung13"
date: "2026-08-01"
points: 100
tags: [Low Exponent Attack]
---

# nom-nom

## 문제 설명

> A hungry moose ate my flag. It looked pretty hungry so I don't blame it, but I really need that flag back.

- 첨부 파일: `nom-nom.sage`, `nom-nom.txt`

## 풀이

### 분석

`nom-nom.sage`에 flag를 암호화하는 코드가 주어진다.
flag는 pow 함수를 이용하여 평문 p에 대해 p^e(mod n) 연산을 수행하여 구한 값이다.
flag = 'Vuw{' + flag_inner + '}'로 이루어지고, flag_inner는 16바이트이다.

`nom-nom.txt`에는 e, n, c_flag_inner, c_flag가 주어진다.

### 취약점

c = p^e(mod n) 로 계산한다.
이때 flag_inner는 16바이트이고, e 값은 3이다. 반면 n은 2048비트이므로, c_flag_inner = flag_inner^3 < n이 성립한다.

따라서 c_flag_inner는 flag_inner를 세제곱한 값이며, 세제곱근을 구하면 원문을 복구할 수 있다.


### 익스플로잇

주어진 c_flag_inner의 세제곱근을 구한다.

```python
from sympy import integer_nthroot
from Cryptodome.Util.number import long_to_bytes

c_flag_inner=1133267644716881236728907279798730177484710508597335845998937053548163164206075334320272976072123221745873552889781

m, exact = integer_nthroot(c_flag_inner, 3)
if exact:
    print(long_to_bytes(m))
```

## 플래그

```
VuwCTF{REDACTED}
```

## 배운 점

- 저번에 풀이하였던 문제인 THCon 2026의 exponope 문제와 유사한 유형이었다. 작은 공개 키 e를 사용할 때, 패딩 없이 작은 메시지를 암호화하면 Low Exponent Attack이 가능하다.
- m^e < n이면 c = m^e mod n에서 모듈러 연산이 발생하지 않으므로, 암호문에 대해 정수 e제곱근을 구하는 것만으로 평문을 복구할 수 있다.
- 큰 수의 제곱근을 구하는 라이브러리가 없을 경우, 아래와 같은 코드로 풀 수도 있다.
```python
c_flag_inner=1133267644716881236728907279798730177484710508597335845998937053548163164206075334320272976072123221745873552889781

lo, hi = 0, 1 << ((c_flag_inner.bit_length() + 2) // 3 + 1)

while lo < hi:
    mid = (lo + hi + 1) // 2

    if mid ** 3 <= c_flag_inner:
        lo = mid
    else:
        hi = mid - 1

m = lo

print(m ** 3 == c_flag_inner)
print(m.to_bytes(16, "big"))
```
