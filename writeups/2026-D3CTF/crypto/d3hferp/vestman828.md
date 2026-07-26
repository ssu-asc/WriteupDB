---
ctf_name: "2026-D3CTF"
challenge_name: "D3HFERP"
category: "crypto"
difficulty: "medium"
author: "vestman828"
date: "2026-07-26"
tags: [crypto]
---

# D3HFERP

## 문제 설명

> 2026-D3CTF의 D3HFERP 문제입니다. Crypto입니다.

## 풀이

### 분석

문제에서는 다변수 공개키 암호의 공개키 `pubkey.txt`와 7개의 암호문 블록을 제공합니다. 공개키는 `GF(3)` 위의 31변수, 53개 이차식으로 구성되어 있습니다.

암호화 함수의 각 출력 좌표는 다음 형태입니다.

\[
c_k=x^T P_k x+L_kx+R_k
\]

따라서 암호문 좌표를 우변으로 넘기면 공개키만으로 53개의 다항식 방정식을 만들 수 있습니다. `P_k`가 대칭행렬이므로 다항식을 펼칠 때 대각항은 `P[i][i] * x[i]^2`, 교차항은 `2 * P[i][j] * x[i] * x[j]`가 됩니다.

처음에는 Z3로 이차 합동식을 직접 풀었지만 속도가 매우 느렸습니다. 대신 각 변수가 `GF(3)`의 원소라는 사실을 나타내는 체 방정식을 추가했습니다.

\[
x_i^3-x_i=0
\]

`GF(3)`에서는 `-1 = 2`이므로 msolve 입력에는 `x_i^3+2*x_i`로 기록합니다. 블록 하나마다 공개식 53개와 체 방정식 31개, 총 84개의 식을 F4 Gröbner basis 계산기인 msolve로 풀었습니다. 계산 결과 reduced Gröbner basis가 31개의 일차식으로 환원되어 각 평문 변수가 유일하게 결정됐습니다.

평문은 다음 방식으로 인코딩되어 있습니다.

1. 플래그 앞에 2바이트 little-endian 길이를 붙입니다.
2. 전체 바이트열을 little-endian 정수로 해석합니다.
3. 정수를 3진수로 변환합니다.
4. 3진수 자릿수를 31개씩 나누어 암호화합니다.

마지막 블록은 0으로 패딩됩니다. 플래그가 `}`로 끝난다고 가정하여 길이를 조사하면 길이 38일 때 마지막 블록에서 앞 16개 변수만 활성화됩니다. 이 블록은 나머지 15개 변수를 0으로 고정하여 빠르게 풀 수 있었습니다.

복구된 7개 블록의 3진수 값을 이어 붙여 정수로 만든 뒤 little-endian 바이트열로 바꾸면 다음 값이 나옵니다.

```text
b'&\x00d3ctf{S1mpl3_Att4ck_br34ks_HFERP_2026}'
```

첫 두 바이트 `26 00`은 38을 의미하며 실제 플래그 길이와도 일치합니다. 복구한 평문을 공개 암호화식에 다시 대입했을 때 7개 블록의 53개 좌표가 모두 원본 암호문과 일치했습니다.

### 익스플로잇

핵심은 공개 이차식과 체 방정식을 msolve 입력으로 생성하고 결과를 다시 3진수 정수로 합치는 것입니다. 전체 코드는 `D3HFERP/solve.py`에 있습니다.

```python
# 공개키의 한 출력 좌표를 다항식으로 변환
for i in range(variables):
    add(matrix[i][i] * x[i] ** 2)
    add(linear[i] * x[i])
    for j in range(i + 1, variables):
        add(2 * matrix[i][j] * x[i] * x[j])

add(constant - target)

# 모든 변수를 GF(3)의 원소로 제한
polynomials.extend(f"x{i}^3+2*x{i}" for i in range(variables))

# 복구한 trit을 원래 little-endian 정수로 결합
value = sum(trit * (3 ** i) for i, trit in enumerate(all_trits))
raw = value.to_bytes((value.bit_length() + 7) // 8, "little")
length = int.from_bytes(raw[:2], "little")
print(raw[2:2 + length].decode())
```

```powershell
# 0~5번 블록은 31변수로 계산
0..5 | ForEach-Object {
    python D3HFERP/solve.py --block $_ --variables 31 --output "block$_.ms"
    msolve -f "block$_.ms" -g 2 -t 8 > "block$_.gb"
}

# 마지막 블록은 활성 변수 16개만 계산
python D3HFERP/solve.py --block 6 --variables 16 --output last16.ms
msolve -f last16.ms -g 2 -t 8 > last16.gb
python D3HFERP/solve.py --decode
```

## 플래그

```text
d3ctf{S1mpl3_Att4ck_br34ks_HFERP_2026}
```

## 배운 점

다변수 공개키 암호가 복잡한 중앙 사상과 비밀 선형변환을 사용하더라도, 공개 MQ 시스템 자체가 충분히 overdefined되어 있으면 숨겨진 구조를 복구하지 않고 직접 풀 수 있습니다. 작은 유한체 문제에서는 `x_i^q-x_i=0` 형태의 체 방정식을 추가하는 것이 Gröbner basis 계산 성능에 큰 영향을 줍니다.
