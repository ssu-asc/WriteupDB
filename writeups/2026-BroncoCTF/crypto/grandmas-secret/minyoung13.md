---
ctf_name: "BroncoCTF"
challenge_name: "Grandma's Secret"
category: "crypto"           # web / pwn / rev / crypto / misc
difficulty: "easy"      # easy / medium / hard / insane
author: "minyoung13"
date: "2026-07-12"
points: 10
tags: [ADFGVX, Classical Cipher, Columnar Transposition]
---

# Grandma's Secret

## 문제 설명

> Grandma wants to protect her wifi password. Can you find out what it is before grandpa does?

- 첨부파일 : 'Letter.jpeg'

![screenshot](images/1.png)

## 풀이

### 분석

편지를 읽어보면 다음과 같은 힌트가 있다.

- "I used my favorite ADFGVX cipher"
  - 사용된 암호가 ADFGVX Cipher임을 직접 알려준다.
- 좌측 하단에는 ADFGVX Polybius Square가 함께 제공된다.
- "alphabetically sorted SUGAR"
  - ADFGVX 암호에서 사용하는 Columnar Transposition Key가 `SUGAR`임을 의미한다.
  - 복호화 시에는 키를 알파벳 순(`A G R S U`)으로 정렬한 순서를 이용해 컬럼을 복원한다.

암호문은 다음과 같다.
```
GVXXFVXVAFXFXVGADAFF
```
### 취약점

문제에서 다음 정보를 모두 제공한다.

- ADFGVX 암호 사용
- Polybius Square 제공
- Transposition Key(`SUGAR`) 제공

따라서 ADFGVX 복호화를 수행하면 된다.

### 익스플로잇

1. 키 `SUGAR`를 이용해 Columnar Transposition을 역으로 수행한다.

2. 얻어진 ADFGVX 문자쌍을 문제에서 제공한 Polybius Square로 변환한다.


```python
square = {
('A','A'):'B',('A','D'):'3',('A','F'):'M',('A','G'):'R',('A','V'):'L',('A','X'):'I',
('D','A'):'A',('D','D'):'6',('D','F'):'F',('D','G'):'0',('D','V'):'8',('D','X'):'2',
('F','A'):'C',('F','D'):'7',('F','F'):'S',('F','G'):'E',('F','V'):'U',('F','X'):'H',
('G','A'):'Z',('G','D'):'9',('G','F'):'D',('G','G'):'X',('G','V'):'K',('G','X'):'V',
('V','A'):'1',('V','D'):'Q',('V','F'):'Y',('V','G'):'W',('V','V'):'5',('V','X'):'P',
('X','A'):'N',('X','D'):'J',('X','F'):'T',('X','G'):'4',('X','V'):'G',('X','X'):'O'
}

cipher = "GVXXFVXVAFXFXVGADAFF"
key = "SUGAR"

ncol = len(key)
rows = len(cipher) // ncol

order = sorted(range(ncol), key=lambda i: key[i])

cols = [""] * ncol
idx = 0
for i in order:
    cols[i] = cipher[idx:idx+rows]
    idx += rows

pairs = ""
for r in range(rows):
    for c in range(ncol):
        pairs += cols[c][r]

plaintext = ""
for i in range(0, len(pairs), 2):
    plaintext += square[(pairs[i], pairs[i+1])]

print(plaintext)
```

## 플래그

```
Bronco{JELLYDONUT}
```

## 배운 점

- ADFGVX 암호는 Polybius Square와 Columnar Transposition을 결합한 고전 암호이다.
- 암호화를 할 때에는 먼저 폴리비우스 사각형을 이용하여 평문을 ADFGVX 문자쌍으로 치환한다.
폴리비우스 사각형은 알파벳(A~Z)과 숫자(0~9)를 섞어 만든 6×6 형태의 표로, 이 표의 가로와 세로 축에 A, D, F, G, V, X 6개의 알파벳을 라벨링한다. 평문의 각 글자를 표에서 찾은 뒤 해당 글자의 (행, 열)에 위치한 라벨을 순서대로 이어 두 글자로 치환하는 방식이다.
그 다음 열을 전치하여 문자쌍의 순서를 섞는다. key의 길이를 열의 개수로 하는 표를 만든 뒤 앞서 얻은 문자쌍을 행 방향으로 채운다. 이후 key를 알파벳 순으로 정렬한 순서에 맞추어 열 단위로 읽으면 암호문이 된다.
```
S U G A R
---------
X D F G A
V A V V F
G F X X X
A F V X F
```
만든 표가 위와 같다면 key를 알파벳 순(A, G, R, S, U)으로 정렬하여 GVXX, FVXV, AFXF, XVGA, DAFF 순서로 읽고 이어 붙여 암호문을 생성한다.
- 복호화는 위 과정을 역순으로 수행한다. 암호문의 길이와 key의 길이를 이용해 각 열의 길이를 계산한 뒤, 암호문을 해당 길이만큼 나누어 알파벳 순으로 정렬된 키(A, G, R, S, U)에 대응하는 열에 채운다. 이후 원래 열의 순서로 다시 배치하고 행 방향으로 읽은 뒤 두 글자씩 폴리비우스 사각형에서 찾으면 평문을 복원할 수 있다.
- 참고 자료 : https://youtu.be/iwd19KMXTYI?si=TK_U3SD7x43Guoaf