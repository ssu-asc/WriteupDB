---
ctf_name: "Sekai CTF 2026"
challenge_name: "Untitled Encore"
category: "rev"
difficulty: "meidum"
author: "ssong17"
date: "2026-06-30"
points: 50
tags: [eBPF, PE, Windows, custom-vm, stream-cipher]
---

# 문제명

## 문제 설명

Yes, you can no longer make PJSK content with Sonolus.
No, I will not ask you to play with Sonolus...

rev_untitled-encore.tar.gz 문제 파일

---

## 풀이

### 1. PE 구조 파악 — embedded eBPF ELF

바이너리를 열면 `.rdata` 섹션 내부 VA **`0x14000e700`** 에서 `7f 45 4c 46` (ELF 매직)이 보인다.  
`pefile`로 RVA를 계산하면:

```
RVA = 0x14000e700 - ImageBase(0x140000000) = 0xe700
```

`.rdata`의 파일 오프셋으로 변환 후 **0xbb8 바이트** 를 추출하면 64비트 eBPF relocatable ELF가 나온다.

```
섹션      오프셋    크기
.text     0x40     0x8b0   ← eBPF 명령어 스트림
.rodata   0x8f0    0x1ac   ← verifier payload 원본
```

---

### 2. Verifier Payload 추출 및 XOR 디코딩

`.rodata` 내 오프셋 `0x28`부터 **388바이트(= 97 × 4)** 가 verifier payload 원본(raw)이다.  
각 4바이트 명령어는 바이트별로 XOR 키가 다르게 적용된다.

```python
b0 = raw[i]   ^ ((i * 0x11 - 0x5d) & 0xff)
b1 = raw[i+1] ^ ((i * 0x1d + 0x11) & 0xff)
b2 = raw[i+2] ^ ((i * 0x1f + 0x7b) & 0xff)
b3 = raw[i+3] ^ ((i * 0x25 - 0x3b) & 0xff)
```

(`i`는 해당 명령어의 바이트 오프셋, 즉 `instruction_index * 4`)

디코딩 후 97개 명령어의 opcode 분포:

| Opcode | 개수 | 역할                        |
|--------|------|-----------------------------|
| 0x21   | 12   | MARKER — input 헤더 값 검증 |
| 0x44   | 20   | CHART\_CHECK — chart 직접 검증 |
| 0x62   | 32   | GEN\_FIRST32 — first32 블록 검증 |
| 0x8b   | 32   | GEN\_VM32 — vm32 블록 생성  |
| 0xf0   | 1    | TERM — 종료                  |

---

### 3. eBPF VM 구조 이해

eBPF `.text`를 capstone으로 디스어셈블하면 메인 루프가 보인다.

```
r6 = 0              ; verifier byte offset
r7 = 0x31c3f00d     ; rolling hash (32-bit)

loop:
  r8 = rodata + r6
  r9 = raw[r8]
  r9 XOR= (r6*0x11 - 0x5d) & 0xff   ; opcode decode
  dispatch r9 → {0x21, 0x44, 0x62, 0x8b, 0xf0}
  r6 += 4
```

각 핸들러는 나머지 3바이트(b1, b2, b3)도 같은 방식으로 XOR 디코딩한 뒤 처리한다.

**Input vector 레이아웃 (r1 포인터):**

```
input[0:12]   — 헤더 (0x21 MARKER가 검증)
input[12:52]  — chart 40바이트
input[52:84]  — first32 32바이트
```

---

### 4. Chart 형식

chart는 정확히 **40바이트 = 20개의 2바이트 노트**다.

각 노트 `i`에 대해 `b0 = chart[2i]`, `b1 = chart[2i+1]`:

```
lane   = b0 & 7
kind   = (b0 >> 3) & 3
flick  = (b0 >> 5) & 1
parity = (b0 >> 6) & 1
```

유효성 조건:

- `lane <= 4`, `kind <= 2`
- `3 <= b1 <= 16`
- `((lane - i) & 1) == parity`

누적값(0x44 이후 aggregate 검증에 사용):

```
lane_sum[lane] += 5*flick + 3*kind + parity + b1
kind_sum[kind] += (i & 3) + lane + b1
```

목표값:

```
lane_sum = [0x38, 0x22, 0x36, 0x21, 0x41]
kind_sum = [0x61, 0x49, 0x3c]
```

---

### 5. 0x44 CHART\_CHECK 명령어로 Chart 역산

0x44 핸들러(eBPF `.text` 0x01c8)는 다음을 수행한다.

```
chart_b0 = input[2*b1_insn + 12]
chart_b1 = input[2*b1_insn + 13]

hash16 = (chart_b0*0x11 + chart_b1*0x1f + rolling_hash + b3_insn*0x49) & 0xffff
check  = ((hash16 >> 8) ^ hash16) & 0xff
assert check == b2_insn
```

**rolling\_hash가 고정**돼 있는 한 (처음 12개의 0x21 명령어가 모두 고정 헤더값을 확인하므로 0x21 처리 직후 r7은 결정론적으로 계산됨), 20개의 0x44 명령어가 각 노트에 대해 1차 방정식을 만든다.  
여기에 aggregate 조건(lane\_sum, kind\_sum)과 노트 유효성 조건을 결합하면 **유일한 chart**가 도출된다.

```
chart = 000c01070a072305140d0b062a06010b1008640408090105320a03050c0f6203100c740649070309
```

---

### 6. first32 / vm32 생성

0x62 명령어는 `input[52+b1]` 값을 검증(= first32가 PE에서 미리 계산된 값과 일치하는지 확인)하고, rolling hash를 업데이트한다.  
0x8b 명령어는 first32와 chart를 혼합해 scratch 버퍼에 **vm32** 32바이트를 직접 기록한다.

```
first32 = 33d263e1008c774e67812c7fb6567b2eb4986d3b028ce0b88146cdbd7f796e9b
vm32    = 4d035adf070143b586d290f25a23ea6c4de4ae932cc64110e3a4d311bc6d6640
```

---

### 7. Flag 복호화

PE `.text` 0x140008470의 복호화 루틴은 아래 순서로 동작한다.

1. **material(32B)** = custom\_hash(aggregate parser 출력: state0-3, lane\_sum, kind\_sum)  
   custom\_hash는 PE 내부의 커스텀 32바이트 byte-mixing 함수.
2. **seed(32B)** = custom\_hash(["SEKAI_sbf_", material, vm32, chart])  
   prefix 10바이트는 "SEKAI_sbf_"로 PE 내에 하드코딩돼 있음.
3. **stream** = counter-block expand(seed)
4. **plaintext** = ciphertext XOR stream

암호문은 `.rdata` VA `0x14000f2b8`에 22바이트로 내장돼 있다:
```
73882f9f36ccbbdeb1d848b5ceaa5156cbb6bc6379a2
```

---

### 익스플로잇

```bash
wine untitled-encore.exe --check-chart \
  000c01070a072305140d0b062a06010b1008640408090105320a03050c0f6203100c740649070309
```

---

## 플래그

```
SEKAI{eBPF_my_B3l0v3d}
```

---

## 배운 점
