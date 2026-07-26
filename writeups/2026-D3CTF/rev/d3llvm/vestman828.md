---
ctf_name: "2026-D3CTF"
challenge_name: "d3llvm"
category: "rev"
difficulty: "medium"
author: "vestman828"
date: "2026-07-26"
tags: [rev]
---

# d3llvm

## 문제 설명

> 2026-D3CTF의 d3llvm 문제입니다. Rev입니다.

## 풀이

### 분석

APK를 실행하면 토큰을 입력하고 터치 게임을 진행하라는 안내가 표시됩니다. 실제 플래그 공개 조건은 다음 세 부분으로 나뉩니다.

1. 네이티브 제약식을 만족하는 64자리 hex 토큰
2. MNN 모델을 64회 실행하며 누적되는 trace
3. 토큰과 trace seed에서 유도되는 AES key

APK의 `libd3llvm.so`는 암호화된 ARM64 payload를 메모리에서 복호화한 뒤 JNI 메서드를 등록합니다. 복호화된 payload에서 중요한 함수는 `FlagNative.nativeVerifyInput`, `FlagNative.nativeRevealFlag`, `MnnTouchClassifier.nativeRun`입니다.

토큰은 64개의 hex 문자, 즉 16개의 16비트 정수로 해석됩니다. OLLVM으로 난독화된 검증 함수를 Unicorn으로 실행하면서 비교 지점의 피연산자를 기록하고, 동일한 제약식을 Z3로 옮겨 다음 토큰을 구했습니다.

```text
196f0d201332b47deb98221f33c7f4a13d03de6c2a77279c4dbc1f87e4d297a8
```

게임 점수는 플래그 공개 시점을 정하는 UI 조건일 뿐이며, 실제 인증 상태는 MNN classifier 객체에 쌓입니다. 검증기는 모델 실행 횟수가 정확히 64인지 확인하고, 매 실행의 operator trace를 누적한 seed를 사용합니다.

모델 FlatBuffer에는 39개 operator가 있지만, 이 이름을 전부 해시하면 잘못된 seed가 만들어집니다. MNN은 실행 그래프를 최적화하면서 Raster 연산을 새로 만들기 때문입니다. 실제 런타임 callback에는 다음 13개 operator만 나타났습니다.

```text
getitem_raster_0
getitem
getitem_3_raster_0
getitem_3
max_pool1d_raster_0
max_pool1d
getitem_6_raster_0
getitem_6
mean_raster_0
mean_raster_1
logits__matmul_converted_raster_0
logits__matmul_converted
logits_raster_0
```

각 이름을 FNV-1a64로 해시하여 더하면 한 번의 실행 trace는 `0x4280720401113ed2`입니다. 같은 실행이 64회 이루어지므로 최종 seed는 `0xa01c8100444fb480`이 됩니다.

`nativeRevealFlag`는 토큰 hash, seed, 상수를 XOR한 값을 두 번의 SplitMix64에 넣어 128비트 AES key를 만듭니다. 유도된 key `22032f61c4e8afd2d43b65e3b4528daa`로 payload의 ciphertext를 AES-ECB 복호화하고 PKCS#7 padding을 제거하면 플래그가 나옵니다.

### 익스플로잇

```python
MASK = (1 << 64) - 1

def fnv1a64(data):
    value = 0xcbf29ce484222325
    for byte in data:
        value ^= byte
        value = value * 0x100000001b3 & MASK
    return value

trace = sum(fnv1a64(name.encode()) for name in runtime_ops) & MASK
seed = 64 * trace & MASK

token_hash = fnv1a64(token.encode())
low = splitmix64(token_hash ^ seed ^ 0xd3c7f19a5eed2026)
high = splitmix64(seed ^ ror64(token_hash, 47) ^ 0xa11ce5c0dec0de42)
key = low.to_bytes(8, "little") + high.to_bytes(8, "little")

plain = AES.new(key, AES.MODE_ECB).decrypt(ciphertext)
print(unpad(plain, 16).decode())
```

```powershell
python solve_token.py
python emulate_constraints.py analysis_recheck/lib/arm64-v8a/libd3llvm_payload.dec.so 196f0d201332b47deb98221f33c7f4a13d03de6c2a77279c4dbc1f87e4d297a8
python probe_mnn.py analysis_recheck/touch_model.decrypted.mnn
python solve_final.py
```

최종 결과는 다음과 같습니다.

```text
token = 196f0d201332b47deb98221f33c7f4a13d03de6c2a77279c4dbc1f87e4d297a8
trace = 0x4280720401113ed2
seed  = 0xa01c8100444fb480
key   = 22032f61c4e8afd2d43b65e3b4528daa
flag  = d3ctf{OLLVM_is_still_somewhat_useful_for_AI}
```

## 플래그

```text
d3ctf{OLLVM_is_still_somewhat_useful_for_AI}
```

## 배운 점

머신러닝 모델 파일에 정적으로 저장된 operator 목록과 런타임이 실제로 실행하는 그래프는 다를 수 있습니다. 실행 trace가 key 재료로 쓰이는 문제에서는 모델 포맷 분석만으로 결론을 내리지 않고 실제 런타임 callback을 관측해야 합니다.
