---
ctf_name: "TBCTF 2026"
challenge_name: "Bespoke Superblock"
category: "misc"
difficulty: "easy"
author: "no-carve-only-pizza"
date: "2026-06-26"
points: 100
tags: [forensics, disk image, custom filesystem, XOR]
---

# Bespoke Superblock

## 문제 설명

> We recovered a strange disk image from a compromised server. Standard forensic tools are having trouble making sense of its contents, though a partially corrupted extraction script was found nearby.
>
> Can you investigate the image and piece together the hidden information?

제공 파일은 `bespoke_superblock.zip`이고, 압축을 풀면 다음 두 파일이 나온다.

```text
challenge.img
parser.py
```

## 풀이

### 분석

먼저 이미지의 앞부분을 확인하면 일반 파일시스템처럼 보이는 부트 섹터가 있지만, `0x200` 위치에 커스텀 파일시스템 시작 위치를 알려주는 문자열이 있다.

```text
NOTICE: Custom Filesystem starts at offset 0x1000. Use parser.py for recovery.
```

`parser.py`도 같은 위치를 기준으로 슈퍼블록을 읽는다.

```python
f.seek(0x1000)
header = f.read(16)
magic, block_size, total_blocks, flag_inode = struct.unpack('<4s H I I 2x', header)
```

슈퍼블록 값은 다음과 같다.

```text
Magic        = TBFS
Block Size   = 512
Total Blocks = 8
Flag Inode   = 0x1020
```

즉 `0x1020`부터 시작해서 512바이트 간격으로 각 블록의 앞 4바이트를 모으면 된다. 하지만 제공된 파서를 그대로 실행하면 결과가 일부 깨져 보인다.

```text
tbctf[SPAT\x11AL\x7fAWARE\x7fXOR\x7f\x11\x13\x13\x17]
```

여기서 문제 설명의 "Bespoke Superblock", 스크립트의 "high entropy", "spatial consistency" 힌트를 보면 단순히 데이터를 이어 붙이는 것이 아니라 위치 기반 처리가 한 번 더 필요하다는 것을 알 수 있다.

### 위치 기반 XOR

플래그 조각은 `flag_inode + i * block_size` 위치에서 읽힌다.

```text
0x1020
0x1220
0x1420
0x1620
...
```

모든 조각의 블록 내부 오프셋은 `0x20`이다. 깨진 문자들도 `0x20`으로 XOR하면 자연스러운 플래그 문자로 바뀐다.

```text
0x7f ^ 0x20 = '_' 
0x11 ^ 0x20 = '1'
0x13 ^ 0x20 = '3'
0x17 ^ 0x20 = '7'
```

따라서 각 블록에서 읽은 4바이트에 현재 위치의 low byte, 즉 `0x20`을 XOR하면 된다.

### 복구 코드

```python
import struct

img_path = "challenge.img"

with open(img_path, "rb") as f:
    f.seek(0x1000)
    header = f.read(16)
    magic, block_size, total_blocks, flag_inode = struct.unpack("<4s H I I 2x", header)

    assert magic == b"TBFS"

    recovered = bytearray()

    for i in range(total_blocks):
        offset = flag_inode + i * block_size
        f.seek(offset)

        chunk = f.read(4)
        key = offset & 0xFF
        recovered += bytes(b ^ key for b in chunk)

    print(recovered.rstrip(b"\x00").decode())
```

실행 결과:

```text
TBCTF{spat1al_aware_xor_1337}
```

## 플래그

```text
TBCTF{spat1al_aware_xor_1337}
```

## 배운 점

손상된 파서가 있어도 완전히 틀린 것은 아닐 수 있다. 이 문제처럼 파서가 올바른 위치와 구조를 알려주고, 마지막 인코딩 계층만 누락한 경우에는 출력의 깨진 패턴과 오프셋 규칙을 함께 보면 복구할 수 있다.
