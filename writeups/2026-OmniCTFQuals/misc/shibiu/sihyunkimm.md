---
ctf_name: "OmniCTF 2026 Quals"
challenge_name: "shibiu"
category: "misc"
difficulty: "easy"
author: "sihyunkimm"
date: "2026-07-19"
points: 68
---

# shibiu

## 문제 설명

> My friend from Shibiu gave me a minecraft world and told me that he hid a message in it. Can you help me find it? Also, this world resembles one I've seen at some point in the past, but I can't remember where exactly.

Minecraft 월드 파일에서 숨겨진 메시지를 찾아야 하는 문제다.

## 풀이

### 접근 방법

맵 파일과 문제를 봤을 때 수정 전 월드와 제공된 월드의 차이를 비교하는 문제일 것 같았다.

또한 도시 맵임을 감안했을 때 우리나라의 도시능력자 맵처럼 해외에서 유명한 맵일 것으로 예상했지만, 나는 해외 맵을 알지 못했다. 그래서 이런 문제는 AI가 어떻게 풀이할지 궁금해 AI에게 분석을 시켜 보았다. ChatGPT 5.6 Sol 모델을 사용했으며 아래는 AI 분석 내역이다.

### 원본 월드 식별

제공된 디렉터리는 `level.dat`, `region/*.mca`, `entities/*.mca`, `playerdata/*.dat` 등을 포함한 Minecraft Java Edition 월드였다. 먼저 NBT 형식인 `level.dat`을 파싱하자 다음 정보를 얻을 수 있었다.

```text
LevelName: Shibuya (sort of...)
Version: 1.20.2
WorldGenSettings: flat
Spawn: (0, -60, 0)
```

월드의 표지판 데이터도 확인해 보니 다음과 같은 제작자 정보가 있었다.

```text
Creator: Noshiaga (Noshychan)
Inspiration: Shibuya, Tokyo, Japan.
Project Date Start: Feb 19, 2023
Project Date End: Oct 13, 2023
```

이를 검색해 [Noshychan이 공개한 Shibuya Recreation. Sort of....](https://www.planetminecraft.com/project/shibuya-recreation-sort-of/) 월드를 찾았다. 문제에서 제공한 월드는 이 공개 월드를 수정한 것으로 보였다.

### 원본과 제공본 비교

공개된 원본 월드를 내려받아 제공본과 비교했다. 단순히 파일 해시만 비교하면 플레이 시간, 플레이어 위치, 엔티티 상태, 지도 갱신 정보처럼 월드를 실행하는 것만으로 달라지는 값까지 모두 잡힌다. 따라서 Anvil region 파일의 각 청크를 NBT로 파싱하고, 블록 팔레트와 packed block state를 실제 월드 좌표의 블록으로 복원한 뒤 비교했다.

비교 과정은 다음과 같다.

```python
for chunk_position in all_chunk_positions:
    original = decode_chunk(original_world, chunk_position)
    modified = decode_chunk(challenge_world, chunk_position)

    for position in original.keys() | modified.keys():
        if original.get(position, "minecraft:air") != modified.get(position, "minecraft:air"):
            differences.append((
                position,
                original.get(position, "minecraft:air"),
                modified.get(position, "minecraft:air"),
            ))
```

그 결과 의미 있는 블록 변경은 다음 범위에만 존재했다.

```text
X: 0 ~ 148
Y: -62
Z: 0 ~ 6

변경된 블록 수: 339개
변경 내용: minecraft:dirt -> minecraft:redstone_block
```

월드의 스폰 높이는 `Y=-60`이므로 메시지는 스폰 지점 바로 아래의 흙층에 숨겨져 있었다. 변경된 레드스톤 블록을 `X-Z` 평면에 그리자 높이 7블록의 픽셀 문자가 나타났다.

![원본 월드와 제공본의 블록 차이](images/block-diff.png)

문자를 순서대로 읽으면 플래그를 얻을 수 있다. 위 이미지에서는 저장소 규칙에 따라 중괄호 내부를 마스킹했다.

## 플래그

```text
OMNICTF{REDACTED}
```

## 배운 점

이번 문제는 정보보안과 관련된 CTF 문제라기보단 문제 분류도 Game으로 되어 있는 등 기믹성 문제에 가까웠기 때문에 직접 풀어볼 수도 있었지만 이 기회에 AI의 CTF 성능을 테스트해보고 싶었다. AI의 성능은 생각보다 우수했으며 직접 클라이언트를 실행해 마인크래프트로 맵을 둘러볼수 없음에도 우회해서 이미지화 및 인식할 방법이 이미 있었다는 사실을 알게 되었다.
