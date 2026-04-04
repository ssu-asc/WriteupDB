---
ctf_name: "SillyCTF 2026"
challenge_name: "six-to-seven"
category: "crypto"
difficulty: "medium"
author: "oscarjhk"
date: "2026-04-04"
tags: [pptx, encoding, binary]
---

# six-to-seven

## 문제 설명

> Our director of silly loves the 6 7 dance.

- 제공 파일: `sixtotheseven.pptx`

## 풀이

### 분석

처음에는 PowerPoint 파일이라서 슬라이드에 숨겨진 텍스트나 이미지 스테가노그래피를 의심했다.
하지만 `pptx`는 ZIP 컨테이너이므로 압축을 풀어 내부 구조를 확인하는 것이 더 빠르다.

```bash
unzip -l sixtotheseven.pptx
```

확인해 보면 슬라이드가 215장 있고, 각 슬라이드에는 텍스트 대신 이미지 하나만 들어 있다.
슬라이드가 참조하는 이미지는 사실상 세 종류뿐이다.

- `image2.png`: 손 위에 `6`
- `image3.png`: 손 위에 `7`
- `image4.jpg`: 숫자가 없는 중간 자세

즉 이 문제는 슬라이드 순서를 따라 `6`, `7`, 그리고 구분자를 읽는 인코딩 문제라고 볼 수 있다.

### 인코딩 규칙 찾기

각 슬라이드의 관계 파일 `ppt/slides/_rels/slideN.xml.rels`에는 해당 슬라이드가 어떤 이미지를 참조하는지가 기록되어 있다.
슬라이드 순서대로 이를 읽으면 다음과 같은 패턴이 나온다.

```text
67776677_67767667_67767766_67767766_67777667_67666677_...
```

여기서:

- `image2.png` -> `6`
- `image3.png` -> `7`
- `image4.jpg` -> `_` (구분자)

로 해석하면 된다.

구분자 `_`로 나누면 정확히 24개의 8자리 블록이 나온다.
따라서 각 블록은 1바이트이며, 자연스럽게 `6 -> 0`, `7 -> 1`로 치환해 볼 수 있다.

예를 들면:

```text
67776677 -> 01110011 -> 0x73 -> 's'
67767667 -> 01101001 -> 0x69 -> 'i'
```

이 변환을 전체에 적용하면 ASCII 문자열이 복원된다.

### 익스플로잇

아래 솔버는 `pptx` 내부 XML을 직접 읽어 슬라이드 순서를 복원하고, 각 슬라이드가 참조하는 이미지를 `6/7/_`로 변환한 뒤 플래그 문자열을 디코드한다.

```python
IMAGE_TO_SYMBOL = {
    "image2.png": "6",
    "image3.png": "7",
    "image4.jpg": "_",
}
```

전체 코드는 같은 디렉터리의 `solve.py`에 첨부했다.

실행:

```bash
python3 solve.py sixtotheseven.pptx
```

## 플래그

```text
sillyCTF{REDACTED}
```

## 배운 점

- `pptx`는 문서 파일이라기보다 ZIP 기반 컨테이너이므로 내부 XML 관계 파일을 먼저 보는 편이 빠르다.
- 이미지 자체를 분석하지 않아도, 어떤 리소스가 어떤 순서로 참조되는지만으로도 충분히 데이터가 숨어 있을 수 있다.
- 문제 설명의 `6 7 dance` 힌트는 결국 두 값으로 이루어진 이진 인코딩을 가리키고 있었다.
