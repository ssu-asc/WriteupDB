---
ctf_name: "Junior Crypt 2026 CTF"
challenge_name: "Invisible Editor"
category: "misc"
difficulty: "easy"
author: "sihyunkimm"
date: "2026-07-11"
points: 100
tags: [docx, xml, forensics]
---

# Invisible Editor

## 문제 설명

> My teammate sent me a file with a flag, but I can't see it. Help me find it.

- 제공 파일: `invisible_editor.docx`

## 풀이

### 분석

제공된 파일은 `docx` 문서입니다. `docx`는 내부적으로 여러 XML 파일을 ZIP 형식으로 묶은 구조이므로, 문서 내용을 직접 확인하기 위해 확장자를 `.zip`으로 변경한 뒤 압축을 해제했습니다.

압축을 해제한 결과 일반적인 문서 본문이 들어 있는 `word/document.xml` 외에도 `customXml` 폴더가 존재했습니다. 이 폴더 안의 `item1.xml`을 확인하니 `revisionLog` 형태의 데이터가 있었고, 편집 과정에서 삽입되거나 삭제된 문자열 조각들이 남아 있었습니다.

### 취약점

문서에서 최종적으로 보이지 않는 내용이라도, 내부 XML이나 사용자 정의 XML 데이터에 편집 이력 또는 중간 문자열을 남길 수 있습니다.

### 익스플로잇

1. `invisible_editor.docx`의 확장자를 `.zip`으로 변경합니다.
2. ZIP 파일의 압축을 해제합니다.
3. 압축 해제된 디렉터리에서 `customXml/item1.xml`을 확인합니다.
4. `revisionLog` 안의 `inserted` 값들을 따라가면 플래그 형식의 문자열이 만들어진 흔적을 확인할 수 있습니다.

## 플래그

```
grodno{REDACTED}
```

## 배운 점

- 문서 본문에 보이지 않는 데이터를 의도적으로 `customXml` 같은 내부 경로에 숨길 수 있습니다.
