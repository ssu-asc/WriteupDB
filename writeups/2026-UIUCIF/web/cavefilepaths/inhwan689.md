---
ctf_name: "UIUCTF"
challenge_name: "CaveFilePaths"
category: "web"           # web / pwn / rev / crypto / misc
difficulty: "easy"      # easy / medium / hard / insane
author: "inhwan689"
date: "2026-08-09"
points: 0
tags: [ifi]
---

# 문제명

## 문제 설명

> Deep beneath the mountain lies the Sword of Mastery. The cave keeper left a tiny file reader and a handful of notes, but the chest itself is hidden off the marked trail. Follow the paths carefully.

- 문제 URL: https://cave-file-paths.chal.uiuc.tf/
- 제공 파일: handout.tar.gz

## 풀이

### 분석

app.py의 핵심은 /read 엔드포인트다. file 파라미터로 받은 이름을 서버에서 읽어 반환한다.
```python

@app.get("/read")
def read_cave_file():
    filename = request.args.get("file", "torch.txt")

    if os.path.isabs(filename):   # <--- 필터링 로직1
        abort(400, description="The cave map only understands relative paths.")

    filename = filename.replace("../", "")   # <--- 필터링 로직2
    requested_path = PUBLIC_CAVE_DIR / filename

    if not requested_path.is_file():
        abort(404, description="That passage does not seem to exist.")

    return send_file(requested_path, mimetype="text/plain")
```
방어는 두 가지다.

1. os.path.isabs() — 절대경로 차단
2. filename.replace("../", "") — 상위 디렉터리 이동 문자열 ../ 제거.

### 취약점

str.replace("../", "")는 한 번만 삭제한다. 즉 문자열을 훑으며 발견한 ../를 지우고 다시 검사하지 않는다.

따라서 입력에 ....//를 넣으면:
....//   -->   "../"를 한 번 제거 -->  남은 것:  "../"

디렉터리 구조상 현재 위치가 /cave_files이고 상자는 /private /secret_chest.txt에 있으므로, cave_files에서 한 단계 위로만 올라가면 된다.

### 익스플로잇

실제 최종 URL:

https://cave-file-paths.chal.uiuc.tf/read?file=....//private/secret_chest.txt

응답:

The ancient chest opens. Inside rests the Sword of Mastery. uiuctf{path_traversal_opens_the_chest}

## 플래그

```
uiuctf{REDACTED}
```

## 배운 점

- 블랙리스트/문자열 치환 기반 필터링은 신뢰할 수 없다. replace("../", "")처럼 위험한 부분을 지우는 방식은 ....//, ..././, ....\/ 의 경우와 같이 지운 뒤 남은 결과가 다시 위험해질 수 있다.
- 절대경로 차단은 이 문제에선 유효했지만, 상대경로 순회를 못 막으므로 절대경로 차단만으로는 LFI 방어가 완결되지 않는다.
