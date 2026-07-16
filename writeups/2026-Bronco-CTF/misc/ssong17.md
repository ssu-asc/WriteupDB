---
ctf_name: "Bronco CTF 2026"
challenge_name: "Bundle 99"
category: "misc"
difficulty: "easy"
author: "ssong17"
date: "2026-07-12"
points: 10
tags: []
---

# 문제명

## 문제 설명

Yoshie found this random file laying around. Do you have any idea what this "bundle" is?

Apparently someone told him it's the 99th bundle of brushes?

What is that supposed to mean...

P.S. This challenge can be solved without downloading any software, but you'll have to hunt for a way to run the related program online and send the bundle to it.

bundle_99 ELF 문제 파일

---

## 풀이

 주어진 `Bundle_99` 파일을 `file` 명령으로 확인하면 확장자는 없지만 실제로는 ZIP 컨테이너이며 `application/x-krita-resourcebundle` MIME 타입, 즉 Krita의 브러시 번들(.bundle) 파일임을 알 수 있다.

`unzip`으로 풀면 `paintoppresets/Brush 99.kpp`, `meta.xml`,`META-INF/manifest.xml`, `preview.png` 가 나온다. `meta.xml`의 description에는 "99 bundles of brushes on the wall..." 이라는 문제 이름에 대한 말장난이 들어있다.

`.kpp`(Krita paintop preset) 파일은 사실 PNG 파일이며, PNG의 tEXt 청크에 브러시 설정을 XML로 저장한다. Pillow로 열어 `img.info["preset"]`을 확인하면 브러시 설정 전체 XML을 얻을 수 있다.

설정 XML 안에서 이 브러시가 `type="kis_text_brush"`(문자열을 붓 자국으로 찍는 텍스트 브러시)이고, 해당 태그의 `text` 속성 값이 곧 플래그임을 확인한다.

---

### 익스플로잇

파일을 다운로드하지 않고도, 브라우저 기반 Krita 데모/온라인 에디터에 `Bundle_99`를 리소스 번들로 임포트한 뒤 "Brush 99" 프리셋으로 캔버스에 칠하면 텍스트 브러시가 찍는 글자가 곧바로 플래그가 된다. (로컬에서는 PNG 메타데이터만 파싱해도 동일하게 확인 가능.)

```python
from PIL import Image
img = Image.open("paintoppresets/Brush 99.kpp")
print(img.info["preset"])
# ...  ...
```

---

## 플래그

```
bronco{1m4n4rt15ttru5t}
```

---

## 배운 점
