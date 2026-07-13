---
ctf_name: "LYKNCTF 2026"
challenge_name: "I HATE THIS APP"
category: "rev"           # web / pwn / rev / crypto / misc
difficulty: "easy"      # easy / medium / hard / insane
author: "yuninam2128"
date: "2026-07-07"
points: 100
tags: [tauri, windows-api, static-analysis, disassembly]
---

# I HATE THIS APP

## 문제 설명

> Aughhh, how the hell can I not take a screenshot of this freaking app? I... I mean... It feels like the app is transparent to my screen. I can see it, but I can't capture it. Why? Am I living in a simulation or something?
>
> Your mission is to find the function that prevents me from taking screenshots.
> FLAG FORMAT: LYKNCTF{function_name} All letters must be lowercase, and there must be no spaces.

- 문제 파일 : `fuoverflow_learning.rar`
- 출제자 : lizzythecatto

화면에는 앱이 **보이는데** 스크린샷을 찍으면 캡처가 안 된다("transparent to my screen")는 게 핵심 단서다. 스크린샷을 막는 함수 이름을 찾는 리버싱 문제.

## 풀이

### 분석

먼저 압축을 풀어 실행 파일을 확인했다.

```bash
$ unrar x fuoverflow_learning.rar
$ file fuoverflow_learning.exe
fuoverflow_learning.exe: PE32+ executable (GUI) x86-64, for MS Windows, 6 sections
```

17MB가 넘는 큰 GUI 실행 파일이다. 문자열을 살펴보면 이 앱의 정체가 드러난다.

```bash
$ strings fuoverflow_learning.exe | grep -iE "tauri|wry|webview2|tao::"
tauri
wry
WebView2
tao::window::...
```

`tauri`, `wry`, `WebView2`, `tao` 문자열이 보인다. 즉 이 앱은 **Tauri**(Rust 백엔드 + WebView2 프론트엔드)로 만들어진 데스크톱 앱이다.

여기서 문제의 증상을 다시 생각해 본다. "화면에는 보이는데 캡처하면 안 나온다"는 것은 창을 **화면 캡처 대상에서만 제외**하는 동작이다. Windows에서 이 기능을 담당하는 API는 딱 하나로 좁혀진다.

```bash
$ strings fuoverflow_learning.exe | grep -i affinity
SetWindowDisplayAffinity
```

`SetWindowDisplayAffinity`가 import 되어 있다. 이 API에 `WDA_EXCLUDEFROMCAPTURE`(Windows 10 2004+에서 추가) 플래그를 주면, 창은 정상적으로 화면에 렌더링되지만 스크린샷/화면 녹화에서는 완전히 제외된다. 증상과 정확히 일치한다.

Tauri에서는 이 동작을 하부 윈도우 라이브러리 `tao`의 `set_content_protection()`이 감싸고 있고, `tauri.conf.json`의 `contentProtected: true` 설정으로 켤 수 있다. 실제로 바이너리에도 관련 문자열이 남아 있었다.

```bash
$ strings fuoverflow_learning.exe | grep -iE "content_protected|contentProtected"
set_content_protected      # Tauri 플러그인 커맨드
contentProtected           # config 키
setContentProtected        # JS API
```

그러나 문제는 "스크린샷을 막는 **함수**"를 묻고 있고, 실제로 그 동작을 수행하는 함수는 config 키나 래퍼가 아니라 최종적으로 호출되는 Win32 API다. 이를 정적 분석으로 확실히 증명했다.

### 취약점 (동작 원리 확인)

추측만으로 제출하지 않고, `SetWindowDisplayAffinity`가 실제로 캡처 제외 플래그와 함께 호출되는지 디스어셈블로 확인했다.

먼저 IAT에서 해당 API의 주소를 찾는다.

```python
import pefile
pe = pefile.PE("fuoverflow_learning.exe")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in entry.imports:
        if imp.name and b"DisplayAffinity" in imp.name:
            print(imp.name.decode(), hex(imp.address))
# SetWindowDisplayAffinity 0x140b1aaa8
```

이 IAT 주소(`0x140b1aaa8`)를 `call qword ptr [rip+disp]`(`FF 15`) 형태로 호출하는 위치를 `.text`에서 스캔하면 3군데가 나온다. `.pdata`(예외 테이블)로 각 호출을 감싸는 함수 경계를 구한 뒤, 가장 얇은 래퍼 함수(`0x14098c580`, 크기 0x50)를 디스어셈블했다.

```asm
0x14098c580  sub    rsp, 0x38
0x14098c584  mov    rcx, qword ptr [rcx + 8]   ; hwnd
0x14098c588  xor    eax, eax                    ; eax = 0  (WDA_NONE)
0x14098c58a  test   dl, dl                      ; enabled 인자 검사
0x14098c58c  mov    edx, 0x11                    ; 0x11 = 17 = WDA_EXCLUDEFROMCAPTURE
0x14098c591  cmove  edx, eax                     ; enabled ? 0x11 : 0
0x14098c594  call   qword ptr [rip + 0x18e50e]   ; -> SetWindowDisplayAffinity(hwnd, dwAffinity)
0x14098c59a  test   eax, eax
...
```

`mov edx, 0x11` → `WDA_EXCLUDEFROMCAPTURE`, 그리고 `cmove`로 `enabled ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE`을 골라 `SetWindowDisplayAffinity(hwnd, ...)`를 호출한다. 이는 `tao`의 `set_content_protection` 구현 그대로이며, 스크린샷을 막는 실체가 `SetWindowDisplayAffinity`임을 확정한다.

바이너리에 실제 문자열로 존재하는 Win32 함수명도 이것뿐이었다.

```bash
$ python3 -c "print(open('fuoverflow_learning.exe','rb').read().count(b'SetWindowDisplayAffinity'))"
1
```

### 익스플로잇

플래그 포맷은 `LYKNCTF{function_name}`이고, "모든 글자는 소문자, 공백 없음" 조건이 붙어 있다. 스크린샷을 막는 함수 `SetWindowDisplayAffinity`를 소문자로 바꿔 제출한다.

```text
SetWindowDisplayAffinity  ->  setwindowdisplayaffinity
```

> ⚠️ 주의: 이름이 길어서 손으로 치면 틀리기 쉽다. `affinity`는 f 2개, i 3개 위치(aff**i**n**i**ty)다. 언더스코어 없이 그대로 붙여 쓴다.

## 플래그

```text
LYKNCTF{setwindowdisplayaffinity}
```

## 배운 점

- "화면엔 보이는데 캡처만 안 된다"는 증상은 곧바로 Windows의 `SetWindowDisplayAffinity` + `WDA_EXCLUDEFROMCAPTURE`를 가리킨다. 증상 → API 매핑을 알고 있으면 절반은 푼 셈이다.
- Tauri/Electron 앱은 표면적으로 `contentProtected` 같은 config 키나 `set_content_protected` 같은 래퍼가 여러 겹 존재한다. "함수"를 물을 때는 이런 래퍼가 아니라 **최종적으로 OS에 명령을 내리는 API**가 답일 가능성이 높다.
- 추측한 함수명이 여러 개일 때는 IAT → 호출부(`FF 15`) → `.pdata` 함수 경계 → 디스어셈블 순서로 **실제 호출 인자(0x11 = WDA_EXCLUDEFROMCAPTURE)** 까지 확인하면 확실하게 하나로 좁힐 수 있다.
