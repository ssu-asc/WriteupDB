---
ctf_name: "gaslightCTF 2026"
challenge_name: "biscuit"
category: "web"           # web / pwn / rev / crypto / misc
difficulty: "easy"      # easy / medium / hard / insane
author: "minyoung13"
date: "2026-08-17"
points: 100
tags: [biscuit, injection]
---

# biscuit

## 문제 설명

> Hello world! _italics_ **bold**

- 주어진 링크를 통해 문제 인스턴스를 생성할 수 있다.
- 첨부파일: `app.py`, `Dockerfile`, `requirements.txt`, `static/`, `templates/`

## 풀이

### 분석

해당 문제는 Flask를 이용해 구현된 간단한 웹 애플리케이션이다. 회원가입, 로그인, 투표, `/flag` 조회 기능을 제공한다.

인증에는 일반적인 세션 대신 `biscuit-python` 라이브러리의 Biscuit 토큰이 사용된다. 사용자가 회원가입하거나 로그인하면 서버는 `mint(username)` 함수를 통해 Biscuit 토큰을 생성하고, 이 토큰은 `biscuit` 쿠키에 저장된다.

```python
def mint(username: str) -> str:
    builder = BiscuitBuilder(
        f"""
        user("{username}");
        check if user($u), $u.length() > 0;
        """,
    )
    if username == "webmaster":
        builder.add_fact(Fact('role("admin")'))
    return builder.build(root.private_key).to_base64()
```

`/flag` 엔드포인트는 현재 사용자가 로그인되어 있는지 확인한 뒤, 아래의 policy를 이용하여 admin인지 검사한다.

```python
def current_admin() -> str | None:
    return _authorize('allow if user($u), role("admin");')
```

유효한 서명을 가진 토큰 안에 `user(...)` fact와 `role("admin")` fact가 함께 존재하면 admin으로 인정된다. 
따라서 flag를 얻기 위해서는 유효한 Biscuit 토큰 안에 `role("admin")` fact가 들어 있어야 한다.

username이 `webmaster`인 경우 `role("admin")` fact가 추가되지만 해당 username에 대한 password가 제공되지 않고, 이미 존재하는 username이기 때문에 동일한 username으로 회원가입하는 것도 불가능하다.

이 문제의 취약점은 Biscuit 토큰을 생성할 때 사용자 입력을 Biscuit DSL 문자열에 그대로 삽입하는 부분에서 발생한다.

### 취약점

핵심은 서버가 토큰을 만들 때 사용하는 Biscuit DSL 문자열에 `role("admin")` fact를 주입하는 것이다.

mint() 함수에서 사용자 입력값인 username을 Biscuit DSL 문자열에 escape 없이 직접 삽입하고 있다. 따라서 username에 큰따옴표와 세미콜론을 포함한 값을 넣으면 Biscuit DSL 문법을 깨고 새로운 fact를 주입할 수 있다.

username을 `u1");role("admin");user("u1`로 설정하면,

서버에서 생성되는 Biscuit DSL은 다음과 같은 형태가 된다.
```
user("u1");
role("admin");
user("u1");
check if user($u), $u.length() > 0;
```

결과적으로 서버가 직접 서명한 정상 Biscuit 토큰 안에 `role("admin")` fact가 포함된다. 이후 `/flag` 접근 시 admin 검사를 통과할 수 있다.

### 익스플로잇

1. 회원가입 페이지에서 username에 Biscuit DSL injection payload를 넣는다.

    payload: `u1");role("admin");user("u1`

2. 서버는 해당 username으로 Biscuit 토큰을 생성하고, 생성된 토큰에는 `role("admin")` fact가 포함된다.

3. 발급받은 쿠키를 유지한 채 /flag에 접근한다.

4. admin 권한으로 인식되어 flag가 출력된다.

## 플래그

```
gaslightCTF{REDACTED}
```

## 배운 점

- Biscuit은 authorization token을 만들기 위한 라이브러리이다. JWT처럼 클라이언트가 토큰을 들고 다니지만, 단순히 claim을 저장하는 것에서 더 나아가 Datalog 기반의 fact, rule, check, policy를 이용해 권한을 표현한다.
    - 이 문제에서 서버는 `KeyPair()`로 root key pair를 생성하고, `BiscuitBuilder`를 이용해 토큰에 fact와 check를 넣은 뒤 private key로 서명한다. 이후 요청이 들어오면 쿠키의 Biscuit 토큰을 public key로 검증하고, `Authorizer`를 통해 특정 policy를 만족하는지 검사한다.
        ```
        user("alice"); # fact
        check if user($u), $u.length() > 0;  # check
        ```
- 서명된 토큰을 사용하여 권한을 검사하더라도, 토큰 생성 단계에서 공격자가 원하는 fact를 넣을 수 있다면 인증 우회가 가능하다.
- DSL, SQL, shell command, template 등 문자열 기반 문법에 사용자 입력을 직접 삽입하면 injection 취약점이 발생할 수 있다. 라이브러리에서 제공하는 API를 사용하는 것이 좋다.