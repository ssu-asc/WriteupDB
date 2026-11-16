---

ctf_name: "2026 BYUCTF"
challenge_name: "Hometown Hero Series"
category: "misc"
difficulty: "medium"
author: "Chik0magenta"
date: "2026-05-31"
tags: [osint, social-media, quora, whitepages, zillow, ifi, geolocation]
------------------------------------------------------------------------

# Hometown Hero Series

## 문제 설명

BYU 학생 Cameron Snider에 대한 공개 정보를 조사하여 다음 정보를 찾아내는 연속 OSINT 문제 시리즈이다.

1. 성장한 도시와 주
2. 다녔던 초등학교
3. 어린 시절 집의 매각 금액
4. 고등학교 졸업 후 여름에 번 금액
5. 고등학교 시절 배운 외국어

## 풀이

### 1. Hometown Hero 1

먼저 Cameron Snider의 공개 프로필을 찾기 위해 검색을 진행하였다.

```text
Cameron Snider graduation
```

검색 결과 Quora 프로필을 발견하였다.

처음에는 동명이인 가능성을 고려했으나, Facebook에서 확인했던 Darth Revan 프로필 사진과 동일한 사진을 사용하고 있어 본인 계정으로 판단하였다.

Quora 프로필에서 다음 정보를 확인하였다.

```text
Lives in Kearney, Nebraska
Studied at Richmond High School
```

이를 통해 Cameron이 성장한 지역이 Kearney, Nebraska임을 확인하였다.

플래그:

```text
byuctf{Kearney:Nebraska}
```

---

### 2. Hometown Hero 2

처음에는 Cameron의 어린 시절 주소를 찾고 학군을 역추적하는 방향으로 접근하였다.

이후 Whitepages와 Zillow를 통해 확보한 주소를 기반으로 Meadowlark Elementary를 추정했으나 오답이었다.

접근 방향을 변경하여 Kearney 지역 신문을 조사하던 중 다음 기사를 발견하였다.

```text
Second-graders brighten holiday for military
```

기사에는 다음과 같은 내용이 포함되어 있었다.

```text
Park Elementary School second-graders,
Clay Gilg,
Cameron Snider,
Ella Murray,
...
```

즉 Cameron이 초등학교 재학 당시 등장한 기사였으며, 이를 통해 초등학교를 확인할 수 있었다.

플래그:

```text
byuctf{Park_Elementary}
```

---

### 3. Hometown Hero 3

1번 문제를 조사하던 중 Quora 팔로워 목록에서 Laura Snider를 발견하였다.

가족일 가능성이 높다고 판단하여 Whitepages를 통해 Laura Snider의 공개 정보를 확인하였다.

그 결과 다음 주소를 확보할 수 있었다.

```text
4103 Fairacres Rd
Kearney, Nebraska
```

해당 주소를 Zillow에서 조회한 결과 다음 매각 기록을 확인할 수 있었다.

```text
10/26/2018 Sold
$200,000
```

플래그:

```text
byuctf{$200,000}
```

---

### 4. Hometown Hero 4

LinkedIn 프로필을 통해 Cameron이 Richmond Community Schools에서 근무한 이력을 확인하였다.

처음에는 Substitute Teacher 일당과 근무일수를 계산하여 금액을 추정하려 했으나 모두 오답이었다.

이후 Indiana 공공 급여 데이터베이스를 조사하던 중 다음 사이트를 발견하였다.

```text
gateway.ifionline.org
```

Richmond Community School Corporation의 2023년 기록을 검색한 결과 다음 정보를 확인하였다.

```text
Snider, Cameron J
SUMMER STUDENT MAINTENANCE
Compensation in 2023
$1,081.08
```

문제에서는 소수점 이하를 제외한 금액을 요구하였다.

플래그:

```text
byuctf{$1,081}
```

---

### 5. Hometown Hero 5

처음에는 Richmond High School의 교육과정을 조사하였다.

미국 고등학교에서 가장 흔한 외국어인 Spanish를 제출하였으나 오답이었다.

이후 1번 문제를 조사하던 과정에서 발견했던 선교사 프로필을 다시 확인하였다.

Called to Serve 프로필에서 다음 정보를 확인할 수 있었다.

```text
France Lyon Mission
Mission Language: French
```

선교 언어는 일반적으로 고등학교에서 배운 외국어와 연결되므로 French를 정답으로 판단하였다.

플래그:

```text
byuctf{French}
```

## 정리

이번 시리즈는 하나의 정보원으로 해결되는 문제가 아니라 여러 공개 정보원을 연결해야 해결할 수 있는 OSINT 문제였다.

활용한 주요 정보원은 다음과 같다.

```text
Quora
Facebook
Whitepages
Zillow
Kearney Hub
LinkedIn
IFI Online
Called to Serve
```

특히 인상적이었던 점은 단순 추론보다 공개 기록을 확보하는 것이 훨씬 강력하다는 사실이었다.

초등학교 문제에서는 학군을 이용한 추론이 실패했지만, 지역 신문 기사 한 건으로 정답을 확인할 수 있었고, 수입 문제 역시 급여를 계산하는 대신 공공 급여 기록을 조회하여 해결할 수 있었다.

## 배운 점

* OSINT에서는 추론보다 기록이 우선이다.
* 여러 플랫폼의 정보를 교차 검증하는 과정이 중요하다.
* 가족, 주소, 학교, 직장 정보는 서로 연결되는 경우가 많다.
* Zillow, Whitepages, IFI Online과 같은 공개 데이터베이스는 매우 유용한 정보원이 될 수 있다.
* 처음에는 중요해 보이지 않는 단서도 이후 문제의 결정적인 힌트가 될 수 있다.
