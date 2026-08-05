---
ctf_name: "2026-KaliTeamCTF"
challenge_name: "warmy"
category: "rev"           # web / pwn / rev / crypto / misc
difficulty: "medium"      # easy / medium / hard / insane
author: "ansihoo"
date: "2026-08-06"
points: 500
tags: [anti-symbolic, arx]
---

# 문제명
- warmy

## 문제 설명

> 제공 파일: faultline(ELF64, PIE, stripped), faultline.map(magic FLT2)

## 풀이

### 분석

맵은 78바이트 헤더 + 256×24바이트 레코드 구조이고, 헤더에 flag 길이(42), VM 스텝 수(104), 시드가 들어 있다. main은 입력을 48바이트 버퍼 Q에 담아 Q = flag XOR K(맵 시드로 만든 splitmix64 keystream)로 변환한 뒤, 맵이 정의한 104스텝 VM을 돌려 Q를 변형하고, 최종 Q == KS(맵 파생 상수)면 통과시킨다.

핵심은 이 VM이 fault로 흐름을 숨긴다는 점이다. 매 스텝 서브루틴이 mode에 따라 ud2(SIGILL)·div 0(SIGFPE)·널 쓰기(SIGSEGV)로 예외를 고의 유발하고, 시그널 핸들러가 예외 종류별로 Q에 가역 연산(ADD, XOR, 회전, 배열 rotate, 홀수 모듈러 곱)을 수행한 뒤 longjmp로 복귀한다.

### 취약점

메모리 버그가 아니라 anti-analysis(심볼릭 실행 방해) 설계의 구조적 허점이다. VM 명령열이 맵에서만 나와 입력과 무관하게 고정이고 모든 연산이 가역이라, 정방향을 이해할 필요 없이 KS에서 거꾸로 되돌려 flag = SM⁻¹(KS) XOR K로 유일 해가 나온다.

### 익스플로잇

디버거를 전혀 쓰지 않고 faultline.map 파일 하나만으로 오프라인에서 풀었다. fault-VM이 사용하는 모든 값(명령 시퀀스·목표 상수 KS·keystream K)이 오직 맵에서만 결정되므로, 바이너리 로직을 파이썬으로 재구현하면 실행 자체가 필요 없다.

핵심은 격자(cartography) 다. 좌표 (X,Y)는 헤더 시드로 초기화되고 idx = X + 16·Y로 256개 레코드 중 하나를 가리킨다. 각 레코드 24바이트를 splitmix64 키스트림으로 복호하면 24바이트 "명령"이 나오고, 명령의 6번째 바이트가 이동 방향을 정해 다음 좌표로 넘어간다. 이렇게 104스텝을 돌며 명령을 뽑고 동시에 내부 해시 H를 갱신한다. 마지막 H와 헤더 바이트로 목표 상수 KS가 만들어진다. 그다음 여섯 연산의 역연산을 KS에 역순으로 적용해 Q₀ = SM⁻¹(KS)를 얻고, 맵 시드 keystream K를 벗겨 flag = Q₀ XOR K.

```python
import sys
M = (1 << 64) - 1
C1, C2 = 0xbf58476d1ce4e5b9, 0x94d049bb133111eb
def sm(x):
    a=(x^(x>>30))&M; a=(a*C1)&M; a=(a^(a>>27))&M; a=(a*C2)&M; return (a^(a>>31))&M
def rol(x,r): r&=63; return ((x<<r)|(x>>(64-r)))&M if r else x&M
def ror(x,r): r&=63; return ((x>>r)|(x<<(64-r)))&M if r else x&M

mp   = open(sys.argv[1] if len(sys.argv)>1 else "faultline.map","rb").read()
SEED = int.from_bytes(mp[0x0e:0x16],"little")
N    = int.from_bytes(mp[0x06:0x08],"little")     # 104
FLEN = int.from_bytes(mp[0x08:0x0a],"little")     # 42
recs = mp[0x4e:]

X = ((SEED>>8)&0xf)^mp[0x0c]; Y = ((SEED>>0x14)&0xf)^mp[0x0d]
H = sm(SEED ^ 0x1bd11bdaa9fc1a22)
tblA, tblB = (-1,0,1,0), (0,1,0,-1)               # 바이너리 0x2050 / 0x2060
R10, R11, MUL, GOLD = 0xa0761d6478bd642f, 0x6a09e667f3bcc909, 0xd6e8feb86659fd93, 0x9e3779b97f4a7c15
steps = []
for c in range(N):
    idx = (X+(Y<<4))&0xffffffff
    rec, rsi, out = recs[idx*24:idx*24+24], (idx*MUL)&M, b""
    for j in range(3):
        out += ((int.from_bytes(rec[j*8:j*8+8],"little") ^ sm((SEED^((j*R10)&M)^rsi^R11)&M))&M).to_bytes(8,"little")
    steps.append(out)
    q2 = int.from_bytes(out[16:24],"little")
    H  = sm((H ^ q2 ^ Y ^ ((X<<8)&M) ^ ((c*GOLD)&M))&M)
    d  = out[5]&3; X += tblB[d]; Y += tblA[d]

KS = bytes(((sm(((i>>3)*0xe7037ed1a0b428db ^ H ^ 0x243f6a8885a308d3)&M)>>((i&7)*8))&0xff) ^ mp[0x16+i] for i in range(48))

K  = b"".join(sm((SEED^((i*GOLD)&M))^0xbadc0ffee0ddf00d).to_bytes(8,"little") for i in range(6))

def fields(b): return b[0],b[1],b[2],b[3],b[4],int.from_bytes(b[6:8],"little"),int.from_bytes(b[8:16],"little")
def ODD(w):    return (((w*0x0001000000010000)|((w^0xa55a)&0xffff))|1)&M
to_q = lambda b:[int.from_bytes(b[i*8:i*8+8],"little") for i in range(6)]
to_b = lambda Q:b"".join((x&M).to_bytes(8,"little") for x in Q)
def inv_op(Q, ins):
    Q=Q[:]; m0,m1,m2,m3,m4,w,Kc = fields(ins)
    if m0==0:                                     # SIGILL
        d,s=m2%6,m3%6
        Q[d]=(Q[d]-rol(Q[s]^Kc,m4))&M if m1==0 else (((Q[d]*pow(ODD(w),-1,1<<64))&M)-Kc)&M
    elif m0==1:                                   # SIGFPE
        d,s,r=m2%6,m3%6,m4&0x3f
        if m1==0: o=Q[d]; Q[d]=(Q[s]^rol((Kc+o)&M,r))&M; Q[s]=o
        else:     Q[d]=(Q[d]^rol((Q[s]^Kc)&M,r))&M
    else:                                         # SIGSEGV
        if m1==0: off=(m2%6)%5; Q=[Q[(j+off+1)%6] for j in range(6)]
        else:     i=m2%6; Q[i]=(ror(Q[i],m4)^Kc)&M
    return Q

Q = to_q(KS)
for ins in reversed(steps): Q = inv_op(Q, ins)
print(bytes(a^b for a,b in zip(to_b(Q), K))[:FLEN].decode())
```

## 플래그

```
KaliTeam{faults_draw_the_only_honest_path}
```

## 배운 점

fault(SIGILL/SIGFPE/SIGSEGV)와 setjmp/longjmp를 엮은 제어 흐름 난독화는 정적 분석과 심볼릭 실행(angr 등)을 효과적으로 방해하지만, 검증에 쓰이는 값들이 결국 입력과 무관하게 맵에서만 결정되고 모든 연산이 가역이라면, 디버거로 실행할 필요조차 없이 그 생성 로직을 그대로 재구현해 거꾸로 되돌리는 것만으로 유일한 정답을 얻을 수 있다. anti-analysis 리버싱에서 실행을 흉내 내지 말고, 데이터가 어디서 오는지를 추적해 오프라인으로 재현하라는 접근이 강력하다는 걸 배웠다.
