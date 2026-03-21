#!/usr/bin/env python3
"""Writeup frontmatter 검증 스크립트.

writeups/ 디렉토리 내 모든 README.md 파일의 YAML frontmatter를 검증합니다.
특정 파일만 검증하려면 인자로 경로를 전달하세요.

Usage:
    python scripts/validate_frontmatter.py                          # 전체 검증
    python scripts/validate_frontmatter.py writeups/.../README.md   # 특정 파일 검증
"""

import sys
from pathlib import Path

import frontmatter

REQUIRED_FIELDS = ["ctf_name", "challenge_name", "category", "difficulty", "author", "date"]
VALID_CATEGORIES = {"web", "pwn", "rev", "crypto", "misc"}
VALID_DIFFICULTIES = {"easy", "medium", "hard", "insane"}


def validate_file(filepath: Path) -> list[str]:
    """단일 writeup 파일의 frontmatter를 검증하고 에러 목록을 반환합니다."""
    errors = []

    try:
        post = frontmatter.load(filepath)
    except Exception as e:
        return [f"frontmatter 파싱 실패: {e}"]

    # 필수 필드 검사
    for field in REQUIRED_FIELDS:
        if field not in post.metadata:
            errors.append(f"필수 필드 누락: '{field}'")

    metadata = post.metadata

    # 카테고리 유효값 검사
    category = metadata.get("category")
    if category and category not in VALID_CATEGORIES:
        errors.append(f"유효하지 않은 카테고리: '{category}' (허용: {', '.join(sorted(VALID_CATEGORIES))})")

    # 난이도 유효값 검사
    difficulty = metadata.get("difficulty")
    if difficulty and difficulty not in VALID_DIFFICULTIES:
        errors.append(f"유효하지 않은 난이도: '{difficulty}' (허용: {', '.join(sorted(VALID_DIFFICULTIES))})")

    # 디렉토리 경로와 메타데이터 일치 검증
    parts = filepath.parts
    try:
        writeups_idx = parts.index("writeups")
        if len(parts) >= writeups_idx + 4:
            dir_category = parts[writeups_idx + 2]
            if category and dir_category != category:
                errors.append(
                    f"디렉토리 카테고리 '{dir_category}'와 frontmatter 카테고리 '{category}'가 불일치"
                )
    except ValueError:
        pass  # writeups 디렉토리 외부 파일은 경로 검증 건너뜀

    # 파일명과 author 필드 일치 검증
    expected_author = filepath.stem  # 파일명에서 확장자 제거 (예: alice.md -> alice)
    author = metadata.get("author")
    if author and expected_author != author:
        errors.append(
            f"파일명 '{filepath.name}'과 author 필드 '{author}'가 불일치 "
            f"(파일명을 '{author}.md'로 변경하거나 author를 '{expected_author}'로 수정하세요)"
        )

    # tags 필드 타입 검사
    tags = metadata.get("tags")
    if tags is not None and not isinstance(tags, list):
        errors.append(f"'tags' 필드는 리스트여야 합니다 (현재: {type(tags).__name__})")

    # points 필드 타입 검사
    points = metadata.get("points")
    if points is not None and not isinstance(points, (int, float)):
        errors.append(f"'points' 필드는 숫자여야 합니다 (현재: {type(points).__name__})")

    return errors


def find_writeup_files(paths: list[str] | None = None) -> list[Path]:
    """검증할 writeup 파일 목록을 반환합니다."""
    if paths:
        return [Path(p) for p in paths if Path(p).suffix == ".md"]

    repo_root = Path(__file__).resolve().parent.parent
    writeups_dir = repo_root / "writeups"
    if not writeups_dir.exists():
        return []
    return list(writeups_dir.rglob("*.md"))


def main() -> int:
    files = find_writeup_files(sys.argv[1:] if len(sys.argv) > 1 else None)

    if not files:
        print("검증할 writeup 파일이 없습니다.")
        return 0

    has_errors = False

    for filepath in files:
        errors = validate_file(filepath)
        if errors:
            has_errors = True
            print(f"\n[FAIL] {filepath}")
            for err in errors:
                print(f"  - {err}")
        else:
            print(f"[PASS] {filepath}")

    if has_errors:
        print("\n검증 실패: 위 오류를 수정해주세요.")
        return 1

    print(f"\n전체 {len(files)}개 파일 검증 통과")
    return 0


if __name__ == "__main__":
    sys.exit(main())
