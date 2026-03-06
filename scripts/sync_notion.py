#!/usr/bin/env python3
"""Writeup을 Notion DB에 동기화하는 스크립트.

변경된 writeup 파일의 frontmatter를 파싱하여 Notion DB에 생성/업데이트합니다.

Usage:
    python scripts/sync_notion.py writeups/.../README.md [...]

Environment:
    NOTION_API_KEY       - Notion Internal Integration Token
    NOTION_DATABASE_ID   - 대상 Notion Database ID
    GITHUB_REPOSITORY    - GitHub 레포 (owner/repo 형식, Actions에서 자동 설정)
    GITHUB_SERVER_URL    - GitHub 서버 URL (Actions에서 자동 설정)
"""

import os
import sys
from pathlib import Path

import frontmatter
from notion_client import Client


def get_notion_client() -> Client:
    api_key = os.environ.get("NOTION_API_KEY")
    if not api_key:
        print("Error: NOTION_API_KEY 환경변수가 설정되지 않았습니다.")
        sys.exit(1)
    return Client(auth=api_key)


def get_database_id() -> str:
    db_id = os.environ.get("NOTION_DATABASE_ID")
    if not db_id:
        print("Error: NOTION_DATABASE_ID 환경변수가 설정되지 않았습니다.")
        sys.exit(1)
    return db_id


def build_github_url(filepath: Path) -> str:
    """writeup 파일의 GitHub URL을 생성합니다."""
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not repo:
        return ""
    # writeups/ 이하 상대 경로 사용
    return f"{server}/{repo}/blob/main/{filepath}"


def parse_writeup(filepath: Path) -> dict:
    """writeup 파일의 frontmatter를 파싱합니다."""
    post = frontmatter.load(filepath)
    return post.metadata


def find_existing_page(notion: Client, database_id: str, ctf_name: str, challenge_name: str) -> str | None:
    """CTF명+문제명으로 기존 Notion 페이지를 검색합니다. 있으면 page_id 반환."""
    response = notion.databases.query(
        database_id=database_id,
        filter={
            "and": [
                {
                    "property": "대회명",
                    "rich_text": {"equals": ctf_name},
                },
                {
                    "property": "문제명",
                    "title": {"equals": challenge_name},
                },
            ]
        },
    )
    results = response.get("results", [])
    return results[0]["id"] if results else None


def build_properties(metadata: dict, github_url: str) -> dict:
    """frontmatter 메타데이터를 Notion properties로 변환합니다."""
    properties = {
        "문제명": {"title": [{"text": {"content": metadata.get("challenge_name", "")}}]},
        "대회명": {"rich_text": [{"text": {"content": metadata.get("ctf_name", "")}}]},
        "분야": {"select": {"name": metadata.get("category", "misc").upper()}},
        "난이도": {"select": {"name": metadata.get("difficulty", "medium")}},
        "작성자(학번_이름)": {"rich_text": [{"text": {"content": metadata.get("author", "")}}]},
    }

    # 날짜
    date = metadata.get("date")
    if date:
        properties["날짜"] = {"date": {"start": str(date)}}

    # 취약점 태그
    tags = metadata.get("tags")
    if tags and isinstance(tags, list):
        properties["취약점 태그"] = {"multi_select": [{"name": str(t)} for t in tags]}

    # Git 링크
    if github_url:
        properties["Git 링크"] = {"url": github_url}

    return properties


def sync_writeup(notion: Client, database_id: str, filepath: Path) -> None:
    """단일 writeup을 Notion DB에 동기화합니다."""
    metadata = parse_writeup(filepath)
    ctf_name = metadata.get("ctf_name", "")
    challenge_name = metadata.get("challenge_name", "")

    if not ctf_name or not challenge_name:
        print(f"[SKIP] {filepath}: ctf_name 또는 challenge_name 누락")
        return

    github_url = build_github_url(filepath)
    properties = build_properties(metadata, github_url)

    existing_page_id = find_existing_page(notion, database_id, ctf_name, challenge_name)

    if existing_page_id:
        notion.pages.update(page_id=existing_page_id, properties=properties)
        print(f"[UPDATE] {ctf_name} - {challenge_name}")
    else:
        notion.pages.create(parent={"database_id": database_id}, properties=properties)
        print(f"[CREATE] {ctf_name} - {challenge_name}")


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python sync_notion.py <writeup_file> [...]")
        return 1

    notion = get_notion_client()
    database_id = get_database_id()

    for filepath_str in sys.argv[1:]:
        filepath = Path(filepath_str)
        if not filepath.exists():
            print(f"[SKIP] {filepath}: 파일 없음")
            continue
        try:
            sync_writeup(notion, database_id, filepath)
        except Exception as e:
            print(f"[ERROR] {filepath}: {e}")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
