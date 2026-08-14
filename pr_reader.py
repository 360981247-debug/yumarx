"""Read public GitHub pull-request context for the Code Review Agent."""

from __future__ import annotations

import os
import re
from typing import Any

import httpx


GITHUB_API_URL = "https://api.github.com"
_REPOSITORY_RE = re.compile(
    r"^(?:https?://github\.com/)?(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)
_MAX_FILES = 100
_MAX_PATCH_CHARS = 120_000


class PullRequestReaderError(ValueError):
    """An invalid PR reader request that can be shown to the agent user."""


def _parse_repository(repository: str) -> tuple[str, str]:
    """Return the owner and repo names for an HTTPS GitHub repository URL."""
    match = _REPOSITORY_RE.fullmatch(repository.strip())
    if not match:
        raise PullRequestReaderError(
            "repository 必须是 `owner/repo` 或 https://github.com/owner/repo 格式。"
        )
    return match.group("owner"), match.group("repo")


def _limit(value: int, *, default: int, maximum: int) -> int:
    """Clamp an LLM-provided integer to a safe, predictable request limit."""
    if not isinstance(value, int):
        return default
    return max(1, min(value, maximum))


def _github_headers() -> dict[str, str]:
    """Build GitHub API headers; an optional token raises the rate limit."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "veadk-code-review-agent",
    }
    if token := os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _response_error(response: httpx.Response) -> dict[str, Any]:
    """Return a safe, actionable API error without exposing credentials."""
    try:
        payload = response.json()
        detail = payload.get("message", response.text) if isinstance(payload, dict) else response.text
    except ValueError:
        detail = response.text
    return {
        "error": "GitHub API 请求失败",
        "status_code": response.status_code,
        "detail": str(detail)[:500],
    }


async def _get_all_pages(
    client: httpx.AsyncClient, path: str, *, per_page: int, max_items: int
) -> list[dict[str, Any]] | dict[str, Any]:
    """Fetch REST pagination while bounding the context returned to the model."""
    items: list[dict[str, Any]] = []
    for page in range(1, (max_items + per_page - 1) // per_page + 1):
        response = await client.get(path, params={"per_page": per_page, "page": page})
        if response.is_error:
            return _response_error(response)
        try:
            payload = response.json()
        except ValueError:
            return {"error": "GitHub API 返回了无法解析的数据"}
        if not isinstance(payload, list):
            return {"error": "GitHub API 返回了非预期的数据格式"}
        items.extend(item for item in payload if isinstance(item, dict))
        if len(payload) < per_page or len(items) >= max_items:
            break
    return items[:max_items]


def _review_file(file: dict[str, Any], remaining_patch_chars: int) -> tuple[dict[str, Any], int]:
    """Keep review-relevant file data and clip a patch to the global budget."""
    patch = file.get("patch")
    if not isinstance(patch, str):
        patch = ""
    shown_patch = patch[:remaining_patch_chars]
    patch_truncated = len(shown_patch) < len(patch)
    return (
        {
            "filename": file.get("filename"),
            "status": file.get("status"),
            "additions": file.get("additions", 0),
            "deletions": file.get("deletions", 0),
            "changes": file.get("changes", 0),
            "previous_filename": file.get("previous_filename"),
            "patch": shown_patch or None,
            "patch_truncated": patch_truncated,
            "patch_unavailable": not isinstance(file.get("patch"), str),
        },
        max(0, remaining_patch_chars - len(shown_patch)),
    )


async def pr_reader(
    repository: str,
    pr_number: int,
    include_comments: bool = True,
    max_files: int = 50,
    max_patch_chars: int = 80_000,
) -> dict[str, Any]:
    """读取一个 GitHub PR 的元数据、文件 diff 和已有评审评论。

    Args:
        repository: 公共 GitHub 仓库，格式为 ``owner/repo`` 或完整 GitHub URL。
        pr_number: Pull Request 编号。
        include_comments: 是否同时读取已有的行级评论，默认读取。
        max_files: 最多返回的变更文件数（1-100），默认 50。
        max_patch_chars: 全部 diff 的最大字符数（1-120000），默认 80000。

    Returns:
        结构化 PR 上下文；错误会在 ``error`` 字段中返回，供 Agent 向用户解释。
    """
    try:
        owner, repo = _parse_repository(repository)
    except PullRequestReaderError as error:
        return {"error": str(error)}

    if not isinstance(pr_number, int) or pr_number < 1:
        return {"error": "pr_number 必须是大于 0 的整数。"}

    file_limit = _limit(max_files, default=50, maximum=_MAX_FILES)
    patch_limit = _limit(max_patch_chars, default=80_000, maximum=_MAX_PATCH_CHARS)
    base_path = f"/repos/{owner}/{repo}/pulls/{pr_number}"

    timeout = httpx.Timeout(float(os.getenv("PR_READER_TIMEOUT_SECONDS", "20")))
    try:
        async with httpx.AsyncClient(
            base_url=GITHUB_API_URL,
            headers=_github_headers(),
            timeout=timeout,
            follow_redirects=False,
        ) as client:
            pr_response = await client.get(base_path)
            if pr_response.is_error:
                return _response_error(pr_response)
            try:
                pr = pr_response.json()
            except ValueError:
                return {"error": "GitHub API 返回了无法解析的数据"}
            if not isinstance(pr, dict):
                return {"error": "GitHub API 返回了非预期的数据格式"}

            raw_files = await _get_all_pages(
                client, f"{base_path}/files", per_page=100, max_items=file_limit + 1
            )
            if isinstance(raw_files, dict):
                return raw_files

            comments: list[dict[str, Any]] = []
            comments_truncated = False
            if include_comments:
                raw_comments = await _get_all_pages(
                    client, f"{base_path}/comments", per_page=100, max_items=101
                )
                if isinstance(raw_comments, dict):
                    return raw_comments
                comments_truncated = len(raw_comments) > 100
                comments = [
                    {
                        "path": comment.get("path"),
                        "line": comment.get("line"),
                        "side": comment.get("side"),
                        "body": comment.get("body"),
                        "user": (comment.get("user") or {}).get("login"),
                    }
                    for comment in raw_comments[:100]
                ]
    except httpx.HTTPError as error:
        return {
            "error": "无法连接到 GitHub API",
            "detail": str(error)[:500],
        }

    files_truncated = len(raw_files) > file_limit
    raw_files = raw_files[:file_limit]
    remaining_patch_chars = patch_limit
    files: list[dict[str, Any]] = []
    for changed_file in raw_files:
        file_context, remaining_patch_chars = _review_file(
            changed_file, remaining_patch_chars
        )
        files.append(file_context)

    patch_chars_omitted = any(file["patch_truncated"] for file in files)

    return {
        "repository": f"{owner}/{repo}",
        "pr": {
            "number": pr.get("number"),
            "title": pr.get("title"),
            "body": pr.get("body"),
            "state": pr.get("state"),
            "draft": pr.get("draft"),
            "author": (pr.get("user") or {}).get("login"),
            "base": (pr.get("base") or {}).get("ref"),
            "head": (pr.get("head") or {}).get("ref"),
            "url": pr.get("html_url"),
        },
        "files": files,
        "existing_review_comments": comments,
        "context_limits": {
            "max_files": file_limit,
            "max_patch_chars": patch_limit,
            "files_truncated": files_truncated,
            "patch_chars_omitted": patch_chars_omitted,
            "comments_truncated": comments_truncated,
        },
    }
