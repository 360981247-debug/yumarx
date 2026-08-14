"""Tests for the GitHub PR reader tool without making network requests."""

from __future__ import annotations

import unittest
from unittest.mock import patch

import httpx

from pr_reader import pr_reader


_REAL_ASYNC_CLIENT = httpx.AsyncClient


class MockAsyncClient:
    """An httpx client replacement backed by a test-only mock transport."""

    handler = None

    def __init__(self, **kwargs: object) -> None:
        self.client = _REAL_ASYNC_CLIENT(
            base_url=str(kwargs.get("base_url", "")),
            transport=httpx.MockTransport(type(self).handler),
        )

    async def __aenter__(self) -> httpx.AsyncClient:
        return self.client

    async def __aexit__(self, *_: object) -> None:
        await self.client.aclose()


class PRReaderTests(unittest.IsolatedAsyncioTestCase):
    async def test_reads_pr_files_and_comments(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/pulls/12"):
                return httpx.Response(
                    200,
                    json={
                        "number": 12,
                        "title": "Add tax calculation",
                        "body": "Adds tax support.",
                        "state": "open",
                        "draft": False,
                        "user": {"login": "octocat"},
                        "base": {"ref": "main"},
                        "head": {"ref": "feature/tax"},
                        "html_url": "https://github.com/acme/orders/pull/12",
                    },
                )
            if request.url.path.endswith("/files"):
                return httpx.Response(
                    200,
                    json=[
                        {
                            "filename": "src/tax.py",
                            "status": "modified",
                            "additions": 2,
                            "deletions": 1,
                            "changes": 3,
                            "patch": "+rate = 0.1\\n-return total\\n+return total * rate",
                        }
                    ],
                )
            if request.url.path.endswith("/comments"):
                return httpx.Response(
                    200,
                    json=[
                        {
                            "path": "src/tax.py",
                            "line": 3,
                            "side": "RIGHT",
                            "body": "Consider rounding.",
                            "user": {"login": "reviewer"},
                        }
                    ],
                )
            return httpx.Response(404, json={"message": "Not Found"})

        MockAsyncClient.handler = handler
        with patch("pr_reader.httpx.AsyncClient", MockAsyncClient):
            result = await pr_reader("https://github.com/acme/orders", 12)

        self.assertEqual(result["repository"], "acme/orders")
        self.assertEqual(result["pr"]["title"], "Add tax calculation")
        self.assertEqual(result["files"][0]["filename"], "src/tax.py")
        self.assertEqual(result["existing_review_comments"][0]["line"], 3)

    async def test_rejects_non_github_repository(self) -> None:
        result = await pr_reader("https://gitlab.com/acme/orders", 12)
        self.assertIn("repository", result["error"])

    async def test_returns_github_error_without_leaking_headers(self) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"message": "Not Found"})

        MockAsyncClient.handler = handler
        with patch("pr_reader.httpx.AsyncClient", MockAsyncClient):
            result = await pr_reader("acme/orders", 12)

        self.assertEqual(result["status_code"], 404)
        self.assertEqual(result["detail"], "Not Found")

    async def test_returns_structured_network_error(self) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("network unavailable")

        MockAsyncClient.handler = handler
        with patch("pr_reader.httpx.AsyncClient", MockAsyncClient):
            result = await pr_reader("acme/orders", 12)

        self.assertEqual(result["error"], "无法连接到 GitHub API")

    async def test_reports_patch_and_comment_truncation(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/pulls/12"):
                return httpx.Response(200, json={"number": 12, "user": {}, "base": {}, "head": {}})
            if request.url.path.endswith("/files"):
                return httpx.Response(
                    200,
                    json=[{"filename": "src/example.py", "status": "modified", "patch": "+abcdef"}],
                )
            if request.url.path.endswith("/comments"):
                return httpx.Response(
                    200,
                    json=[{"path": "src/example.py", "body": str(index), "user": {}} for index in range(101)],
                )
            return httpx.Response(404, json={"message": "Not Found"})

        MockAsyncClient.handler = handler
        with patch("pr_reader.httpx.AsyncClient", MockAsyncClient):
            result = await pr_reader("acme/orders", 12, max_patch_chars=3)

        self.assertEqual(result["files"][0]["patch"], "+ab")
        self.assertTrue(result["files"][0]["patch_truncated"])
        self.assertTrue(result["context_limits"]["patch_chars_omitted"])
        self.assertTrue(result["context_limits"]["comments_truncated"])
        self.assertEqual(len(result["existing_review_comments"]), 100)

    async def test_does_not_report_omission_when_patch_exactly_fills_limit(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/pulls/12"):
                return httpx.Response(200, json={"number": 12, "user": {}, "base": {}, "head": {}})
            if request.url.path.endswith("/files"):
                return httpx.Response(
                    200,
                    json=[{"filename": "src/example.py", "status": "modified", "patch": "+abc"}],
                )
            return httpx.Response(404, json={"message": "Not Found"})

        MockAsyncClient.handler = handler
        with patch("pr_reader.httpx.AsyncClient", MockAsyncClient):
            result = await pr_reader("acme/orders", 12, include_comments=False, max_patch_chars=4)

        self.assertFalse(result["context_limits"]["patch_chars_omitted"])


if __name__ == "__main__":
    unittest.main()
