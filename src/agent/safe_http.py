"""不依赖代理环境的 SSRF-safe HTTP(S) 文本抓取。"""

from __future__ import annotations

import http.client
import socket
import ssl
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

from .tool_security import UnsafeURL, ValidatedURL, validate_web_url

MAX_WEB_BYTES = 64 * 1024
MAX_REDIRECTS = 3
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
TEXT_CONTENT_TYPES = {
    "application/json",
    "application/xml",
    "application/xhtml+xml",
}


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, endpoint: ValidatedURL, timeout: float):
        super().__init__(endpoint.hostname, endpoint.port, timeout=timeout)
        self._pinned_address = endpoint.addresses[0]

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._pinned_address, self.port),
            self.timeout,
            self.source_address,
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, endpoint: ValidatedURL, timeout: float):
        super().__init__(
            endpoint.hostname,
            endpoint.port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        self._pinned_address = endpoint.addresses[0]

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._pinned_address, self.port),
            self.timeout,
            self.source_address,
        )
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)


def _request_target(url: str) -> str:
    parsed = urlsplit(url)
    path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parsed.query, safe="=&%:@!$'()*+,;/?-._~")
    return urlunsplit(("", "", path, query, ""))


def _is_text_content_type(content_type: str) -> bool:
    media_type = content_type.partition(";")[0].strip().lower()
    return not media_type or media_type.startswith("text/") or media_type in TEXT_CONTENT_TYPES


def fetch_public_text(url: str, timeout: float = 10) -> str:
    """只连接预先解析并确认的公网 IP，且每次重定向都重新校验。"""

    current_url = url
    for redirect_count in range(MAX_REDIRECTS + 1):
        endpoint = validate_web_url(current_url, resolve_dns=True, allow_fixture=False)
        connection_class = _PinnedHTTPSConnection if endpoint.scheme == "https" else _PinnedHTTPConnection
        connection = connection_class(endpoint, timeout)
        try:
            connection.request(
                "GET",
                _request_target(current_url),
                headers={
                    "User-Agent": "ArgusGuardian/0.2",
                    "Accept": "text/plain,text/html,application/json,application/xml;q=0.9,*/*;q=0.1",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            if response.status in REDIRECT_STATUSES:
                location = response.getheader("Location")
                if not location:
                    raise UnsafeURL("重定向响应缺少 Location")
                if redirect_count >= MAX_REDIRECTS:
                    raise UnsafeURL("URL 重定向次数过多")
                current_url = urljoin(current_url, location)
                continue
            if response.status < 200 or response.status >= 300:
                raise UnsafeURL(f"远端返回 HTTP {response.status}")

            content_type = response.getheader("Content-Type", "")
            if not _is_text_content_type(content_type):
                raise UnsafeURL(f"拒绝非文本响应：{content_type or 'unknown'}")
            body = response.read(MAX_WEB_BYTES + 1)
            if len(body) > MAX_WEB_BYTES:
                raise UnsafeURL(f"响应超过 {MAX_WEB_BYTES} 字节上限")
            charset = response.headers.get_content_charset() or "utf-8"
            try:
                return body.decode(charset, errors="replace")
            except LookupError:
                return body.decode("utf-8", errors="replace")
        except (OSError, http.client.HTTPException) as exc:
            raise UnsafeURL(f"安全抓取失败：{exc}") from exc
        finally:
            connection.close()

    raise UnsafeURL("URL 重定向次数过多")
