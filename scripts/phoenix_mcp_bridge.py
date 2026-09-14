#!/usr/bin/env python3
"""
MCP HTTP bridge for Claude Desktop (stdio).

Reads JSON-RPC messages from stdin, forwards to the MCP HTTP endpoint,
and writes JSON-RPC responses to stdout using Content-Length framing.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple


def _read_message(stream: Any) -> Optional[Dict[str, Any]]:
    """Read a JSON-RPC message from stdin (Content-Length or JSON line)."""
    first_line = stream.readline()
    if not first_line:
        return None

    if first_line.startswith(b"Content-Length:"):
        headers = [first_line]
        while True:
            line = stream.readline()
            if not line:
                return None
            headers.append(line)
            if line in (b"\r\n", b"\n"):
                break
        content_length = None
        for header in headers:
            try:
                decoded = header.decode("utf-8").strip()
            except Exception:
                continue
            if decoded.lower().startswith("content-length:"):
                try:
                    content_length = int(decoded.split(":", 1)[1].strip())
                except ValueError:
                    content_length = None
                break
        if content_length is None:
            return None
        body = stream.read(content_length)
        if not body:
            return None
        return json.loads(body.decode("utf-8"))

    line = first_line.strip()
    if not line:
        return None
    return json.loads(line.decode("utf-8"))


def _write_message(stream: Any, payload: Dict[str, Any]) -> None:
    """Write JSON-RPC message to stdout using Content-Length framing."""
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
    stream.write(header + body)
    stream.flush()


def _http_request(
    url: str,
    api_key: Optional[str],
    payload: Dict[str, Any],
    timeout: int,
    *,
    insecure_tls: bool,
) -> Tuple[Optional[int], str]:
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["x-api-key"] = api_key
    request = urllib.request.Request(url, data=data, method="POST", headers=headers)
    context = None
    if insecure_tls and url.lower().startswith("https://"):
        context = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")
    except Exception as exc:
        return None, str(exc)


def _error_response(request_id: Optional[object], message: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32000,
            "message": message,
            "data": data,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Bridge MCP stdio to HTTP JSON-RPC.")
    parser.add_argument(
        "--url",
        default=os.getenv("MCP_HTTP_URL", "http://localhost:8000/api/v1/mcp/claude"),
        help="MCP HTTP endpoint URL.",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("MCP_API_KEY", ""),
        help="API key for MCP endpoint (x-api-key header).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=int(os.getenv("MCP_HTTP_TIMEOUT", "30")),
        help="HTTP request timeout in seconds.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        default=os.getenv("MCP_HTTP_INSECURE", "").lower() in {"1", "true", "yes"},
        help="Disable TLS verification (for local self-signed HTTPS).",
    )
    args = parser.parse_args()

    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer

    while True:
        try:
            message = _read_message(stdin)
        except Exception as exc:
            _write_message(stdout, _error_response(None, "Invalid JSON input", {"error": str(exc)}))
            continue

        if message is None:
            break

        request_id = message.get("id") if isinstance(message, dict) else None
        if not isinstance(message, dict):
            _write_message(stdout, _error_response(request_id, "Invalid JSON-RPC payload"))
            continue

        status, body = _http_request(
            args.url,
            args.api_key or None,
            message,
            args.timeout,
            insecure_tls=args.insecure,
        )
        if status is None:
            _write_message(stdout, _error_response(request_id, "MCP HTTP request failed", {"detail": body}))
            continue

        try:
            response_payload = json.loads(body)
        except Exception:
            response_payload = None

        if isinstance(response_payload, dict) and ("result" in response_payload or "error" in response_payload):
            _write_message(stdout, response_payload)
            continue

        error_detail = {
            "status": status,
            "body": response_payload if response_payload is not None else body,
        }
        _write_message(stdout, _error_response(request_id, "MCP HTTP error", error_detail))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
