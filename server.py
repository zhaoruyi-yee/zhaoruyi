#!/usr/bin/env python3
"""RepoCheckup 本地 Web 服务（Python 标准库，无第三方依赖）。

用法：
    python server.py                     # http://127.0.0.1:8000
    python server.py --port 9000 --no-local
    python server.py --analyze https://github.com/pallets/flask --out report.md
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import os
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

from analyzer import (RULE_VERSION, TOOL_VERSION, RateLimitError, ServiceError,
                      analyze, check_updates)

WEB_DIR = (Path(__file__).resolve().parent / "web").resolve()
ALLOW_LOCAL = True

# 显式声明静态资源 MIME：Windows 注册表常把 .js/.css 映射成 text/plain，
# 配合 nosniff 会让浏览器拒绝执行脚本，导致页面只剩静态外壳
STATIC_MIME = {
    ".html": "text/html",
    ".css": "text/css",
    ".js": "application/javascript",
    ".json": "application/json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}


def _health() -> dict:
    return {
        "ok": True,
        "tool": "RepoCheckup",
        "version": TOOL_VERSION,
        "rule_version": RULE_VERSION,
        "github_token": bool(os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")),
        "llm_configured": bool(os.environ.get("LLM_API_KEY")),
        "local_enabled": ALLOW_LOCAL,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "RepoCheckup/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    # -- 响应工具 -------------------------------------------------------
    def _send(self, status: int, body: bytes, content_type: str,
              extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8",
                   {"Cache-Control": "no-store"})

    def _error(self, exc: Exception) -> None:
        if isinstance(exc, RateLimitError):
            payload = {"error": {"code": exc.code, "message": exc.message,
                                 "reset_at": exc.reset_at}}
            self._json(payload, 429)
        elif isinstance(exc, ServiceError):
            payload = {"error": {"code": exc.code, "message": exc.message,
                                 "detail": exc.detail}}
            self._json(payload, exc.status)
        else:
            traceback.print_exc()
            self._json({"error": {"code": "internal_error",
                                  "message": "服务端处理失败，请查看终端日志"}}, 500)

    # -- 路由 -----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == "/api/health":
                self._json(_health())
                return
            if path == "/api/head":
                query = parse_qs(parsed.query)
                url = (query.get("url") or [""])[0]
                if not url:
                    raise ServiceError("缺少 url 参数", code="invalid_input")
                self._json(check_updates(url))
                return
            self._serve_static(path)
        except Exception as exc:  # noqa: BLE001
            self._error(exc)

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path != "/api/analyze":
            self._json({"error": {"code": "not_found", "message": "接口不存在"}}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > 64 * 1024:
                raise ServiceError("请求体为空或过大", code="invalid_input")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            url = str(payload.get("url") or "").strip()
            if not url:
                raise ServiceError("请输入公开仓库地址", code="invalid_input")
            ai_cfg = payload.get("ai") if isinstance(payload.get("ai"), dict) else None
            report = analyze(url, force=bool(payload.get("force")), ai_cfg=ai_cfg,
                             allow_local=ALLOW_LOCAL)
            self._json(report)
        except ValueError:
            self._error(ServiceError("请求体不是合法 JSON", code="invalid_input"))
        except Exception as exc:  # noqa: BLE001
            self._error(exc)

    # -- 静态文件 -------------------------------------------------------
    def _serve_static(self, path: str) -> None:
        rel = path.lstrip("/") or "index.html"
        if rel.endswith("/"):
            rel += "index.html"
        target = (WEB_DIR / rel).resolve()
        if target != WEB_DIR and WEB_DIR not in target.parents:
            self._json({"error": {"code": "not_found", "message": "资源不存在"}}, 404)
            return
        if not target.is_file():
            if rel == "favicon.ico":
                self._send(204, b"", "image/x-icon")
                return
            self._json({"error": {"code": "not_found", "message": "资源不存在"}}, 404)
            return
        content_type = (STATIC_MIME.get(target.suffix.lower())
                        or mimetypes.guess_type(str(target))[0]
                        or "application/octet-stream")
        if content_type.startswith("text/") or content_type in ("application/javascript",
                                                                "application/json",
                                                                "image/svg+xml"):
            content_type += "; charset=utf-8"
        body = target.read_bytes()
        cache = "no-cache" if target.suffix == ".html" else "public, max-age=300"
        self._send(200, body, content_type, {"Cache-Control": cache})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(host: str, port: int) -> None:
    httpd = Server((host, port), Handler)
    print(f"RepoCheckup 已启动：http://{host}:{port}  (rule {RULE_VERSION})")
    print(f"本地目录分析：{'开启' if ALLOW_LOCAL else '关闭'}  |  "
          f"GITHUB_TOKEN：{'已配置' if _health()['github_token'] else '未配置（60 次/小时）'}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        httpd.server_close()


def cli(url: str, out: str | None, json_out: str | None, force: bool) -> int:
    try:
        report = analyze(url, force=force)
    except (ServiceError, RateLimitError) as exc:
        print(f"失败：{exc.message}", file=sys.stderr)
        return 1
    summary = report["summary"]
    print(f"仓库：{report['repo']['full_name']}  commit：{report['commit']['short_sha']}")
    print(f"评分：{summary['score']} / 100（{summary['grade']['letter']} · {summary['grade']['label']}）")
    print(f"风险：{summary['counts']}")
    print(f"AI：{report['ai']['provider']} - {report['ai']['summary']}")
    if out:
        Path(out).write_text(report["markdown"], encoding="utf-8")
        print(f"Markdown 已写入：{out}")
    if json_out:
        Path(json_out).write_text(json.dumps(report, ensure_ascii=False, indent=2),
                                  encoding="utf-8")
        print(f"JSON 已写入：{json_out}")
    return 0


def main() -> None:
    global ALLOW_LOCAL
    parser = argparse.ArgumentParser(description="Git 仓库接入体检")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-local", action="store_true", help="禁用本地目录分析")
    parser.add_argument("--analyze", metavar="URL", help="命令行模式：直接分析并输出")
    parser.add_argument("--out", help="命令行模式：Markdown 输出路径")
    parser.add_argument("--json", dest="json_out", help="命令行模式：JSON 输出路径")
    parser.add_argument("--force", action="store_true", help="忽略报告缓存")
    args = parser.parse_args()

    if args.no_local:
        ALLOW_LOCAL = False
    if args.analyze:
        raise SystemExit(cli(args.analyze, args.out, args.json_out, args.force))
    serve(args.host, args.port)


if __name__ == "__main__":
    main()
