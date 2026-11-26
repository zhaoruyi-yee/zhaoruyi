"""离线自测：不依赖外网，验证规则、评分、缓存/兜底与 AI 回退逻辑。

运行：python -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analyzer import ai, analyze, check_updates  # noqa: E402
from analyzer.provider import parse_target  # noqa: E402


def _write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def build_fixture(root: Path) -> None:
    _write(root, "README.md", "# Demo App\n\n## 安装\n\nnpm install\n\n## 运行\n\nnpm run start\n\n"
                              "更多说明见 docs/guide.md。\n")
    _write(root, "package.json", json.dumps({
        "name": "demo-app",
        "version": "1.0.0",
        "engines": {"node": ">=18"},
        "scripts": {"start": "node src/index.js", "dev": "node src/index.js"},
        "dependencies": {"express": "^4.18.0"},
    }, ensure_ascii=False, indent=2))
    _write(root, "package-lock.json", '{"lockfileVersion": 3}')
    _write(root, "LICENSE", "MIT License")
    _write(root, ".gitignore", "node_modules\n")
    _write(root, "docs/guide.md", "文档目录。示例：cd C:\\Users\\yourname\\demo（仅为示例）\n")
    _write(root, "scripts/setup.bat", "set APP_HOME=C:\\Users\\alice\\app\n%APPDATA%\\demo\n")
    _write(root, "scripts/deploy.ps1", "Write-Host 'deploy'\n")
    _write(root, "src/index.js", "require('express')\n")
    _write(root, "src/config.js",
           'const dataDir = "C:\\\\Users\\\\alice\\\\workspace\\\\app";\n'
           'const password = "averylongsecretvalue123";\n')
    _write(root, "src/net.js",
           'const base = "https://example.com/api/v1";\n'
           'const token = process.env.API_KEY;\n'
           'const placeholder = "your_password_here";\n')
    # 运行期拼接假密钥，避免仓库里出现真实格式的密钥字符串
    fake = "sk-" + ("A1b2C3d4" * 4)
    _write(root, ".env", f"OPENAI_API_KEY={fake}\nPORT=3000\n")


class AnalyzerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name) / "demo-repo"
        cls.root.mkdir(parents=True)
        build_fixture(cls.root)
        cls.report = analyze(str(cls.root), force=True)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def test_score_range_and_dimensions(self) -> None:
        score = self.report["summary"]["score"]
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)
        keys = {d["key"] for d in self.report["dimensions"]}
        self.assertEqual(keys, {"docs", "deps", "run", "portability", "security"})
        self.assertEqual(sum(d["max"] for d in self.report["dimensions"]), 100)

    def test_docs_and_deps_detected(self) -> None:
        facts = self.report["facts"]
        self.assertTrue(facts["readme"]["exists"])
        self.assertTrue(facts["readme"]["has_install"])
        self.assertTrue(facts["readme"]["has_run"])
        self.assertTrue(facts["deps"]["manifests"])
        self.assertIn("package-lock.json", facts["deps"]["lockfiles"])
        self.assertTrue(self.report["facts"]["run"]["start_like"])

    def test_secrets_env_and_private_key(self) -> None:
        rules = {r["rule"] for r in self.report["risks"]}
        self.assertIn("openai_key", rules)
        self.assertIn("env_committed", rules)
        self.assertIn("generic_secret", rules)
        self.assertEqual(self.report["facts"]["secrets"]["critical"] >= 2, True)
        # 输出必须脱敏
        for risk in self.report["risks"]:
            self.assertNotIn("sk-" + "A1b2C3d4" * 4, risk["snippet"])

    def test_windows_scripts_and_paths(self) -> None:
        stats = self.report["stats"]
        self.assertGreaterEqual(stats["windows_scripts"], 2)
        self.assertGreaterEqual(stats["hardcoded_paths"], 1)
        rules = {r["rule"] for r in self.report["risks"]}
        self.assertIn("windows_script", rules)
        self.assertTrue(any(r in rules for r in ("windows_user_path", "windows_drive")))

    def test_false_positive_guards(self) -> None:
        for risk in self.report["risks"]:
            if risk["file"] == "src/net.js":
                self.fail(f"误报：{risk['title']}")
            if risk["file"] == "docs/guide.md" and risk["category"] == "paths":
                self.fail(f"文档示例不应作为路径风险：{risk['title']}")

    def test_markdown_report(self) -> None:
        md = self.report["markdown"]
        self.assertIn("接入体检报告", md)
        self.assertIn(self.report["commit"]["short_sha"], md)
        self.assertIn("接入建议", md)

    def test_check_updates_local(self) -> None:
        result = check_updates(str(self.root))
        self.assertTrue(result["is_local"])

    def test_parse_targets(self) -> None:
        t = parse_target("https://github.com/pallets/flask")
        self.assertEqual((t.kind, t.owner, t.name), ("github", "pallets", "flask"))
        t2 = parse_target("https://github.com/microsoft/vscode/tree/main/src/vs/editor")
        self.assertEqual((t2.ref, t2.subdir), ("main", "src/vs/editor"))
        t3 = parse_target("https://gitlab.com/group/sub/repo/-/tree/dev/app")
        self.assertEqual((t3.kind, t3.owner, t3.name, t3.ref, t3.subdir),
                         ("gitlab", "group/sub", "repo", "dev", "app"))

    def test_ai_llm_integration_with_mock(self) -> None:
        class MockLLM(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                assert payload["model"] == "mock-model"
                content = json.dumps({
                    "verdict": "需要整改",
                    "summary": "存在密钥风险。",
                    "suggestions": [{"title": "轮换密钥", "action": "立即执行",
                                     "priority": "P0", "expected_gain": "+8"}],
                }, ensure_ascii=False)
                body = json.dumps({"choices": [{"message": {"content": content}}]},
                                  ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), MockLLM)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            result = ai.advise(self.report, {"base_url": f"http://127.0.0.1:{port}/v1",
                                             "model": "mock-model", "api_key": "test-key"})
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(result["provider"], "llm")
        self.assertEqual(result["suggestions"][0]["title"], "轮换密钥")

    def test_ai_fallback_when_llm_fails(self) -> None:
        result = ai.advise(self.report, {"base_url": "http://127.0.0.1:9/v1",
                                         "model": "x", "api_key": "k"})
        self.assertEqual(result["provider"], "rules")
        self.assertIn("回退", result["note"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
