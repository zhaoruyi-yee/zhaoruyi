"""检测规则：文档、依赖、启动脚本、Windows 专用脚本、硬编码路径、密钥风险。"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict

from .provider import RepoSnapshot, WINDOWS_SCRIPT_EXTS

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

RISK_CAPS = {"secrets": 60, "paths": 70, "windows": 25, "docs": 10, "deps": 10,
             "run": 8, "hygiene": 12}

PLACEHOLDER_HINTS = (
    "xxxx", "your", "example", "placeholder", "changeme", "change_me", "dummy",
    "sample", "fake", "redacted", "todo", "***", "...", "<", ">", "{{", "}}",
    "os.environ", "process.env", "getenv", "env[", "env.", "settings.", "config.",
)


def _mask(token: str) -> str:
    if len(token) <= 10:
        return "***"
    return token[:4] + "…" + token[-3:]


def _looks_placeholder(value: str) -> bool:
    low = value.lower()
    return any(h in low for h in PLACEHOLDER_HINTS)


def _is_doc(path: str) -> bool:
    low = path.lower()
    return low.endswith((".md", ".mdx", ".rst", ".txt")) or low.startswith("docs/")


def _is_test_path(path: str) -> bool:
    """测试夹具目录：其中的示例路径/口令是刻意构造的，不计入可移植性与凭据风险。"""
    return bool(re.search(r"(^|/)(tests?|spec|__tests__|fixtures?)/", path, re.I))


# ---------------------------------------------------------------------------
# 密钥规则
# ---------------------------------------------------------------------------

SECRET_RULES = [
    {
        "key": "private_key",
        "severity": "critical",
        "label": "私钥内容",
        "pattern": re.compile(r"-----BEGIN (?:[A-Z0-9 ]{0,40})?PRIVATE KEY-----"),
        "advice": "立即从仓库移除私钥并重新签发；使用 git filter-repo / BFG 清理历史，改由密钥管理服务下发。",
    },
    {
        "key": "openai_key",
        "severity": "critical",
        "label": "OpenAI / Anthropic 风格密钥",
        "pattern": re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}"),
        "advice": "立即吊销并轮换该密钥，改为通过环境变量或密钥管理服务注入，同时清理 git 历史。",
    },
    {
        "key": "stripe_live",
        "severity": "critical",
        "label": "Stripe Live 密钥",
        "pattern": re.compile(r"\bsk_live_[A-Za-z0-9]{16,}"),
        "advice": "Live 密钥泄露风险极高，请立刻在 Stripe 后台轮换，并检查是否有异常调用。",
    },
    {
        "key": "aws_access_key",
        "severity": "critical",
        "label": "AWS Access Key",
        "pattern": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "advice": "立即在 IAM 中禁用并轮换该 Access Key，排查 CloudTrail 是否有异常调用。",
    },
    {
        "key": "github_token",
        "severity": "critical",
        "label": "GitHub Token",
        "pattern": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,})\b"),
        "advice": "在 GitHub Settings → Developer settings 中撤销该 Token，并使用最小权限重新签发。",
    },
    {
        "key": "aliyun_key",
        "severity": "high",
        "label": "阿里云 AccessKey",
        "pattern": re.compile(r"\bLTAI[0-9A-Za-z]{12,}\b"),
        "advice": "在阿里云 RAM 控制台禁用并轮换 AccessKey，改用 STS 临时凭证。",
    },
    {
        "key": "tencent_key",
        "severity": "high",
        "label": "腾讯云 SecretId",
        "pattern": re.compile(r"\bAKID[0-9A-Za-z]{13,}\b"),
        "advice": "在腾讯云访问管理中禁用并轮换该 SecretId，改用子账号最小权限。",
    },
    {
        "key": "google_api_key",
        "severity": "high",
        "label": "Google API Key",
        "pattern": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "advice": "在 Google Cloud Console 限制/轮换该 API Key，并配置 HTTP 来源与 API 白名单。",
    },
    {
        "key": "slack_token",
        "severity": "high",
        "label": "Slack Token",
        "pattern": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "advice": "在 Slack App 管理页撤销并重新安装应用，轮换 Token。",
    },
    {
        "key": "bearer_token",
        "severity": "medium",
        "label": "Bearer Token",
        "pattern": re.compile(r"\bBearer\s+([A-Za-z0-9\-._~+/]{16,}=*)"),
        "advice": "确认该 Token 是否真实有效；改为运行时注入，避免写入源码或文档。",
    },
    {
        "key": "jwt",
        "severity": "medium",
        "label": "JWT Token",
        "pattern": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        "advice": "避免把可用期较长的 JWT 写入仓库，改用短期令牌并通过环境变量下发。",
    },
    {
        "key": "generic_secret",
        "severity": "medium",
        "label": "疑似口令 / 密钥赋值",
        "pattern": re.compile(
            r"""(?i)(?:api[_-]?key|secret(?:[_-]?key)?|password|passwd|pwd|access[_-]?token|auth[_-]?token|private[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9_\-./+=]{12,})["']?"""
        ),
        "advice": "确认为真实凭据后立即轮换，并改用环境变量 / 配置中心；示例值请标注为占位符。",
    },
]

ENV_FILE_RE = re.compile(r"(^|/)\.env(?:\.(?:local|production|prod|development|dev|staging|test|uat))?$", re.I)
SAFE_ENV_RE = re.compile(r"\.env\.(?:example|sample|template|dist)$", re.I)
SENSITIVE_FILE_RE = re.compile(
    r"(^|/)(?:id_rsa|id_dsa|id_ed25519|id_ecdsa|\.htpasswd)$|\.(?:pem|key|pfx|p12|jks|keystore)$", re.I)


def scan_secrets(snap: RepoSnapshot) -> tuple[list[dict], dict]:
    risks: list[dict] = []
    counts = Counter()
    seen: set[tuple] = set()

    for path, fc in snap.files.items():
        text = fc.text
        if not text:
            continue
        for idx, line in enumerate(text.splitlines(), 1):
            if len(line) > 4000:
                line = line[:4000]
            for rule in SECRET_RULES:
                for m in rule["pattern"].finditer(line):
                    token = m.group(1) if (rule["key"] == "bearer_token" and m.groups()) else m.group(0)
                    token = token.strip().strip("\"'")
                    if not token or _looks_placeholder(token):
                        continue
                    severity = rule["severity"]
                    if rule["key"] == "generic_secret":
                        if token in ("password", "secret", "token", "null", "none", "true", "false"):
                            continue
                        if token.startswith(("/", "http", "C:\\", "D:\\")):
                            continue
                        # 赋值右侧是表达式/调用（request.form[...]、config.get(...)）而非字面量
                        tail = line[m.end():].lstrip()
                        if tail[:1] in "([{" or any(ch in token for ch in "()[]{}"):
                            continue
                        # 点号标识符（self.xxx / request.form / os.environ）不是硬编码凭据
                        if re.search(r"[A-Za-z_]\.[A-Za-z_]", token):
                            continue
                        # 文档里的示例值降级，避免污染风险清单
                        if _is_doc(path) or _is_test_path(path):
                            severity = "low"
                    dedup_key = (path, idx, rule["key"], token)
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    counts[severity] += 1
                    risks.append({
                        "category": "secrets",
                        "severity": severity,
                        "title": f"{rule['label']}：{_mask(token)}",
                        "file": path,
                        "line": idx,
                        "snippet": line.strip().replace(token, _mask(token))[:200],
                        "advice": rule["advice"],
                        "rule": rule["key"],
                        "url": snap.file_url(path, idx),
                    })

    # .env 入库
    for path in snap.files:
        if ENV_FILE_RE.search(path) and not SAFE_ENV_RE.search(path):
            # 测试夹具 / 示例目录中的 .env 多为占位配置，降级为高风险
            fixture = bool(re.search(r"(^|/)(tests?|spec|__tests__|fixtures?|examples?|samples?)/", path, re.I))
            severity = "high" if fixture else "critical"
            counts[severity] += 1
            risks.append({
                "category": "secrets",
                "severity": severity,
                "title": "敏感配置文件已提交入库（.env）",
                "file": path,
                "line": 0,
                "snippet": "（文件已入库，内容不在报告中展示）",
                "advice": "将 .env 从版本库移除并加入 .gitignore，改用 .env.example 提供字段模板；已泄露的值全部轮换。",
                "rule": "env_committed",
                "url": snap.file_url(path),
            })

    # 证书 / 私钥文件
    for item in snap.tree:
        path = item.get("path", "")
        if SENSITIVE_FILE_RE.search(path):
            counts["high"] += 1
            risks.append({
                "category": "secrets",
                "severity": "high",
                "title": "密钥/证书类文件已入库",
                "file": path,
                "line": 0,
                "snippet": "",
                "advice": "确认文件是否为真实证书/私钥；若为真实凭据请轮换并从仓库移除，改用部署时挂载。",
                "rule": "sensitive_file",
                "url": snap.file_url(path),
            })

    summary = {
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "total": sum(counts.values()),
    }
    return risks, summary


# ---------------------------------------------------------------------------
# 硬编码路径
# ---------------------------------------------------------------------------

PATH_RULES = [
    ("windows_user_path", re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s\"'`<>|,;)\]，。、；：！？（）【】「」]+", re.I), "high"),
    ("windows_drive", re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/](?:[^\s\"'`<>|,;)\]，。、；：！？（）【】「」]{1,180})"), "medium"),
    ("mac_home", re.compile(r"/Users/[A-Za-z0-9._-]+"), "medium"),
    ("linux_home", re.compile(r"/home/[A-Za-z0-9._-]+"), "medium"),
    ("unc", re.compile(r"\\\\[A-Za-z0-9._$-]+\\[^\s\"'`<>|,;)\]，。、；：！？（）【】「」]{0,120}"), "medium"),
    ("file_url", re.compile(r"file:///[^\s\"'`<>|)\]，。、；：！？（）【】「」]+"), "low"),
    ("common_abs", re.compile(r"/(?:opt|var/www|srv|data|mnt)/[A-Za-z0-9._-]+(?:/[^\s\"'`<>|,;)\]，。、；：！？（）【】「」]*)?"), "low"),
]

PLACEHOLDER_USERS = {"user", "username", "yourname", "your_name", "your-user", "name",
                     "me", "example", "test", "someone", "xxx", "placeholder"}


def scan_paths(snap: RepoSnapshot) -> tuple[list[dict], dict]:
    risks: list[dict] = []
    total = 0
    files_hit: set[str] = set()
    personal = 0
    samples: list[dict] = []
    per_file = Counter()
    for path, fc in snap.files.items():
        if _is_doc(path) or _is_test_path(path):
            continue  # 文档示例与测试夹具中的路径不计入硬编码路径风险
        file_count = 0
        for idx, line in enumerate(fc.text.splitlines(), 1):
            if len(line) > 3000:
                line = line[:3000]
            spans: set[int] = set()
            for key, pattern, base_sev in PATH_RULES:
                for m in pattern.finditer(line):
                    if m.start() in spans:
                        continue
                    spans.add(m.start())
                    value = m.group(0).rstrip("\\/")
                    if not value or len(value) <= 2:
                        continue
                    if "re.compile(" in line or "re.compile" in line:
                        continue  # 检测规则/正则定义中的示例，不是真实路径
                    if any(tag in value for tag in ("…", "...", "***", "<", ">")):
                        continue  # 省略号/占位符形式的示例路径
                    sev = base_sev
                    low_val = value.lower()
                    if key in ("mac_home", "linux_home"):
                        user = value.split("/")[2] if len(value.split("/")) > 2 else ""
                        if user.lower() in PLACEHOLDER_USERS:
                            continue
                        if not _is_doc(path):
                            sev = "high"
                    if key in ("windows_user_path",):
                        user = value.replace("\\", "/").split("/")[2] if len(value.replace("\\", "/").split("/")) > 2 else ""
                        if user.lower() in PLACEHOLDER_USERS:
                            continue
                        sev = "high"
                    total += 1
                    files_hit.add(path)
                    per_file[path] += 1
                    if sev == "high" or key == "windows_user_path":
                        personal += 1
                    if len(samples) < 12:
                        samples.append({"file": path, "line": idx, "value": value[:120],
                                        "severity": sev, "rule": key})
                    if file_count >= 3 or per_file[path] > 3:
                        continue
                    file_count += 1
                    risks.append({
                        "category": "paths",
                        "severity": sev,
                        "title": f"硬编码绝对路径：{value[:70]}",
                        "file": path,
                        "line": idx,
                        "snippet": line.strip()[:200],
                        "advice": "改为相对路径 + 环境变量/配置文件注入；在文档中给出示例路径，避免写死本机目录。",
                        "rule": key,
                        "url": snap.file_url(path, idx),
                    })
    summary = {"total": total, "files": len(files_hit), "personal": personal,
               "samples": samples}
    return risks, summary


# ---------------------------------------------------------------------------
# Windows 专用脚本与信号
# ---------------------------------------------------------------------------

WINDOWS_SIGNAL_RULES = [
    ("windows_env_var", re.compile(r"%USERPROFILE%|%APPDATA%|%LOCALAPPDATA%|%TEMP%|%SystemRoot%", re.I)),
    # 仅在行首匹配，避免把 SQL 的 WHERE、文档里的 copy 说明当成 Windows 命令
    ("windows_cmd", re.compile(r"^\s*(?:setx\s+[A-Za-z_]|chcp\s+\d+)", re.I)),
    ("powershell_policy", re.compile(r"powershell(?:\.exe)?.*?-ExecutionPolicy", re.I)),
    ("win32_import", re.compile(r"\b(?:win32api|win32com|winreg|msvcrt|pywin32)\b")),
    ("windows_system_path", re.compile(r"[A-Za-z]:[\\/]Windows[\\/]System32", re.I)),
]


def scan_windows(snap: RepoSnapshot) -> tuple[list[dict], dict, list[dict]]:
    risks: list[dict] = []
    scripts = []
    for item in snap.tree:
        path = item.get("path", "")
        low = path.lower()
        if low.endswith(WINDOWS_SCRIPT_EXTS):
            size = int(item.get("size") or 0)
            scripts.append({"path": path, "size": size, "ext": low.rsplit(".", 1)[-1]})
    scripts.sort(key=lambda x: x["path"])
    for s in scripts[:20]:
        risks.append({
            "category": "windows",
            "severity": "medium",
            "title": f"Windows 专用脚本：{s['path']}",
            "file": s["path"],
            "line": 0,
            "snippet": "",
            "advice": "提供跨平台等价脚本（.sh / Node / Python）或明确声明仅支持 Windows；如需 CI，增加 Windows runner 说明。",
            "rule": "windows_script",
            "url": snap.file_url(s["path"]),
        })

    signals = []
    seen_files: set[str] = set()
    for path, fc in snap.files.items():
        if path in seen_files or len(signals) >= 12 or _is_test_path(path):
            continue
        hits = []
        for idx, line in enumerate(fc.text.splitlines(), 1):
            if len(line) > 2000:
                line = line[:2000]
            if "re.compile(" in line or "WINDOWS_SIGNAL_RULES" in line:
                continue  # 规则定义自身，避免自指误报
            for name, pattern in WINDOWS_SIGNAL_RULES:
                m = pattern.search(line)
                if m:
                    hits.append({"rule": name, "line": idx, "value": m.group(0)[:80]})
            if len(hits) >= 3:
                break
        if hits:
            seen_files.add(path)
            signals.append({"file": path, "hits": hits})
            risks.append({
                "category": "windows",
                "severity": "low" if _is_doc(path) else "medium",
                "title": f"Windows 专属用法：{hits[0]['value']}",
                "file": path,
                "line": hits[0]["line"],
                "snippet": hits[0]["value"],
                "advice": "确认目标运行环境；如需 Linux/容器部署，改为跨平台实现或补充兼容说明。",
                "rule": hits[0]["rule"],
                "url": snap.file_url(path, hits[0]["line"]),
            })
    summary = {"scripts": scripts, "signals": signals}
    return risks, summary, signals


# ---------------------------------------------------------------------------
# 文档 / 依赖 / 启动 / 规范
# ---------------------------------------------------------------------------

INSTALL_RE = re.compile(
    r"(npm (?:i|install|ci)|pnpm (?:i|install)|yarn(?: install)?|pip3? install|poetry install|"
    r"uv sync|go mod download|composer install|bundle install|cargo build|dotnet restore|"
    r"mvn (?:install|package)|gradle build|make install)", re.I)
RUN_RE = re.compile(
    r"(npm run [\w:-]+|pnpm (?:run )?[\w:-]+|yarn (?:run )?[\w:-]+|python3? -m [\w.]+|python3? [\w./-]+\.py|"
    r"uvicorn [\w.:]+|flask (?:--?\w+(?:=\S+)? )*run\b|gunicorn [\w.:]+|go run [\w./-]+|cargo run|"
    r"docker(?: compose)? up[\w .-]*|make (?:run|dev|start|serve|up|preview|app)\b|java -jar [\w./-]+|dotnet run|"
    r"streamlit run [\w./-]+|next dev|vite(?: dev)?)", re.I)

# Makefile 中可视为“启动方式”的目标
START_MAKE_TARGETS = {"run", "dev", "develop", "start", "serve", "server", "up", "app", "preview"}

MANIFEST_TYPES = {
    "package.json": "Node.js / npm",
    "requirements.txt": "Python / pip",
    "pyproject.toml": "Python / pyproject",
    "pipfile": "Python / Pipenv",
    "go.mod": "Go Modules",
    "cargo.toml": "Rust / Cargo",
    "pom.xml": "Java / Maven",
    "build.gradle": "Java / Gradle",
    "build.gradle.kts": "Java / Gradle",
    "composer.json": "PHP / Composer",
    "gemfile": "Ruby / Bundler",
}

LOCK_NAMES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
              "poetry.lock", "pipfile.lock", "go.sum", "cargo.lock", "composer.lock",
              "gemfile.lock", "pdm.lock", "uv.lock"}

RUNTIME_PIN_NAMES = {".nvmrc", ".node-version", ".python-version", ".tool-versions",
                     "rust-toolchain", "rust-toolchain.toml", ".ruby-version", "global.json"}


def _root_name(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def find_readme(snap: RepoSnapshot) -> tuple[str | None, str]:
    for path, fc in snap.files.items():
        if "/" not in path and path.lower().startswith("readme"):
            return path, fc.text
    for path in ("docs/README.md", "docs/readme.md", "README/README.md"):
        if path in snap.files:
            return path, snap.files[path].text
    for item in snap.tree:
        p = item.get("path", "")
        if "/" not in p and p.lower().startswith("readme"):
            return p, ""
    return None, ""


def inspect_docs(snap: RepoSnapshot) -> tuple[dict, list[dict]]:
    risks: list[dict] = []
    path, text = find_readme(snap)
    headings = len(re.findall(r"^#{1,6}\s+\S", text, re.M))
    code_blocks = text.count("```") // 2
    has_install = bool(INSTALL_RE.search(text)) or bool(re.search(r"(?im)^#{1,6}\s*.*(安装|install|setup|getting started)", text))
    has_run = bool(RUN_RE.search(text)) or bool(re.search(r"(?im)^#{1,6}\s*.*(使用|运行|usage|run|quick ?start|开始)", text))
    has_license_section = bool(re.search(r"(?im)^#{1,6}\s*.*licen[cs]e|许可证", text))
    has_badges = "shields.io" in text.lower() or bool(re.search(r"!\[[^\]]*\]\(https?://", text))

    if not path:
        risks.append({
            "category": "docs", "severity": "high", "title": "缺少 README",
            "file": "", "line": 0, "snippet": "",
            "advice": "补充 README：项目简介、环境要求、安装、启动、配置项、目录结构、常见问题。",
            "rule": "readme_missing", "url": "",
        })
    else:
        if not has_install:
            risks.append({
                "category": "docs", "severity": "medium", "title": "README 未说明安装/依赖安装方式",
                "file": path, "line": 0, "snippet": "",
                "advice": "增加“安装 / 环境准备”章节，给出可直接复制的命令和版本要求。",
                "rule": "readme_install", "url": snap.file_url(path),
            })
        if not has_run:
            risks.append({
                "category": "docs", "severity": "medium", "title": "README 未说明启动方式",
                "file": path, "line": 0, "snippet": "",
                "advice": "增加“快速开始 / 运行”章节，给出启动命令、默认端口与必要配置。",
                "rule": "readme_run", "url": snap.file_url(path),
            })

    facts = {
        "path": path,
        "exists": bool(path),
        "chars": len(text),
        "lines": text.count("\n") + (1 if text else 0),
        "headings": headings,
        "code_blocks": code_blocks,
        "has_install": has_install,
        "has_run": has_run,
        "has_license_section": has_license_section,
        "has_badges": has_badges,
    }
    return facts, risks


def inspect_deps(snap: RepoSnapshot) -> tuple[dict, list[dict]]:
    risks: list[dict] = []
    manifests = []
    lockfiles = []
    runtime_pins = []
    package_scripts: dict[str, str] = {}
    package_json_valid: bool | None = None

    for path, fc in snap.files.items():
        base = _root_name(path).lower()
        if base in MANIFEST_TYPES:
            detail = ""
            if base == "package.json":
                try:
                    data = json.loads(fc.text)
                    deps = data.get("dependencies") or {}
                    dev = data.get("devDependencies") or {}
                    package_scripts = {k: str(v) for k, v in (data.get("scripts") or {}).items()}
                    engines = data.get("engines") or {}
                    detail = f"{len(deps)} 个运行时依赖 / {len(dev)} 个开发依赖"
                    package_json_valid = True
                    if engines:
                        detail += "；engines: " + ", ".join(f"{k} {v}" for k, v in engines.items())
                except ValueError:
                    package_json_valid = False
                    risks.append({
                        "category": "deps", "severity": "medium",
                        "title": "package.json 无法解析",
                        "file": path, "line": 0, "snippet": "",
                        "advice": "修复 package.json 语法，确保依赖可被 npm/pnpm 正确安装。",
                        "rule": "invalid_manifest", "url": snap.file_url(path),
                    })
            elif base == "requirements.txt":
                count = len([ln for ln in fc.text.splitlines()
                             if ln.strip() and not ln.strip().startswith("#")])
                detail = f"{count} 条依赖声明"
            elif base == "go.mod":
                m = re.search(r"^go\s+([\d.]+)", fc.text, re.M)
                module = re.search(r"^module\s+(\S+)", fc.text, re.M)
                detail = (f"module {module.group(1)}" if module else "") + \
                         (f"；go {m.group(1)}" if m else "")
            elif base == "pyproject.toml":
                m = re.search(r"requires-python\s*=\s*[\"']([^\"']+)", fc.text)
                detail = f"requires-python {m.group(1)}" if m else ""
            elif base == "cargo.toml":
                m = re.search(r"^edition\s*=\s*[\"']([^\"']+)", fc.text, re.M)
                detail = f"edition {m.group(1)}" if m else ""
            manifests.append({"file": path, "type": MANIFEST_TYPES[base], "detail": detail})

    for item in snap.tree:
        base = _root_name(item.get("path", "")).lower()
        if base in LOCK_NAMES:
            lockfiles.append(item.get("path", ""))
        if base in RUNTIME_PIN_NAMES:
            runtime_pins.append(item.get("path", ""))
    lockfiles = sorted(set(lockfiles))[:6]
    runtime_pins = sorted(set(runtime_pins))[:6]

    facts = {
        "manifests": manifests,
        "lockfiles": lockfiles,
        "runtime_pins": runtime_pins,
        "package_scripts": package_scripts,
        "package_json_valid": package_json_valid,
    }
    return facts, risks


def inspect_run(snap: RepoSnapshot, deps: dict, readme_text: str) -> tuple[dict, list[dict]]:
    risks: list[dict] = []
    tree_paths = [item.get("path", "") for item in snap.tree]

    scripts = deps.get("package_scripts") or {}
    start_like = {k: v for k, v in scripts.items()
                  if k.lower() in ("start", "dev", "develop", "serve", "preview", "run")}

    # 优先根目录 Makefile（docs/Makefile 多为文档构建，不代表项目启动方式）
    makefile = next((p for p in tree_paths if "/" not in p and _root_name(p).lower() == "makefile"), "")
    if not makefile:
        makefile = next((p for p in tree_paths if _root_name(p).lower() == "makefile"), "")
    make_targets: list[str] = []
    if makefile and makefile in snap.files:
        targets = re.findall(r"^([A-Za-z0-9_.-]+)\s*:", snap.files[makefile].text, re.M)
        make_targets = [t for t in dict.fromkeys(targets)
                        if not t.startswith(".") and t.lower() in START_MAKE_TARGETS][:8]

    procfile = next((p for p in tree_paths if _root_name(p).lower() == "procfile"), "")
    container = [p for p in tree_paths if _root_name(p).lower() in
                 ("dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")]

    readme_cmd = ""
    if readme_text:
        m = RUN_RE.search(readme_text)
        if m:
            readme_cmd = m.group(0)
    has_start = bool(start_like) or bool(make_targets) or bool(procfile) or (readme_cmd != "")
    if not has_start and (snap.files or snap.tree):
        risks.append({
            "category": "run", "severity": "medium", "title": "未发现明确的启动方式",
            "file": "", "line": 0, "snippet": "",
            "advice": "补充可执行入口（package.json scripts.start / Makefile / Procfile / 文档命令），并在 README 中给出启动命令。",
            "rule": "no_start", "url": "",
        })

    facts = {
        "scripts": scripts,
        "start_like": start_like,
        "makefile": makefile,
        "make_targets": make_targets,
        "procfile": procfile,
        "container": container,
        "readme_command": readme_cmd,
    }
    return facts, risks


def inspect_hygiene(snap: RepoSnapshot) -> tuple[dict, list[dict]]:
    risks: list[dict] = []
    tree_paths = [item.get("path", "") for item in snap.tree]

    license_file = next(
        (p for p in tree_paths if re.match(r"(?i)^(license|licence)(\.|$)", _root_name(p))), "")
    license_exists = bool(license_file) or bool(snap.license_name)
    if not license_exists:
        risks.append({
            "category": "hygiene", "severity": "low", "title": "未发现开源许可证文件",
            "file": "", "line": 0, "snippet": "",
            "advice": "补充 LICENSE（如 MIT / Apache-2.0），明确二次分发与商用边界。",
            "rule": "license_missing", "url": "",
        })

    gitignore_path = next((p for p in tree_paths if p.lower() == ".gitignore"), "")
    covers_env = False
    if gitignore_path and gitignore_path in snap.files:
        for line in snap.files[gitignore_path].text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if s in (".env", ".env*", "*.env") or s.startswith(".env"):
                covers_env = True
                break
    if not gitignore_path:
        risks.append({
            "category": "hygiene", "severity": "medium", "title": "缺少 .gitignore",
            "file": "", "line": 0, "snippet": "",
            "advice": "添加 .gitignore，至少忽略 .env、构建产物、依赖目录与本地配置。",
            "rule": "gitignore_missing", "url": "",
        })
    elif not covers_env:
        risks.append({
            "category": "hygiene", "severity": "medium", "title": ".gitignore 未忽略 .env",
            "file": gitignore_path, "line": 0, "snippet": "",
            "advice": "在 .gitignore 中加入 .env / .env.*（保留 .env.example），防止凭据误提交。",
            "rule": "gitignore_env", "url": snap.file_url(gitignore_path),
        })

    ci = [p for p in tree_paths
          if p.startswith(".github/workflows/") or _root_name(p).lower() in
          (".gitlab-ci.yml", "jenkinsfile", "azure-pipelines.yml", ".travis.yml", "circle.yml")]
    tests = any(re.search(r"(^|/)(tests?|spec|__tests__)/|(_test|\.test|\.spec|_spec)\.", p, re.I)
                for p in tree_paths)
    docs_dir = any(p.lower().startswith("docs/") for p in tree_paths)
    changelog = any(_root_name(p).lower().startswith(("changelog", "changes", "history")) for p in tree_paths)
    contributing = any(_root_name(p).lower().startswith("contributing") for p in tree_paths)

    facts = {
        "license": {"exists": license_exists, "name": snap.license_name},
        "gitignore": {"exists": bool(gitignore_path), "covers_env": covers_env,
                      "path": gitignore_path},
        "ci": sorted(set(ci))[:6],
        "tests": tests,
        "docs_dir": docs_dir,
        "changelog": changelog,
        "contributing": contributing,
    }
    return facts, risks


# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------

def _attach_ids(risks: list[dict]) -> None:
    for r in risks:
        raw = f"{r['category']}|{r['rule']}|{r['file']}|{r['line']}|{r['title']}"
        r["id"] = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:10]


def run_rules(snap: RepoSnapshot) -> dict:
    readme_facts, readme_risks = inspect_docs(snap)
    deps_facts, deps_risks = inspect_deps(snap)
    readme_path, readme_text = find_readme(snap)
    run_facts, run_risks = inspect_run(snap, deps_facts, readme_text)
    hygiene_facts, hygiene_risks = inspect_hygiene(snap)

    secret_risks, secret_summary = scan_secrets(snap)
    path_risks, path_summary = scan_paths(snap)
    win_risks, win_summary, win_signals = scan_windows(snap)

    all_risks = (secret_risks + path_risks + win_risks + readme_risks +
                 deps_risks + run_risks + hygiene_risks)
    _attach_ids(all_risks)

    # 按分类截断，避免超大仓库刷屏
    kept: list[dict] = []
    counter: Counter = Counter()
    for r in sorted(all_risks, key=lambda x: (SEVERITY_ORDER[x["severity"]], x["category"],
                                              x["file"], x["line"])):
        if counter[r["category"]] >= RISK_CAPS.get(r["category"], 20):
            continue
        counter[r["category"]] += 1
        kept.append(r)

    facts = {
        "readme": readme_facts,
        "deps": deps_facts,
        "run": run_facts,
        "hygiene": hygiene_facts,
        "windows_scripts": win_summary["scripts"],
        "windows_signals": win_signals,
        "paths": path_summary,
        "secrets": secret_summary,
        "coverage": {
            "tree_files": len(snap.tree),
            "scanned_files": len(snap.files),
            "coverage_pct": round(len(snap.files) / max(1, len(snap.tree)) * 100, 1),
        },
    }

    checks = _build_checks(snap, facts, kept)
    return {"facts": facts, "risks": kept, "checks": checks}


def _status(ok: bool | None, warn: bool = False) -> str:
    if ok is None:
        return "info"
    if ok:
        return "pass"
    return "warn" if warn else "fail"


def _build_checks(snap: RepoSnapshot, facts: dict, risks: list[dict]) -> list[dict]:
    readme = facts["readme"]
    deps = facts["deps"]
    run = facts["run"]
    hygiene = facts["hygiene"]
    sec = facts["secrets"]
    paths = facts["paths"]
    checks: list[dict] = []

    def add(group: str, key: str, label: str, status: str, detail: str):
        checks.append({"group": group, "key": key, "label": label,
                       "status": status, "detail": detail})

    add("docs", "readme", "README 存在", _status(readme["exists"]),
        readme["path"] or "未找到 README")
    add("docs", "readme_quality", "README 包含安装与运行说明",
        _status(readme["has_install"] and readme["has_run"]),
        f"安装说明={'有' if readme['has_install'] else '无'}，运行说明={'有' if readme['has_run'] else '无'}，"
        f"{readme['lines']} 行 / {readme['headings']} 个标题")
    add("docs", "license", "LICENSE 许可证", _status(hygiene["license"]["exists"]),
        hygiene["license"]["name"] or "未声明")
    add("docs", "changelog", "CHANGELOG / CONTRIBUTING",
        _status(hygiene["changelog"] or hygiene["contributing"], warn=True),
        f"CHANGELOG={'有' if hygiene['changelog'] else '无'}，"
        f"CONTRIBUTING={'有' if hygiene['contributing'] else '无'}")

    add("deps", "manifest", "依赖清单",
        _status(bool(deps["manifests"])),
        "、".join(f"{m['type']}" for m in deps["manifests"]) or "未发现 package.json / requirements.txt 等")
    add("deps", "lockfile", "依赖锁定文件", _status(bool(deps["lockfiles"]), warn=True),
        "、".join(deps["lockfiles"]) or "未发现 lock 文件，安装结果可能不可复现")
    add("deps", "runtime_pin", "运行时版本约束", _status(bool(deps["runtime_pins"]), warn=True),
        "、".join(deps["runtime_pins"]) or "未发现 .nvmrc / engines / requires-python 等版本约束")

    add("run", "start_script", "启动/开发脚本", _status(bool(run["start_like"])),
        "、".join(f"{k}: {v[:40]}" for k, v in list(run["start_like"].items())[:3]) or "package.json 中未发现 start/dev")
    add("run", "readme_command", "README 中的运行命令", _status(bool(run["readme_command"]), warn=True),
        run["readme_command"] or "未在 README 中匹配到启动命令")
    add("run", "container", "容器 / 进程启动描述",
        _status(bool(run["container"] or run["procfile"] or run["make_targets"]), warn=True),
        "、".join((run["container"] + ([run["procfile"]] if run["procfile"] else []))[:4]) or "未发现 Dockerfile / Procfile / Makefile")

    add("portability", "windows_scripts", "Windows 专用脚本",
        _status(not facts["windows_scripts"], warn=True),
        f"{len(facts['windows_scripts'])} 个 .bat/.cmd/.ps1/.vbs 文件" if facts["windows_scripts"] else "未发现")
    add("portability", "hardcoded_paths", "硬编码绝对路径",
        _status(paths["total"] == 0, warn=paths["total"] <= 3),
        f"{paths['total']} 处，涉及 {paths['files']} 个文件" if paths["total"] else "未发现")
    add("portability", "windows_signals", "Windows 专属用法信号",
        _status(len(facts["windows_signals"]) == 0, warn=True),
        f"{len(facts['windows_signals'])} 个文件包含 Windows 环境变量、win32 导入等专属用法"
        if facts["windows_signals"] else "未发现")

    add("security", "secret_critical", "高危密钥泄露",
        _status(sec["critical"] == 0), f"{sec['critical']} 处严重风险" if sec["critical"] else "未发现")
    add("security", "secret_high", "云厂商 / 第三方密钥",
        _status(sec["high"] == 0, warn=True), f"{sec['high']} 处高风险" if sec["high"] else "未发现")
    add("security", "secret_medium", "疑似口令 / Token",
        _status(sec["medium"] == 0, warn=True), f"{sec['medium']} 处中风险" if sec["medium"] else "未发现")
    env_risks = [r for r in risks if r["rule"] == "env_committed"]
    add("security", "env_committed", ".env 未入库",
        _status(len(env_risks) == 0),
        f"{len(env_risks)} 个 .env 文件已提交" if env_risks else "未发现")
    add("security", "gitignore", ".gitignore 覆盖敏感文件",
        _status(hygiene["gitignore"]["exists"] and hygiene["gitignore"]["covers_env"],
                warn=hygiene["gitignore"]["exists"]),
        "已忽略 .env" if hygiene["gitignore"]["covers_env"] else
        ("缺少 .gitignore" if not hygiene["gitignore"]["exists"] else ".gitignore 未忽略 .env"))

    add("hygiene", "ci", "CI 配置", _status(bool(hygiene["ci"]), warn=True),
        "、".join(hygiene["ci"][:3]) or "未发现 CI 配置")
    add("hygiene", "tests", "测试目录 / 用例", _status(hygiene["tests"], warn=True),
        "已发现测试文件" if hygiene["tests"] else "未发现测试文件")
    add("hygiene", "docs_dir", "docs 目录", _status(hygiene["docs_dir"], warn=True),
        "已提供" if hygiene["docs_dir"] else "未发现")
    return checks
