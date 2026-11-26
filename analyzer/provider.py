"""仓库数据获取层。

支持：
- GitHub 公开仓库（REST API + raw.githubusercontent.com）
- GitLab 公开仓库（REST API v4 + /-/raw/）
- 本地目录（离线演示、自测；仅在本机服务中默认开启）

设计要点：
1. 只做 1~3 次 API 调用（仓库元信息 / commit / 文件树），文件正文走 raw 域名，避免耗尽 API 配额。
2. 文件内容按 git blob sha 做内容寻址缓存，同一 blob 跨 commit 复用，为“增量更新”打基础。
3. 任何网络失败都转成带 code 的 ServiceError，由上层决定是否回退到旧报告。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

UA = "RepoCheckup/1.0"
APP_DIR = Path(__file__).resolve().parent.parent
CACHE_DIR = Path(os.environ.get("REPOCHECK_CACHE") or (APP_DIR / ".cache"))
BLOB_CACHE_DIR = CACHE_DIR / "blobs"
REPORT_CACHE_DIR = CACHE_DIR / "reports"

MAX_FILE_BYTES = 200_000
FETCH_LIMIT = 320
TOTAL_BUDGET = 12_000_000

SKIP_DIRS = {
    "node_modules", "vendor", ".git", "dist", "build", "out", "target",
    ".venv", "venv", "__pycache__", ".next", ".nuxt", "coverage",
    "third_party", "bower_components", ".gradle", ".idea", ".vscode",
    ".mypy_cache", ".pytest_cache", ".tox", ".cache",
}

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "pipfile.lock", "go.sum", "cargo.lock", "composer.lock", "gemfile.lock",
}

TEXT_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte",
    ".go", ".rs", ".java", ".kt", ".kts", ".scala", ".rb", ".php", ".cs",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".m", ".mm", ".swift", ".sh", ".bash",
    ".zsh", ".fish", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".json", ".json5",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml",
    ".gradle", ".md", ".mdx", ".rst", ".txt", ".sql", ".html", ".htm", ".css",
    ".scss", ".less", ".tf", ".tfvars", ".pl", ".lua", ".r", ".jl", ".dart",
    ".ex", ".exs", ".erl", ".clj", ".groovy", ".proto", ".graphql", ".env",
    ".dockerfile", ".editorconfig", ".gitattributes", ".npmrc", ".pypirc",
}

TEXT_NAMES = {
    "dockerfile", "makefile", "procfile", "gemfile", "rakefile", "jenkinsfile",
    "vagrantfile", "brewfile", "pipfile", "cmakelists.txt", ".gitignore",
    ".dockerignore", ".npmrc", ".pypirc", ".nvmrc", ".python-version",
    ".tool-versions", ".env", "license",
}

IMPORTANT_NAMES = TEXT_NAMES | {
    "readme.md", "readme.rst", "readme.txt", "readme", "package.json",
    "pyproject.toml", "requirements.txt", "go.mod", "cargo.toml", "pom.xml",
    "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
    "composer.json", "docker-compose.yml", "docker-compose.yaml", "compose.yml",
    "compose.yaml", "license.md", "contributing.md", "changelog.md", ".env.example",
}

WINDOWS_SCRIPT_EXTS = (".bat", ".cmd", ".ps1", ".vbs")


class ServiceError(Exception):
    """可安全返回给前端的业务错误。"""

    def __init__(self, message: str, *, code: str = "error", status: int = 400,
                 detail: str | None = None, reset_at: int | None = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status
        self.detail = detail
        self.reset_at = reset_at


class RateLimitError(ServiceError):
    def __init__(self, message: str, *, reset_at: int | None = None):
        super().__init__(message, code="rate_limited", status=429, reset_at=reset_at)


@dataclass
class Target:
    raw: str
    kind: str  # github / gitlab / local
    host: str = ""
    owner: str = ""
    name: str = ""
    ref: str | None = None
    subdir: str = ""
    local_path: str = ""

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}" if self.owner else self.name


@dataclass
class FileContent:
    path: str
    size: int
    sha: str
    text: str
    truncated: bool = False


@dataclass
class RepoSnapshot:
    target: Target
    host: str
    full_name: str
    description: str
    default_branch: str
    branch: str
    commit_sha: str
    commit_date: str
    commit_message: str
    pushed_at: str
    stars: int
    language: str
    license_name: str
    archived: bool
    subdir: str
    tree: list[dict] = field(default_factory=list)
    files: dict[str, FileContent] = field(default_factory=dict)
    truncated_tree: bool = False
    warnings: list[str] = field(default_factory=list)
    blob_stats: dict = field(default_factory=lambda: {"hit": 0, "miss": 0})

    @property
    def web_url(self) -> str:
        if self.host == "github":
            return f"https://github.com/{self.full_name}"
        if self.host == "gitlab":
            return f"https://gitlab.com/{self.full_name}"
        return ""

    def file_url(self, path: str, line: int | None = None) -> str:
        if self.host == "github":
            url = f"https://github.com/{self.full_name}/blob/{self.commit_sha}/{urllib.parse.quote(path, safe='/')}"
        elif self.host == "gitlab":
            url = f"https://gitlab.com/{self.full_name}/-/blob/{self.commit_sha}/{urllib.parse.quote(path, safe='/')}"
        else:
            return ""
        return f"{url}#L{line}" if line else url


# ---------------------------------------------------------------------------
# 通用 HTTP
# ---------------------------------------------------------------------------

def _github_token() -> str:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""


def _http(url: str, *, token: str | None = None, timeout: int = 20,
          retries: int = 1, accept: str = "application/json") -> tuple[bytes, dict]:
    headers = {"User-Agent": UA, "Accept": accept}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    last_err: Exception | None = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            body = b""
            try:
                body = exc.read()[:2000]
            except Exception:
                pass
            remain = exc.headers.get("X-RateLimit-Remaining") if exc.headers else None
            reset = exc.headers.get("X-RateLimit-Reset") if exc.headers else None
            if exc.code in (403, 429) and (remain == "0" or exc.code == 429):
                raise RateLimitError(
                    "上游 API 触发限流，请稍后重试或配置 GITHUB_TOKEN",
                    reset_at=int(reset) if reset and reset.isdigit() else None,
                )
            if exc.code == 404:
                raise ServiceError("仓库、分支或文件不存在（404）", code="not_found", status=404)
            if exc.code == 401:
                raise ServiceError("Token 无效或已过期（401）", code="unauthorized", status=401)
            last_err = ServiceError(
                f"上游接口返回 HTTP {exc.code}",
                code="upstream_error",
                status=502,
                detail=body.decode("utf-8", "replace")[:300],
            )
            if exc.code < 500:
                raise last_err
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            last_err = ServiceError(f"网络请求失败：{reason}", code="network_error", status=502)
        if attempt < retries:
            time.sleep(0.8 * (attempt + 1))
    raise last_err or ServiceError("网络请求失败", code="network_error", status=502)


def _json(url: str, token: str | None = None, **kwargs) -> Any:
    body, _ = _http(url, token=token, **kwargs)
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ServiceError(f"上游返回了无法解析的数据：{exc}", code="upstream_error", status=502)


# ---------------------------------------------------------------------------
# URL 解析
# ---------------------------------------------------------------------------

def parse_target(text: str) -> Target:
    raw = (text or "").strip().strip("'\"")
    if not raw:
        raise ServiceError("请输入仓库地址或本地目录", code="invalid_input")

    if raw.lower().startswith("file://"):
        raw = urllib.parse.unquote(raw[7:])

    # 本地目录（Windows 路径 / 以 ./ 开头 / 绝对 Unix 路径）
    candidate = Path(raw).expanduser()
    if candidate.is_dir():
        return Target(raw=text.strip(), kind="local", host="local",
                      name=candidate.resolve().name, local_path=str(candidate.resolve()))

    if not re.match(r"^https?://", raw, re.I):
        raise ServiceError("仅支持 https://github.com/... 、https://gitlab.com/... 或本机目录路径",
                           code="invalid_input")

    parsed = urllib.parse.urlparse(raw)
    host = (parsed.hostname or "").lower()
    path = parsed.path.strip("/")

    if host in ("github.com", "www.github.com"):
        parts = [p for p in path.split("/") if p]
        if len(parts) < 2:
            raise ServiceError("GitHub 地址需要包含 owner/repo", code="invalid_input")
        owner = parts[0]
        name = re.sub(r"\.git$", "", parts[1], flags=re.I)
        ref, subdir = None, ""
        if len(parts) >= 4 and parts[2] in ("tree", "blob"):
            ref = urllib.parse.unquote(parts[3])
            subdir = "/".join(parts[4:])
        return Target(raw=raw, kind="github", host="github", owner=owner, name=name,
                      ref=ref, subdir=subdir)

    if host in ("gitlab.com", "www.gitlab.com"):
        path = re.sub(r"\.git$", "", path, flags=re.I)
        ref, subdir = None, ""
        for marker in ("/-/tree/", "/-/blob/"):
            if marker in path:
                before, after = path.split(marker, 1)
                seg = [s for s in after.split("/") if s]
                if seg:
                    ref = urllib.parse.unquote(seg[0])
                    subdir = "/".join(seg[1:])
                path = before
                break
        parts = [p for p in path.split("/") if p]
        if len(parts) < 2:
            raise ServiceError("GitLab 地址需要包含 group/repo", code="invalid_input")
        return Target(raw=raw, kind="gitlab", host="gitlab",
                      owner="/".join(parts[:-1]), name=parts[-1], ref=ref, subdir=subdir)

    raise ServiceError("暂只支持 github.com、gitlab.com 与本机目录", code="unsupported_host")


# ---------------------------------------------------------------------------
# 文件筛选
# ---------------------------------------------------------------------------

def is_text_path(path: str) -> bool:
    low = path.lower()
    base = low.rsplit("/", 1)[-1]
    if base in SKIP_FILES:
        return False
    if base in TEXT_NAMES or base.startswith("readme") or base.startswith(".env"):
        return True
    if base.endswith((".min.js", ".min.css", ".map", ".lock", ".sum")):
        return False
    suffix = "." + base.rsplit(".", 1)[-1] if "." in base else ""
    return suffix in TEXT_EXTS


def _priority(path: str) -> int:
    low = path.lower()
    base = low.rsplit("/", 1)[-1]
    if base in IMPORTANT_NAMES or base.startswith(("readme", "requirements", ".env")):
        return 0
    if base.endswith(WINDOWS_SCRIPT_EXTS):
        return 0
    if "/.github/workflows/" in low or low.startswith(".github/workflows/") or "/.gitlab-ci" in low:
        return 0
    if base in {"dockerfile", "makefile", "procfile", "gemfile", "pipfile",
                "package.json", "tsconfig.json", "vite.config.js", "vite.config.ts"}:
        return 1
    if base.endswith((".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".properties",
                      ".json", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".vbs")):
        return 1
    if base.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java",
                      ".rb", ".php", ".cs", ".c", ".cpp", ".h", ".hpp", ".kt",
                      ".swift", ".m", ".scala", ".dart", ".vue", ".svelte")):
        return 2
    if base.endswith((".md", ".rst", ".txt", ".html", ".css", ".scss")):
        return 3
    return 9


def select_paths(tree: list[dict]) -> list[dict]:
    candidates = []
    for item in tree:
        if item.get("type") != "blob":
            continue
        path = item.get("path", "")
        size = int(item.get("size") or 0)
        if not is_text_path(path):
            continue
        if size == 0:
            continue  # GitHub / 本地：0 字节文件无需扫描
        if size < 0:
            size = 20_000  # GitLab 树不返回大小，按估值计入预算
        if size > MAX_FILE_BYTES:
            continue
        pr = _priority(path)
        if pr > 3:
            continue
        candidates.append({"path": path, "size": size, "sha": item.get("sha", ""), "priority": pr})

    candidates.sort(key=lambda x: (x["priority"], x["size"]))
    picked, budget = [], TOTAL_BUDGET
    for c in candidates:
        if len(picked) >= FETCH_LIMIT:
            break
        if c["size"] > budget:
            continue
        budget -= c["size"]
        picked.append(c)
    return picked


def _filter_subdir(tree: list[dict], subdir: str) -> tuple[list[dict], bool, list[str]]:
    if not subdir:
        return tree, False, []
    prefix = subdir.strip("/") + "/"
    filtered = []
    for item in tree:
        path = item.get("path", "")
        if path.startswith(prefix):
            clone = dict(item)
            clone["path"] = path[len(prefix):]
            filtered.append(clone)
    if not filtered:
        raise ServiceError(f"子目录 {subdir} 不存在或为空", code="not_found", status=404)
    return filtered, True, []


# ---------------------------------------------------------------------------
# 内容缓存
# ---------------------------------------------------------------------------

def _blob_cache_path(sha: str) -> Path:
    return BLOB_CACHE_DIR / f"{sha[:2]}" / f"{sha}.txt"


def _blob_cache_get(sha: str) -> str | None:
    if not sha:
        return None
    fp = _blob_cache_path(sha)
    try:
        if fp.is_file():
            return fp.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    return None


def _blob_cache_put(sha: str, text: str) -> None:
    if not sha:
        return
    fp = _blob_cache_path(sha)
    try:
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(text, encoding="utf-8")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# 抓取：GitHub
# ---------------------------------------------------------------------------

def _fetch_contents(entries: list[dict], fetcher: Callable[[str], str | None],
                    deadline_seconds: float = 100.0) -> tuple[dict, dict, list[str]]:
    """并发抓取文件内容，优先复用 blob 缓存；超出时间预算的文件跳过。"""
    files: dict[str, FileContent] = {}
    stats = {"hit": 0, "miss": 0, "skipped": 0}
    warnings: list[str] = []
    if not entries:
        return files, stats, warnings
    deadline = time.monotonic() + deadline_seconds

    def work(item: dict) -> tuple[dict, FileContent | str | None, str]:
        path, sha = item["path"], item.get("sha", "")
        cached = _blob_cache_get(sha)
        if cached is not None:
            return item, FileContent(path, len(cached), sha, cached), "hit"
        if time.monotonic() > deadline:
            return item, "超出单次扫描时间预算，已跳过", "skip"
        try:
            text = fetcher(path)
        except ServiceError as exc:
            return item, exc.message, "error"
        except Exception as exc:  # noqa: BLE001
            return item, f"读取失败：{exc}", "error"
        if text is None:
            return item, "跳过（无内容或非文本）", "error"
        _blob_cache_put(sha, text)
        return item, FileContent(path, len(text), sha, text), "miss"

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(work, item) for item in entries]
        for fut in as_completed(futures):
            item, result, state = fut.result()
            if state in ("hit", "miss"):
                stats[state] += 1
                files[item["path"]] = result  # type: ignore[assignment]
            elif state == "skip":
                stats["skipped"] += 1
            elif len(warnings) < 8:
                warnings.append(f"{item['path']}: {result}")
    if stats["skipped"]:
        warnings.append(f"{stats['skipped']} 个文件因超出扫描时间预算被跳过。")
    return files, stats, warnings


def _github_raw(owner: str, name: str, ref: str) -> Callable[[str], str | None]:
    """优先走 jsDelivr 镜像（国内网络更稳定），失败再回退 raw.githubusercontent。"""
    ref = urllib.parse.quote(ref, safe="")
    mirrors = ("https://fastly.jsdelivr.net", "https://gcore.jsdelivr.net",
               "https://cdn.jsdelivr.net")

    def fetcher(path: str) -> str | None:
        quoted = urllib.parse.quote(path, safe="/")
        urls = [(f"{base}/gh/{owner}/{name}@{ref}/{quoted}", 10) for base in mirrors]
        urls.append((f"https://raw.githubusercontent.com/{owner}/{name}/{ref}/{quoted}", 15))
        for url, timeout in urls:
            try:
                body, _ = _http(url, retries=0, accept="text/plain,*/*", timeout=timeout)
            except ServiceError:
                continue
            if len(body) > MAX_FILE_BYTES * 2:
                body = body[:MAX_FILE_BYTES]
            if b"\x00" in body[:1000]:
                return None
            return body.decode("utf-8", "replace")
        return None
    return fetcher


def _snapshot_common(target: Target, **kw: Any) -> RepoSnapshot:
    base = dict(
        target=target, host=target.host, full_name=target.full_name,
        description="", default_branch="", branch="", commit_sha="", commit_date="",
        commit_message="", pushed_at="", stars=0, language="", license_name="",
        archived=False, subdir=target.subdir,
    )
    base.update(kw)
    return RepoSnapshot(**base)


def fetch_github(target: Target) -> RepoSnapshot:
    token = _github_token()
    api = "https://api.github.com"
    repo = _json(f"{api}/repos/{target.owner}/{target.name}", token)
    branch = target.ref or repo.get("default_branch") or "main"
    commit = _json(f"{api}/repos/{target.owner}/{target.name}/commits/"
                   f"{urllib.parse.quote(branch, safe='')}", token)
    sha = commit.get("sha", "")
    if not sha:
        raise ServiceError("无法获取分支最新 commit", code="upstream_error", status=502)

    tree_obj = _json(f"{api}/repos/{target.owner}/{target.name}/git/trees/{sha}?recursive=1", token)
    tree = [{"path": n.get("path", ""), "type": n.get("type", ""),
             "size": n.get("size") or 0, "sha": n.get("sha", "")}
            for n in tree_obj.get("tree", []) if n.get("type") == "blob"]
    tree, _ , _ = _filter_subdir(tree, target.subdir)

    entries = select_paths(tree)
    files, stats, warnings = _fetch_contents(entries, _github_raw(target.owner, target.name, sha))

    commit_meta = commit.get("commit", {}) or {}
    return _snapshot_common(
        target,
        full_name=f"{target.owner}/{target.name}",
        description=(repo.get("description") or "").strip(),
        default_branch=repo.get("default_branch") or "main",
        branch=branch,
        commit_sha=sha,
        commit_date=(commit_meta.get("committer") or {}).get("date", ""),
        commit_message=(commit_meta.get("message") or "").splitlines()[0][:200],
        pushed_at=repo.get("pushed_at", ""),
        stars=int(repo.get("stargazers_count") or 0),
        language=repo.get("language") or "",
        license_name=((repo.get("license") or {}).get("spdx_id") or ""),
        archived=bool(repo.get("archived")),
        tree=tree,
        files=files,
        truncated_tree=bool(tree_obj.get("truncated")),
        warnings=warnings,
        blob_stats=stats,
    )


# ---------------------------------------------------------------------------
# 抓取：GitLab
# ---------------------------------------------------------------------------

def _gitlab_project_id(target: Target) -> str:
    return urllib.parse.quote(f"{target.owner}/{target.name}", safe="")


def fetch_gitlab(target: Target) -> RepoSnapshot:
    api = "https://gitlab.com/api/v4"
    pid = _gitlab_project_id(target)
    project = _json(f"{api}/projects/{pid}")
    branch = target.ref or project.get("default_branch") or "main"
    commit = _json(f"{api}/projects/{pid}/repository/commits/"
                   f"{urllib.parse.quote(branch, safe='')}")
    sha = commit.get("id", "")
    if not sha:
        raise ServiceError("无法获取分支最新 commit", code="upstream_error", status=502)

    tree: list[dict] = []
    page = 1
    truncated = False
    while page <= 10:
        batch = _json(f"{api}/projects/{pid}/repository/tree?recursive=true&per_page=100"
                      f"&ref={urllib.parse.quote(sha, safe='')}&page={page}")
        if not isinstance(batch, list):
            break
        for item in batch:
            if item.get("type") == "blob":
                tree.append({"path": item.get("path", ""), "type": "blob",
                             "size": -1, "sha": item.get("id", "")})
        if len(batch) < 100:
            break
        page += 1
        truncated = page > 10
    if not tree:
        raise ServiceError("仓库为空或无法读取文件树", code="not_found", status=404)

    tree, _, _ = _filter_subdir(tree, target.subdir)
    entries = select_paths(tree)
    raw_base = f"https://gitlab.com/{target.owner}/{target.name}/-/raw/{sha}/"

    def fetcher(path: str) -> str | None:
        # 优先走 API 的 raw 接口：gitlab.com 的 /-/raw/<完整sha>/ 会被 Cloudflare 挑战拦截（HTTP 403）
        encoded = urllib.parse.quote(path, safe="")
        urls = [
            f"{api}/projects/{pid}/repository/files/{encoded}/raw"
            f"?ref={urllib.parse.quote(sha, safe='')}",
            raw_base + urllib.parse.quote(path, safe="/"),
        ]
        last_err: ServiceError | None = None
        for url in urls:
            try:
                body, _ = _http(url, retries=0, accept="*/*", timeout=15)
            except ServiceError as exc:
                if exc.code == "not_found":
                    return None
                last_err = exc
                continue
            if b"\x00" in body[:1000]:
                return None
            return body[:MAX_FILE_BYTES].decode("utf-8", "replace")
        if last_err:
            raise last_err
        return None

    files, stats, warnings = _fetch_contents(entries, fetcher)
    return _snapshot_common(
        target,
        full_name=f"{target.owner}/{target.name}",
        description=(project.get("description") or "").strip(),
        default_branch=project.get("default_branch") or "main",
        branch=branch,
        commit_sha=sha,
        commit_date=commit.get("committed_date", ""),
        commit_message=(commit.get("title") or "")[:200],
        pushed_at=project.get("last_activity_at", ""),
        stars=int(project.get("star_count") or 0),
        language="",
        license_name=(project.get("license") or {}).get("nickname", "") if isinstance(project.get("license"), dict) else "",
        archived=bool(project.get("archived")),
        tree=tree,
        files=files,
        truncated_tree=truncated,
        warnings=warnings,
        blob_stats=stats,
    )


# ---------------------------------------------------------------------------
# 抓取：本地目录
# ---------------------------------------------------------------------------

def _git_info(root: Path) -> tuple[str, str, str]:
    try:
        def run(args: list[str]) -> str:
            out = subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                                 text=True, timeout=6, check=False)
            return out.stdout.strip()
        sha = run(["rev-parse", "HEAD"])
        date = run(["log", "-1", "--format=%cI"])
        msg = run(["log", "-1", "--format=%s"])
        if sha:
            return sha, date, msg[:200]
    except (OSError, subprocess.SubprocessError):
        pass
    return "", "", ""


def fetch_local(target: Target) -> RepoSnapshot:
    root = Path(target.local_path)
    entries: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and d != ".git"]
        for fn in filenames:
            fp = Path(dirpath) / fn
            try:
                if not fp.is_file():
                    continue
                size = fp.stat().st_size
            except OSError:
                continue
            rel = fp.relative_to(root).as_posix()
            if len(entries) > 5000:
                break
            entries.append({"path": rel, "type": "blob", "size": size, "sha": ""})
        if len(entries) > 5000:
            break

    selected = select_paths(entries)
    files: dict[str, FileContent] = {}
    warnings: list[str] = []
    for item in selected:
        try:
            raw = (root / item["path"]).read_bytes()[:MAX_FILE_BYTES]
        except OSError as exc:
            if len(warnings) < 8:
                warnings.append(f"{item['path']}: {exc}")
            continue
        if b"\x00" in raw[:1000]:
            continue
        text = raw.decode("utf-8", "replace")
        sha = hashlib.sha1(raw).hexdigest()
        files[item["path"]] = FileContent(item["path"], len(raw), sha, text)

    sha, date, msg = _git_info(root)
    if not sha:
        h = hashlib.sha1()
        for path in sorted(files):
            h.update(path.encode())
            h.update(files[path].sha.encode())
        sha = "local-" + h.hexdigest()[:12]

    meta_path = root / ".repo-checkup.json"
    description = ""
    if meta_path.is_file():
        try:
            description = str(json.loads(meta_path.read_text(encoding="utf-8")).get("description", ""))[:300]
        except (OSError, ValueError):
            pass

    return _snapshot_common(
        target,
        full_name=root.name,
        description=description,
        default_branch="(local)",
        branch="(local)",
        commit_sha=sha,
        commit_date=date,
        commit_message=msg or "本地目录快照",
        pushed_at="",
        stars=0,
        language="",
        license_name="",
        archived=False,
        tree=entries,
        files=files,
        truncated_tree=len(entries) > 5000,
        warnings=warnings,
        blob_stats={"hit": 0, "miss": len(files)},
    )


# ---------------------------------------------------------------------------
# 对外入口
# ---------------------------------------------------------------------------

_HEAD_CACHE: dict[str, tuple[float, dict]] = {}


def _cache_key(target: Target) -> str:
    return f"{target.kind}:{target.full_name}:{target.ref or ''}:{target.subdir}"


def fetch_snapshot(target: Target) -> RepoSnapshot:
    if target.kind == "github":
        return fetch_github(target)
    if target.kind == "gitlab":
        return fetch_gitlab(target)
    if target.kind == "local":
        return fetch_local(target)
    raise ServiceError("不支持的目标类型", code="unsupported_host")


def resolve_head(target: Target) -> dict:
    """只取最新 commit 信息，用于“检查更新”。带 60 秒内存缓存。"""
    if target.kind == "local":
        sha, date, msg = _git_info(Path(target.local_path))
        return {"sha": sha, "date": date, "message": msg, "branch": "(local)"}

    key = _cache_key(target)
    now = time.time()
    hit = _HEAD_CACHE.get(key)
    if hit and now - hit[0] < 60:
        return hit[1]

    if target.kind == "github":
        token = _github_token()
        api = "https://api.github.com"
        branch = target.ref
        if not branch:
            repo = _json(f"{api}/repos/{target.owner}/{target.name}", token)
            branch = repo.get("default_branch") or "main"
        commit = _json(f"{api}/repos/{target.owner}/{target.name}/commits/"
                       f"{urllib.parse.quote(branch, safe='')}", token)
        data = {
            "sha": commit.get("sha", ""),
            "date": (commit.get("commit") or {}).get("committer", {}).get("date", ""),
            "message": ((commit.get("commit") or {}).get("message") or "").splitlines()[0][:200],
            "branch": branch,
        }
    elif target.kind == "gitlab":
        pid = _gitlab_project_id(target)
        api = "https://gitlab.com/api/v4"
        branch = target.ref
        if not branch:
            project = _json(f"{api}/projects/{pid}")
            branch = project.get("default_branch") or "main"
        commit = _json(f"{api}/projects/{pid}/repository/commits/"
                       f"{urllib.parse.quote(branch, safe='')}")
        data = {"sha": commit.get("id", ""), "date": commit.get("committed_date", ""),
                "message": commit.get("title", ""), "branch": branch}
    else:
        data = {"sha": "", "date": "", "message": "", "branch": ""}

    _HEAD_CACHE[key] = (now, data)
    return data
