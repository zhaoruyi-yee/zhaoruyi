"""体检编排：抓取 → 检测 → 评分 → 建议 → 报告，含报告缓存与失败兜底。"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from . import ai as ai_mod
from . import provider, render, rules, scoring
from .provider import REPORT_CACHE_DIR, RateLimitError, ServiceError, Target

TOOL_NAME = "RepoCheckup"
TOOL_VERSION = "1.0.0"
RULE_VERSION = "2026.11.2"

STALE_FALLBACK_CODES = {"rate_limited", "network_error", "timeout", "upstream_error"}


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _slug(target: Target) -> str:
    raw = f"{target.host}_{target.full_name}_{target.subdir or 'root'}"
    return re.sub(r"[^A-Za-z0-9._-]+", "_", raw)[:120]


def _cache_path(target: Target, sha: str) -> Path:
    return REPORT_CACHE_DIR / f"{_slug(target)}_{sha}_{RULE_VERSION}.json"


def _read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _write_json(path: Path, data: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


def _latest_report(target: Target) -> dict | None:
    try:
        files = sorted(REPORT_CACHE_DIR.glob(f"{_slug(target)}_*.json"),
                       key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        return None
    for fp in files[:5]:
        data = _read_json(fp)
        if data:
            return data
    return None


def _commit_url(snap: provider.RepoSnapshot) -> str:
    if snap.host == "github":
        return f"https://github.com/{snap.full_name}/commit/{snap.commit_sha}"
    if snap.host == "gitlab":
        return f"https://gitlab.com/{snap.full_name}/-/commit/{snap.commit_sha}"
    return ""


def _build_base(snap: provider.RepoSnapshot, cache: dict) -> dict:
    result = rules.run_rules(snap)
    facts, risks = result["facts"], result["risks"]
    score = scoring.compute_score(facts, risks)
    coverage = facts["coverage"]

    warnings = list(snap.warnings)
    if snap.truncated_tree:
        warnings.append("文件树被上游截断（truncated），仅能覆盖部分文件。")
    if coverage["scanned_files"] < coverage["tree_files"]:
        warnings.append(
            f"为控制耗时，仅按优先级扫描 {coverage['scanned_files']} 个文本文件"
            f"（共 {coverage['tree_files']} 个文件），二进制/锁文件/超大文件未读取。")
    if snap.subdir:
        warnings.append(f"仅分析子目录：{snap.subdir}")

    stats = {
        "files_total": coverage["tree_files"],
        "files_scanned": coverage["scanned_files"],
        "coverage_pct": coverage["coverage_pct"],
        "windows_scripts": len(facts["windows_scripts"]),
        "hardcoded_paths": facts["paths"]["total"],
        "hardcoded_path_files": facts["paths"]["files"],
        "secret_hits": facts["secrets"]["total"],
        "manifests": len(facts["deps"]["manifests"]),
        "start_scripts": len(facts["run"]["start_like"]),
        "env_files": len([r for r in risks if r.get("rule") == "env_committed"]),
    }

    return {
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION, "rule_version": RULE_VERSION},
        "target": snap.target.raw,
        "generated_at": _now(),
        "repo": {
            "host": snap.host,
            "full_name": snap.full_name,
            "web_url": snap.web_url,
            "description": snap.description,
            "language": snap.language,
            "stars": snap.stars,
            "default_branch": snap.default_branch,
            "archived": snap.archived,
            "license": snap.license_name,
            "pushed_at": snap.pushed_at,
            "subdir": snap.subdir,
            "is_local": snap.host == "local",
        },
        "commit": {
            "sha": snap.commit_sha,
            "short_sha": snap.commit_sha[:7],
            "ref": snap.branch,
            "date": snap.commit_date,
            "message": snap.commit_message,
            "url": _commit_url(snap),
        },
        "cache": cache,
        "summary": {
            "score": score["total"],
            "max": score["max"],
            "percent": score["percent"],
            "grade": score["grade"],
            "verdict": score["verdict"],
            "counts": score["counts"],
        },
        "stats": stats,
        "dimensions": score["dimensions"],
        "risks": risks,
        "checks": result["checks"],
        "facts": facts,
        "warnings": warnings,
    }


def _finalize(base: dict, ai_cfg: dict | None) -> dict:
    report = dict(base)
    report["ai"] = ai_mod.advise(report, ai_cfg)
    report["markdown"] = render.to_markdown(report)
    return report


def analyze(text: str, *, force: bool = False, ai_cfg: dict | None = None,
            allow_local: bool = True) -> dict:
    target = provider.parse_target(text)
    if target.kind == "local":
        if not allow_local:
            raise ServiceError("服务端已禁用本地目录分析", code="local_disabled", status=403)
        snap = provider.fetch_local(target)
        base = _build_base(snap, {"report_hit": False, "blob_hits": 0,
                                  "blob_misses": snap.blob_stats.get("miss", 0), "stale": False})
        return _finalize(base, ai_cfg)

    try:
        head = provider.resolve_head(target)
        cache_file = _cache_path(target, head["sha"])
        if not force:
            cached = _read_json(cache_file)
            if cached:
                cached["cache"] = {**(cached.get("cache") or {}), "report_hit": True, "stale": False}
                cached["commit"].update({
                    "sha": head["sha"], "short_sha": head["sha"][:7],
                    "date": head.get("date") or cached["commit"].get("date", ""),
                    "message": head.get("message") or cached["commit"].get("message", ""),
                })
                return _finalize(cached, ai_cfg)

        snap = provider.fetch_snapshot(target)
        base = _build_base(snap, {
            "report_hit": False,
            "blob_hits": snap.blob_stats.get("hit", 0),
            "blob_misses": snap.blob_stats.get("miss", 0),
            "stale": False,
        })
        _write_json(cache_file, base)
        return _finalize(base, ai_cfg)

    except RateLimitError as exc:
        stale = _latest_report(target)
        if stale:
            return _stale_response(stale, exc, ai_cfg)
        reset = ""
        if exc.reset_at:
            reset = datetime.fromtimestamp(exc.reset_at).strftime("%H:%M")
        raise RateLimitError(
            f"上游 API 限流，且没有可用的历史报告。请在服务端配置 GITHUB_TOKEN 提升配额"
            + (f"，或于 {reset} 后重试。" if reset else "，稍后重试。"),
            reset_at=exc.reset_at)
    except ServiceError as exc:
        if exc.code in STALE_FALLBACK_CODES:
            stale = _latest_report(target)
            if stale:
                return _stale_response(stale, exc, ai_cfg)
        raise


def _stale_response(stale: dict, exc: ServiceError, ai_cfg: dict | None) -> dict:
    stale = json.loads(json.dumps(stale))  # 深拷贝，避免污染缓存
    stale["cache"] = {**(stale.get("cache") or {}), "report_hit": True, "stale": True}
    stale.setdefault("warnings", []).append(
        f"上游暂时不可用（{exc.code}），本报告为最近一次成功结果，"
        f"基于 commit {stale.get('commit', {}).get('short_sha', '')}，可能已过期。")
    return _finalize(stale, ai_cfg)


def check_updates(text: str) -> dict:
    target = provider.parse_target(text)
    if target.kind == "local":
        return {"is_local": True, "changed": None, "has_report": False}
    head = provider.resolve_head(target)
    latest = _latest_report(target)
    latest_sha = (latest or {}).get("commit", {}).get("sha", "")
    return {
        "is_local": False,
        "sha": head["sha"],
        "short_sha": head["sha"][:7],
        "branch": head.get("branch", ""),
        "date": head.get("date", ""),
        "message": head.get("message", ""),
        "latest_report_sha": latest_sha,
        "latest_report_short": latest_sha[:7],
        "has_report": bool(latest_sha),
        "changed": bool(latest_sha) and latest_sha != head["sha"],
    }
