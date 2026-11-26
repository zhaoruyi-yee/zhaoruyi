"""接入建议：本地规则引擎 + 可选 OpenAI 兼容大模型增强。"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

DEFAULT_BASE = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"


def _dim_gap(report: dict, key: str) -> float:
    for dim in report.get("dimensions", []):
        if dim["key"] == key:
            return max(0.0, dim["max"] - dim["score"])
    return 0.0


def rule_advice(report: dict) -> dict:
    risks = report.get("risks", [])
    facts = report.get("facts", {})
    counts = report.get("summary", {}).get("counts", {})
    grade = report.get("summary", {}).get("grade", {})

    suggestions: list[dict] = []

    def add(title: str, action: str, priority: str, dimension: str, impact: float):
        gap = _dim_gap(report, dimension)
        gain = round(min(max(impact, 0.0), gap), 1)
        if gain <= 0:
            gain = 0.0
        suggestions.append({
            "title": title,
            "action": action,
            "priority": priority,
            "dimension": dimension,
            "expected_gain": f"+{gain:.1f}",
            "impact": gain,
        })

    crit = int(counts.get("critical") or 0)
    if crit:
        add("先清理严重密钥与敏感文件",
            "立即轮换已暴露的密钥，使用 git filter-repo / BFG 清理历史，并补充 .gitignore 与密钥注入方案；"
            "这一步完成前不建议接入。",
            "P0", "security", min(20.0, crit * 8.0))

    gitignore = facts.get("hygiene", {}).get("gitignore", {})
    if not gitignore.get("exists"):
        add("补充 .gitignore", "至少忽略 .env、依赖目录、构建产物与本地配置。", "P1", "security", 3.0)
    elif not gitignore.get("covers_env"):
        add("让 .gitignore 覆盖 .env", "加入 .env 与 .env.* 规则，仅保留 .env.example 作为模板。",
            "P1", "security", 2.0)

    win_scripts = facts.get("windows_scripts") or []
    if win_scripts:
        add(f"处理 {len(win_scripts)} 个 Windows 专用脚本",
            "提供 .sh / Node / Python 等价脚本，或明确声明仅支持 Windows；容器化可一次性抹平差异。",
            "P1", "portability", min(6.0, len(win_scripts) * 1.5))

    path_files = int(facts.get("paths", {}).get("files") or 0)
    if path_files:
        add(f"移除硬编码路径（{path_files} 个文件）",
            "将 C:\\Users\\…、/Users/… 等改为基础目录 + 环境变量/配置文件，并提供示例路径。",
            "P1", "portability", min(9.0, path_files * 1.5))

    readme = facts.get("readme", {})
    if not readme.get("exists"):
        add("补充 README", "写清项目用途、环境要求、安装、启动、配置项与目录结构。", "P1", "docs", 14.0)
    elif not (readme.get("has_install") and readme.get("has_run")):
        add("补全 README 的安装与运行章节",
            "给出可直接复制执行的安装/启动命令、默认端口与必需环境变量。", "P2", "docs", 5.0)

    deps = facts.get("deps", {})
    if not deps.get("manifests"):
        add("补充依赖清单", "根据技术栈添加 package.json / requirements.txt / go.mod 等，便于平台自动构建。",
            "P1", "deps", 13.0)
    elif not deps.get("lockfiles"):
        add("提交依赖锁定文件", "提交 package-lock.json / requirements 锁文件，保证安装结果可复现。",
            "P2", "deps", 4.0)

    run = facts.get("run", {})
    if not run.get("start_like"):
        add("提供标准启动脚本", "在 package.json scripts 中提供 start/dev，或补充 Makefile / Procfile 启动目标。",
            "P1", "run", 6.0)
    if not run.get("readme_command"):
        add("在 README 写明启动命令", "例如 npm run dev / uvicorn app:app / docker compose up，附端口说明。",
            "P2", "run", 4.0)

    if not facts.get("hygiene", {}).get("license", {}).get("exists"):
        add("补充 LICENSE", "明确开源许可证（MIT / Apache-2.0 等），避免二次分发与商用边界不清。",
            "P2", "docs", 3.0)

    order = {"P0": 0, "P1": 1, "P2": 2}
    suggestions.sort(key=lambda s: (order.get(s["priority"], 3), -s["impact"]))
    suggestions = suggestions[:6]

    top = [r for r in risks if r["severity"] in ("critical", "high")][:3]
    if counts.get("critical"):
        summary = (f"当前接入就绪度 {report['summary']['score']} 分（{grade.get('letter')} · "
                   f"{grade.get('label')}）。存在严重密钥/敏感信息风险，属于接入阻断项，需先完成轮换与历史清理。")
    elif report["summary"]["score"] >= 85:
        summary = (f"接入就绪度 {report['summary']['score']} 分（{grade.get('letter')} · "
                   f"{grade.get('label')}）。工程要素齐全，可按常规流程接入，顺手处理中低风险项即可。")
    elif report["summary"]["score"] >= 70:
        summary = (f"接入就绪度 {report['summary']['score']} 分（{grade.get('letter')} · "
                   f"{grade.get('label')}）。整体可接入，建议先补齐启动/依赖/可移植性中的短板。")
    else:
        summary = (f"接入就绪度 {report['summary']['score']} 分（{grade.get('letter')} · "
                   f"{grade.get('label')}）。存在多个基础性缺口，建议完成整改并复检后再接入。")
    if top:
        summary += " 重点关注：" + "；".join(r["title"] for r in top) + "。"

    return {
        "provider": "rules",
        "model": "内置规则引擎",
        "summary": summary,
        "suggestions": suggestions,
        "note": "未配置大模型时的本地规则建议，离线可用；规则仅基于本次扫描到的文件。",
    }


# ---------------------------------------------------------------------------
# 可选 LLM 增强
# ---------------------------------------------------------------------------

def _resolve_cfg(cfg: dict | None) -> dict:
    cfg = cfg or {}
    base = (cfg.get("base_url") or os.environ.get("LLM_BASE_URL") or DEFAULT_BASE).strip()
    model = (cfg.get("model") or os.environ.get("LLM_MODEL") or DEFAULT_MODEL).strip()
    key = (cfg.get("api_key") or os.environ.get("LLM_API_KEY") or "").strip()
    base = base.rstrip("/")
    if not re.match(r"^https?://", base):
        raise ValueError("AI Base URL 必须以 http(s):// 开头")
    if len(key) > 400:
        raise ValueError("API Key 长度异常")
    return {"base_url": base, "model": model, "api_key": key}


def _compact_report(report: dict) -> dict:
    facts = report.get("facts", {})
    return {
        "repo": {
            "full_name": report["repo"]["full_name"],
            "description": report["repo"].get("description", "")[:200],
            "language": report["repo"].get("language", ""),
            "stars": report["repo"].get("stars", 0),
        },
        "score": report["summary"]["score"],
        "grade": report["summary"]["grade"],
        "dimensions": [{"label": d["label"], "score": d["score"], "max": d["max"]}
                       for d in report["dimensions"]],
        "counts": report["summary"]["counts"],
        "risks": [{"severity": r["severity"], "title": r["title"][:120], "file": r["file"]}
                  for r in report.get("risks", [])[:15]],
        "facts": {
            "readme": {k: facts.get("readme", {}).get(k) for k in
                       ("exists", "has_install", "has_run", "lines", "headings")},
            "manifests": [m["type"] for m in facts.get("deps", {}).get("manifests", [])],
            "lockfiles": facts.get("deps", {}).get("lockfiles", []),
            "runtime_pins": facts.get("deps", {}).get("runtime_pins", []),
            "start_scripts": list((facts.get("run", {}).get("scripts") or {}).keys()),
            "windows_scripts": [s["path"] for s in facts.get("windows_scripts", [])][:10],
            "hardcoded_path_files": facts.get("paths", {}).get("files", 0),
            "env_files": [r["file"] for r in report.get("risks", []) if r.get("rule") == "env_committed"],
            "license": facts.get("hygiene", {}).get("license", {}),
            "ci": facts.get("hygiene", {}).get("ci", []),
            "tests": facts.get("hygiene", {}).get("tests", False),
        },
    }


SYSTEM_PROMPT = (
    "你是代码仓库接入评审专家。请基于给定的体检数据，输出 JSON，不要输出 Markdown 代码块。"
    "要求：1) 不要编造数据中不存在的事实；2) 建议必须可执行、按优先级排序；"
    "3) 预计提分需保守估计，不超过对应维度当前失分；4) 全部使用简体中文。"
    '输出格式：{"verdict":"一句话结论","summary":"2-3 句总体评估",'
    '"suggestions":[{"title":"短标题","action":"具体动作","priority":"P0|P1|P2",'
    '"expected_gain":"+x.x 分"}]}'
)


def _call_llm(report: dict, cfg: dict) -> dict:
    payload = {
        "model": cfg["model"],
        "temperature": 0.2,
        "max_tokens": 900,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(_compact_report(report), ensure_ascii=False)},
        ],
    }
    req = urllib.request.Request(
        f"{cfg['base_url']}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {cfg['api_key']}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace")[:200]
        except Exception:
            pass
        raise RuntimeError(f"AI 服务返回 HTTP {exc.code} {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"AI 服务网络错误：{exc.reason}") from exc

    content = ((data.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    content = content.strip()
    if content.startswith("```"):
        content = re.sub(r"^```[a-zA-Z]*\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
    try:
        parsed = json.loads(content)
    except ValueError as exc:
        raise RuntimeError("AI 返回内容不是合法 JSON") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("AI 返回结构异常")

    suggestions = []
    for item in (parsed.get("suggestions") or [])[:6]:
        if not isinstance(item, dict):
            continue
        suggestions.append({
            "title": str(item.get("title", ""))[:80],
            "action": str(item.get("action", ""))[:500],
            "priority": str(item.get("priority", "P1")).upper()[:2],
            "dimension": "ai",
            "expected_gain": str(item.get("expected_gain", ""))[:20],
            "impact": 0,
        })
    if not suggestions:
        raise RuntimeError("AI 未返回可用建议")

    return {
        "model": cfg["model"],
        "verdict": str(parsed.get("verdict", ""))[:200],
        "summary": str(parsed.get("summary", ""))[:800],
        "suggestions": suggestions,
        "note": "由大模型基于体检摘要生成，仅供辅助决策；请以清单中的事实为准。",
    }


def advise(report: dict, cfg: dict | None = None) -> dict:
    try:
        resolved = _resolve_cfg(cfg)
    except ValueError as exc:
        out = rule_advice(report)
        out["note"] = f"AI 配置无效，已回退本地规则建议：{exc}"
        return out
    if not resolved["api_key"]:
        return rule_advice(report)
    try:
        result = _call_llm(report, resolved)
        result["provider"] = "llm"
        return result
    except Exception as exc:  # noqa: BLE001
        out = rule_advice(report)
        out["provider"] = "rules"
        out["note"] = f"AI 增强调用失败，已回退本地规则建议（{exc}）"
        return out
