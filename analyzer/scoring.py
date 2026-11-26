"""评分引擎：五个维度、扣分可解释。"""
from __future__ import annotations

DIMENSIONS = [
    ("docs", "文档与说明", 20),
    ("deps", "依赖与构建", 20),
    ("run", "启动与运行", 15),
    ("portability", "跨平台可移植性", 20),
    ("security", "安全与敏感信息", 25),
]

TOTAL_MAX = sum(d[2] for d in DIMENSIONS)


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _grade(total: float, critical: int) -> dict:
    if total >= 85 and critical == 0:
        return {"letter": "A", "label": "可直接接入", "tone": "good"}
    if total >= 70:
        return {"letter": "B", "label": "低风险接入", "tone": "good" if critical == 0 else "warn"}
    if total >= 55:
        return {"letter": "C", "label": "需整改后接入", "tone": "warn"}
    return {"letter": "D", "label": "高风险，暂缓接入", "tone": "bad"}


def _verdict(total: float, grade: dict, risks: list[dict], facts: dict) -> str:
    counts = _counts(risks)
    if counts["critical"]:
        return (f"发现 {counts['critical']} 处严重密钥/敏感信息风险，"
                "建议先完成密钥轮换与历史清理，再讨论接入。")
    if total >= 85:
        return "依赖、启动与文档较为完整，未发现阻断性风险，可直接接入并按低优先级优化中风险项。"
    if total >= 70:
        return "整体可接入，建议在接入窗口内完成中风险项整改（启动脚本、可移植性、文档细节）。"
    if total >= 55:
        return "存在较多缺失或可移植性问题，建议完成整改并通过一次复检后再接入。"
    return "文档、依赖或安全层面存在明显缺口，不建议直接接入，需先完成治理。"


def _counts(risks: list[dict]) -> dict:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": len(risks)}
    for r in risks:
        if r["severity"] in out:
            out[r["severity"]] += 1
    return out


def compute_score(facts: dict, risks: list[dict]) -> dict:
    readme = facts.get("readme", {})
    deps = facts.get("deps", {})
    run = facts.get("run", {})
    hygiene = facts.get("hygiene", {})
    sec = facts.get("secrets", {})
    paths = facts.get("paths", {})

    dims: list[dict] = []

    # ---- 文档 ----
    reasons: list[dict] = []
    score = 0.0
    if readme.get("exists"):
        score += 9
        reasons.append({"text": "README 已提供", "delta": 9.0})
        quality = 0.0
        if readme.get("has_install"):
            quality += 2
            reasons.append({"text": "README 含安装说明", "delta": 2.0})
        else:
            reasons.append({"text": "README 缺少安装说明", "delta": 0.0})
        if readme.get("has_run"):
            quality += 2
            reasons.append({"text": "README 含运行/使用说明", "delta": 2.0})
        else:
            reasons.append({"text": "README 缺少运行说明", "delta": 0.0})
        if readme.get("headings", 0) >= 3 and readme.get("code_blocks", 0) >= 1:
            quality += 1
            reasons.append({"text": "README 结构完整（标题 + 代码块）", "delta": 1.0})
        score += quality
    else:
        reasons.append({"text": "缺少 README", "delta": 0.0})
    if hygiene.get("license", {}).get("exists"):
        score += 3
        reasons.append({"text": "已声明许可证", "delta": 3.0})
    else:
        reasons.append({"text": "未发现 LICENSE", "delta": 0.0})
    extras = 0.0
    if hygiene.get("changelog") or hygiene.get("contributing"):
        extras += 1.5
        reasons.append({"text": "提供 CHANGELOG / CONTRIBUTING", "delta": 1.5})
    if hygiene.get("docs_dir"):
        extras += 1.5
        reasons.append({"text": "提供 docs 目录", "delta": 1.5})
    score += extras
    dims.append(_dim("docs", score, reasons))

    # ---- 依赖 ----
    reasons = []
    score = 0.0
    if deps.get("manifests"):
        score += 10
        reasons.append({"text": f"识别到 {len(deps['manifests'])} 个依赖清单", "delta": 10.0})
    else:
        reasons.append({"text": "未发现标准依赖清单", "delta": 0.0})
    if deps.get("lockfiles"):
        score += 4
        reasons.append({"text": f"提供锁定文件（{len(deps['lockfiles'])} 个）", "delta": 4.0})
    else:
        reasons.append({"text": "缺少依赖锁定文件", "delta": 0.0})
    if deps.get("runtime_pins"):
        score += 3
        reasons.append({"text": "声明运行时版本约束", "delta": 3.0})
    else:
        reasons.append({"text": "未声明运行时版本", "delta": 0.0})
    if deps.get("manifests") and deps.get("package_json_valid") is not False:
        score += 3
        reasons.append({"text": "依赖清单可正常解析", "delta": 3.0})
    elif deps.get("package_json_valid") is False:
        reasons.append({"text": "package.json 解析失败", "delta": 0.0})
    dims.append(_dim("deps", score, reasons))

    # ---- 启动 ----
    reasons = []
    score = 0.0
    if run.get("start_like"):
        score += 6
        reasons.append({"text": f"提供启动/开发脚本：{', '.join(run['start_like'])}", "delta": 6.0})
    else:
        reasons.append({"text": "未发现 start/dev 脚本", "delta": 0.0})
    if run.get("readme_command"):
        score += 4
        reasons.append({"text": f"README 给出运行命令：{run['readme_command'][:40]}", "delta": 4.0})
    else:
        reasons.append({"text": "README 未给出可复制的运行命令", "delta": 0.0})
    if run.get("container") or run.get("procfile") or run.get("make_targets"):
        score += 5
        detail = "、".join((run.get("container") or []) + ([run.get("procfile")] if run.get("procfile") else [])
                            + ([run.get("makefile")] if run.get("makefile") else []))
        reasons.append({"text": f"提供容器/进程描述：{detail[:60]}", "delta": 5.0})
    else:
        reasons.append({"text": "未发现 Dockerfile / Procfile / Makefile", "delta": 0.0})
    dims.append(_dim("run", score, reasons))

    # ---- 可移植性 ----
    reasons = []
    win_count = len(facts.get("windows_scripts") or [])
    path_files = int(paths.get("files") or 0)
    personal = int(paths.get("personal") or 0)
    pen_win = min(6.0, win_count * 1.5)
    pen_paths = min(9.0, path_files * 1.5)
    pen_personal = min(5.0, personal * 1.2)
    score = 20.0 - pen_win - pen_paths - pen_personal
    if win_count:
        reasons.append({"text": f"{win_count} 个 Windows 专用脚本（-{pen_win:.1f}）", "delta": -pen_win})
    else:
        reasons.append({"text": "无 Windows 专用脚本", "delta": 0.0})
    if path_files:
        reasons.append({"text": f"硬编码路径涉及 {path_files} 个文件（-{pen_paths:.1f}）", "delta": -pen_paths})
    else:
        reasons.append({"text": "未发现硬编码绝对路径", "delta": 0.0})
    if personal:
        reasons.append({"text": f"{personal} 处个人目录/盘符路径（-{pen_personal:.1f}）", "delta": -pen_personal})
    dims.append(_dim("portability", score, reasons))

    # ---- 安全 ----
    reasons = []
    crit = int(sec.get("critical") or 0)
    high = int(sec.get("high") or 0)
    medium = int(sec.get("medium") or 0)
    pen = min(20.0, crit * 8.0) + min(10.0, high * 4.0) + min(6.0, medium * 1.5)
    gitignore = hygiene.get("gitignore", {})
    pen_git = 0.0
    if not gitignore.get("exists"):
        pen_git = 3.0
    elif not gitignore.get("covers_env"):
        pen_git = 2.0
    score = 25.0 - pen - pen_git
    if crit:
        reasons.append({"text": f"{crit} 处严重密钥/敏感信息风险（-{min(20.0, crit * 8.0):.1f}）",
                        "delta": -min(20.0, crit * 8.0)})
    else:
        reasons.append({"text": "未发现严重密钥泄露", "delta": 0.0})
    if high:
        reasons.append({"text": f"{high} 处高风险凭据/证书（-{min(10.0, high * 4.0):.1f}）",
                        "delta": -min(10.0, high * 4.0)})
    if medium:
        reasons.append({"text": f"{medium} 处疑似口令/Token（-{min(6.0, medium * 1.5):.1f}）",
                        "delta": -min(6.0, medium * 1.5)})
    if pen_git:
        reasons.append({"text": f".gitignore 保护不足（-{pen_git:.1f}）", "delta": -pen_git})
    dims.append(_dim("security", score, reasons))

    total = round(_clamp(sum(d["score"] for d in dims), 0, TOTAL_MAX), 1)
    counts = _counts(risks)
    grade = _grade(total, counts["critical"])
    return {
        "total": total,
        "max": TOTAL_MAX,
        "percent": round(total / TOTAL_MAX * 100, 1),
        "grade": grade,
        "verdict": _verdict(total, grade, risks, facts),
        "dimensions": dims,
        "counts": counts,
    }


def _dim(key: str, score: float, reasons: list[dict]) -> dict:
    label, max_score = next((d[1], d[2]) for d in DIMENSIONS if d[0] == key)
    score = round(_clamp(score, 0, max_score), 1)
    return {
        "key": key,
        "label": label,
        "score": score,
        "max": max_score,
        "percent": round(score / max_score * 100, 1),
        "reasons": reasons,
    }
