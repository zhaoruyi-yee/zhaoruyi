"""把报告渲染成 Markdown，供前端下载或 CLI 输出。"""
from __future__ import annotations


def _cell(value: object, limit: int = 160) -> str:
    text = str(value if value is not None else "")
    text = text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    return text[:limit]


def to_markdown(report: dict) -> str:
    repo = report.get("repo", {})
    commit = report.get("commit", {})
    summary = report.get("summary", {})
    grade = summary.get("grade", {})
    counts = summary.get("counts", {})
    stats = report.get("stats", {})

    lines: list[str] = []
    lines.append(f"# 接入体检报告：{repo.get('full_name', '')}")
    lines.append("")
    lines.append(f"- 目标：{report.get('target', '')}")
    lines.append(f"- 分支 / commit：`{commit.get('ref', '')}` / `{commit.get('short_sha', '')}`"
                 f"（{commit.get('date', '')}）")
    lines.append(f"- 生成时间：{report.get('generated_at', '')}")
    lines.append(f"- 规则版本：{report.get('tool', {}).get('rule_version', '')}")
    lines.append(f"- 扫描范围：{stats.get('files_scanned', 0)} / {stats.get('files_total', 0)} 个文件"
                 f"（{stats.get('coverage_pct', 0)}%）")
    lines.append("")
    lines.append(f"## 接入就绪度：{summary.get('score', 0)} / 100"
                 f"（{grade.get('letter', '')} · {grade.get('label', '')}）")
    lines.append("")
    lines.append(f"> {summary.get('verdict', '')}")
    lines.append("")
    lines.append(f"风险统计：严重 {counts.get('critical', 0)} · 高 {counts.get('high', 0)} · "
                 f"中 {counts.get('medium', 0)} · 低 {counts.get('low', 0)}")
    lines.append("")
    lines.append("| 维度 | 得分 | 满分 |")
    lines.append("| --- | --: | --: |")
    for dim in report.get("dimensions", []):
        lines.append(f"| {_cell(dim['label'])} | {dim['score']} | {dim['max']} |")
    lines.append("")

    lines.append("## 主要风险清单")
    lines.append("")
    risks = report.get("risks", [])
    if not risks:
        lines.append("未发现风险项。")
    else:
        lines.append("| 级别 | 类别 | 问题 | 位置 | 建议 |")
        lines.append("| --- | --- | --- | --- | --- |")
        for risk in risks[:40]:
            location = risk.get("file") or "-"
            if risk.get("line"):
                location += f":{risk['line']}"
            lines.append(f"| {risk['severity']} | {_cell(risk['category'])} | "
                         f"{_cell(risk['title'], 110)} | {_cell(location, 90)} | "
                         f"{_cell(risk['advice'], 140)} |")
        if len(risks) > 40:
            lines.append("")
            lines.append(f"（仅列出前 40 条，共 {len(risks)} 条；完整清单见 JSON 报告。）")
    lines.append("")

    lines.append("## 检查清单")
    lines.append("")
    lines.append("| 分组 | 检查项 | 状态 | 说明 |")
    lines.append("| --- | --- | --- | --- |")
    status_label = {"pass": "通过", "warn": "注意", "fail": "未通过", "info": "信息"}
    for check in report.get("checks", []):
        lines.append(f"| {_cell(check['group'])} | {_cell(check['label'])} | "
                     f"{status_label.get(check['status'], check['status'])} | {_cell(check['detail'], 140)} |")
    lines.append("")

    ai_block = report.get("ai") or {}
    if ai_block.get("suggestions"):
        lines.append("## 接入建议")
        lines.append("")
        if ai_block.get("summary"):
            lines.append(ai_block["summary"])
            lines.append("")
        for idx, item in enumerate(ai_block["suggestions"], 1):
            gain = item.get("expected_gain") or ""
            lines.append(f"{idx}. **[{item.get('priority', 'P1')}] {item.get('title', '')}**"
                         f"（预计 {gain}）：{item.get('action', '')}")
        lines.append("")
        if ai_block.get("note"):
            lines.append(f"> {ai_block['note']}")
            lines.append("")

    warnings = report.get("warnings") or []
    if warnings:
        lines.append("## 扫描说明与限制")
        lines.append("")
        for w in warnings:
            lines.append(f"- {w}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("本报告由 RepoCheckup 自动生成，基于静态扫描，可能存在误报/漏报；"
                 "密钥类结果仅展示脱敏片段，任何疑似真实凭据请按流程轮换。")
    lines.append("")
    return "\n".join(lines)
