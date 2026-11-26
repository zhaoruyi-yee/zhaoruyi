'use strict';

const $ = (id) => document.getElementById(id);

const SEV_LABEL = { critical: '严重', high: '高', medium: '中', low: '低' };
const CAT_LABEL = {
  secrets: '密钥与敏感信息', paths: '硬编码路径', windows: 'Windows 专用',
  docs: '文档', deps: '依赖', run: '启动', hygiene: '工程规范',
};
const GROUP_LABEL = {
  docs: '文档与说明', deps: '依赖与构建', run: '启动与运行',
  portability: '跨平台可移植性', security: '安全与敏感信息', hygiene: '工程规范',
};
const STATUS_LABEL = { pass: '通过', warn: '注意', fail: '未通过', info: '信息' };
const LOADING_STEPS = [
  '解析仓库地址与分支',
  '获取仓库元信息与最新 commit',
  '拉取文件树，按优先级筛选文件',
  '抓取文件内容（命中 blob 缓存则跳过）',
  '执行规则扫描与评分',
  '生成接入建议与报告',
];

const state = {
  report: null,
  sev: 'all',
  category: 'all',
  q: '',
  shown: 20,
  timers: { clock: null, step: null },
  startedAt: 0,
};

/* ------------------------------------------------------------------ */
/* 工具函数                                                            */
/* ------------------------------------------------------------------ */

function esc(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function safeUrl(url) {
  return typeof url === 'string' && /^https?:\/\//i.test(url) ? url : '';
}

function fmtNum(value) {
  const num = Number(value);
  if (!Number.isFinite(num)) return '0';
  return Number.isInteger(num) ? String(num) : num.toFixed(1);
}

function truncate(text, max) {
  const str = String(text == null ? '' : text);
  return str.length > max ? str.slice(0, max) + '…' : str;
}

function toast(message) {
  const box = $('toast');
  box.textContent = message;
  box.hidden = false;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => { box.hidden = true; }, 2600);
}

function download(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

/* ------------------------------------------------------------------ */
/* 初始化                                                              */
/* ------------------------------------------------------------------ */

function init() {
  $('analyze-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const url = $('repo-url').value.trim();
    if (!url) {
      showError('请输入仓库地址', '支持 GitHub / GitLab 公开仓库，或本机目录路径。');
      return;
    }
    runAnalyze(url, false);
  });

  document.querySelectorAll('.chip[data-url]').forEach((chip) => {
    chip.addEventListener('click', () => {
      $('repo-url').value = chip.dataset.url;
      $('repo-url').focus();
    });
  });

  document.querySelectorAll('.tab').forEach((tab) => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
  });

  $('sev-filters').addEventListener('click', (event) => {
    const btn = event.target.closest('.filter-chip');
    if (!btn) return;
    state.sev = btn.dataset.sev;
    state.shown = 20;
    document.querySelectorAll('#sev-filters .filter-chip').forEach((el) => {
      el.classList.toggle('active', el === btn);
    });
    renderRisks();
  });

  $('category-filter').addEventListener('change', (event) => {
    state.category = event.target.value;
    state.shown = 20;
    renderRisks();
  });

  let searchTimer = null;
  $('risk-search').addEventListener('input', (event) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.q = event.target.value.trim().toLowerCase();
      state.shown = 20;
      renderRisks();
    }, 120);
  });

  $('load-more').addEventListener('click', () => {
    state.shown += 20;
    renderRisks();
  });

  $('check-update').addEventListener('click', checkUpdates);
  $('rescan').addEventListener('click', () => {
    if (state.report) {
      $('repo-url').value = state.report.target;
      runAnalyze(state.report.target, true);
    }
  });
  $('update-rerun').addEventListener('click', () => {
    if (state.report) runAnalyze(state.report.target, true);
  });

  $('download-md').addEventListener('click', () => {
    const report = state.report;
    if (!report) return;
    download(`${fileName(report)}.md`, report.markdown || '', 'text/markdown;charset=utf-8');
  });
  $('download-json').addEventListener('click', () => {
    const report = state.report;
    if (!report) return;
    download(`${fileName(report)}.json`, JSON.stringify(report, null, 2), 'application/json');
  });
  $('print-report').addEventListener('click', () => window.print());

  fetchHealth();
}

function fileName(report) {
  const name = (report.repo.full_name || 'repo').replace(/[\\/:*?"<>|\s]+/g, '-');
  return `repocheckup-${name}-${report.commit.short_sha || 'local'}`;
}

/* ------------------------------------------------------------------ */
/* 健康检查 / 环境提示                                                 */
/* ------------------------------------------------------------------ */

async function fetchHealth() {
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    $('rule-version').textContent = `rule ${data.rule_version}`;
    $('footer-versions').textContent = `v${data.version} · rule ${data.rule_version}`;
    const badges = [];
    badges.push(`<span class="health-badge ${data.github_token ? 'ok' : 'warn'}">
      <span class="dot"></span>${data.github_token ? 'GitHub Token 已配置' : '未配置 Token · 60 次/小时'}</span>`);
    badges.push(`<span class="health-badge ${data.llm_configured ? 'ok' : ''}">
      <span class="dot"></span>${data.llm_configured ? '服务端 AI 模型已配置' : 'AI：本地规则引擎'}</span>`);
    badges.push(`<span class="health-badge ${data.local_enabled ? 'ok' : 'warn'}">
      <span class="dot"></span>${data.local_enabled ? '本地目录分析可用' : '本地目录分析已禁用'}</span>`);
    $('health-badges').innerHTML = badges.join('');
    $('ai-mode-hint').textContent = data.llm_configured
      ? '服务端已配置模型，可直接调用'
      : '未配置时使用本地规则引擎';
  } catch (err) {
    $('health-badges').innerHTML = '<span class="health-badge warn"><span class="dot"></span>服务状态未知</span>';
  }
}

/* ------------------------------------------------------------------ */
/* 分析流程                                                            */
/* ------------------------------------------------------------------ */

function collectAiCfg() {
  const base = $('ai-base').value.trim();
  const model = $('ai-model').value.trim();
  const key = $('ai-key').value.trim();
  if (!key) return null;
  return { base_url: base || undefined, model: model || undefined, api_key: key };
}

function startLoading() {
  state.startedAt = performance.now();
  $('loading').hidden = false;
  $('loading-step').textContent = LOADING_STEPS[0];
  $('loading-time').textContent = '0.0s';
  let step = 0;
  state.timers.step = setInterval(() => {
    step = Math.min(step + 1, LOADING_STEPS.length - 1);
    $('loading-step').textContent = LOADING_STEPS[step];
  }, 1300);
  state.timers.clock = setInterval(() => {
    const seconds = (performance.now() - state.startedAt) / 1000;
    $('loading-time').textContent = `${seconds.toFixed(1)}s`;
  }, 100);
}

function stopLoading() {
  clearInterval(state.timers.step);
  clearInterval(state.timers.clock);
  $('loading').hidden = true;
}

async function runAnalyze(url, force) {
  hideError();
  $('result').hidden = true;
  $('submit-btn').disabled = true;
  startLoading();
  try {
    const payload = { url, force: Boolean(force) };
    const aiCfg = collectAiCfg();
    if (aiCfg) payload.ai = aiCfg;
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || !data || data.error) {
      throw buildError(data, res.status);
    }
    state.report = data;
    state.sev = 'all';
    state.category = 'all';
    state.q = '';
    state.shown = 20;
    resetFilters();
    renderReport(data);
    $('result').hidden = false;
    $('update-banner').hidden = true;
    window.scrollTo({ top: $('result').offsetTop - 16, behavior: 'smooth' });
    toast(data.cache && data.cache.report_hit ? '命中缓存：commit 未变化' : '体检完成');
  } catch (err) {
    showError(err.title || '分析失败', err.message || '未知错误', err.hint || '');
  } finally {
    stopLoading();
    $('submit-btn').disabled = false;
  }
}

function buildError(data, status) {
  const error = (data && data.error) || {};
  const code = error.code || `http_${status}`;
  const hints = {
    rate_limited: '可在服务端设置 GITHUB_TOKEN 后重启服务以提升配额，或稍后重试；已有历史报告时会自动回退展示。',
    not_found: '请确认仓库/分支公开且地址完整（owner/repo）。',
    invalid_input: '支持 https://github.com/owner/repo、https://gitlab.com/group/repo 或本机目录。',
    unsupported_host: '当前支持 GitHub、GitLab 与本机目录，其他平台暂未接入。',
    network_error: '本机无法访问 GitHub/GitLab，请检查网络或代理；也可先用本机目录验证核心功能。',
    timeout: '上游响应超时，请稍后重试或配置 GITHUB_TOKEN。',
    unauthorized: 'GITHUB_TOKEN 无效或过期，请更新服务端环境变量后重启。',
    local_disabled: '服务端使用 --no-local 启动，已禁用本地目录分析。',
  };
  return {
    title: '分析失败',
    message: error.message || `请求失败（HTTP ${status}）`,
    hint: hints[code] || '',
  };
}

function showError(title, message, hint) {
  $('error-title').textContent = title;
  $('error-detail').textContent = message;
  $('error-hint').textContent = hint || '';
  $('error-box').hidden = false;
  $('error-box').scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function hideError() {
  $('error-box').hidden = true;
}

/* ------------------------------------------------------------------ */
/* 渲染主流程                                                          */
/* ------------------------------------------------------------------ */

function renderReport(report) {
  renderScore(report);
  renderDimensions(report);
  renderStats(report);
  renderMeta(report);
  renderRisks();
  renderChecks(report);
  renderFacts(report);
  renderAi(report);
  renderExport(report);
  $('risk-tab-count').textContent = report.summary.counts.total;
  $('check-tab-count').textContent = report.checks.filter(
    (c) => c.status === 'fail' || c.status === 'warn').length;
}

function renderScore(report) {
  const summary = report.summary;
  const percent = Math.max(0, Math.min(100, Number(summary.percent) || 0));
  const circumference = 2 * Math.PI * 72;
  const ring = $('ring-value');
  const tone = summary.grade.tone;
  const color = tone === 'bad' ? '#f87171' : tone === 'warn' ? '#fbbf24' : '#5eead4';
  ring.style.stroke = color;
  ring.style.strokeDasharray = `${circumference}`;
  ring.style.strokeDashoffset = `${circumference}`;
  requestAnimationFrame(() => {
    setTimeout(() => {
      ring.style.strokeDashoffset = `${circumference * (1 - percent / 100)}`;
    }, 40);
  });
  $('score-value').textContent = fmtNum(summary.score);
  const badge = $('grade-letter');
  badge.textContent = summary.grade.letter;
  badge.className = 'grade-badge' + (tone === 'warn' ? ' warn' : tone === 'bad' ? ' bad' : '');
  $('grade-label').textContent = summary.grade.label;
  $('verdict').textContent = summary.verdict;
  const counts = summary.counts;
  $('risk-counts').innerHTML = ['critical', 'high', 'medium', 'low'].map((sev) => `
    <span class="count-pill ${sev}">${SEV_LABEL[sev]}风险 <b>${counts[sev] || 0}</b></span>
  `).join('');
}

function renderDimensions(report) {
  $('dims').innerHTML = report.dimensions.map((dim) => {
    const reasons = dim.reasons.map((reason) => {
      const delta = Number(reason.delta) || 0;
      const cls = delta > 0 ? 'reason-pos' : delta < 0 ? 'reason-neg' : '';
      const label = delta > 0 ? `+${fmtNum(delta)}` : delta < 0 ? fmtNum(delta) : '0';
      return `<li class="${cls}">${esc(reason.text)} · ${label}</li>`;
    }).join('');
    return `
      <div class="dim-row">
        <div class="dim-top"><span>${esc(dim.label)}</span><span>${fmtNum(dim.score)} / ${dim.max}</span></div>
        <div class="dim-bar"><div class="dim-fill" style="width:${Math.max(0, Math.min(100, dim.percent))}%"></div></div>
        <details>
          <summary>${dim.reasons.length} 条评分依据</summary>
          <ul class="reason-list">${reasons}</ul>
        </details>
      </div>`;
  }).join('');
}

function renderStats(report) {
  const stats = report.stats || {};
  const counts = report.summary.counts;
  const tiles = [
    { label: '扫描文件', value: `${stats.files_scanned ?? 0}/${stats.files_total ?? 0}`,
      sub: `覆盖率 ${fmtNum(stats.coverage_pct)}%` },
    { label: '风险总数', value: counts.total,
      sub: `严重 ${counts.critical} · 高 ${counts.high}`, cls: counts.critical ? 'danger' : '' },
    { label: 'Windows 脚本', value: stats.windows_scripts ?? 0,
      sub: '.bat / .cmd / .ps1 / .vbs', cls: stats.windows_scripts ? 'warn' : '' },
    { label: '硬编码路径', value: stats.hardcoded_paths ?? 0,
      sub: `涉及 ${stats.hardcoded_path_files ?? 0} 个文件`, cls: stats.hardcoded_paths ? 'warn' : '' },
    { label: '密钥命中', value: stats.secret_hits ?? 0,
      sub: '命中后自动脱敏', cls: stats.secret_hits ? 'danger' : '' },
    { label: '依赖清单', value: stats.manifests ?? 0,
      sub: `锁文件 ${(report.facts.deps.lockfiles || []).length} 个` },
  ];
  $('stat-strip').innerHTML = tiles.map((tile) => `
    <div class="stat-tile ${tile.cls || ''}">
      <span class="stat-label">${esc(tile.label)}</span>
      <span class="stat-value">${esc(tile.value)}</span>
      <span class="stat-sub">${esc(tile.sub)}</span>
    </div>`).join('');
}

function renderMeta(report) {
  const repo = report.repo;
  const commit = report.commit;
  const cache = report.cache || {};
  $('repo-name').textContent = repo.full_name;
  const link = $('repo-link');
  if (repo.web_url) {
    link.href = safeUrl(repo.web_url);
    link.textContent = repo.host === 'gitlab' ? '在 GitLab 查看' : '在 GitHub 查看';
    link.hidden = false;
  } else {
    link.hidden = true;
  }
  $('repo-desc').textContent = repo.description || (repo.is_local ? '本机目录快照（未提供描述）' : '暂无仓库描述');
  const tags = [];
  if (repo.is_local) tags.push('本地目录');
  if (repo.language) tags.push(repo.language);
  if (repo.license) tags.push(repo.license);
  if (repo.stars) tags.push(`${repo.stars} stars`);
  if (repo.default_branch) tags.push(`默认分支 ${repo.default_branch}`);
  if (repo.subdir) tags.push(`子目录 ${repo.subdir}`);
  if (repo.archived) tags.push('已归档');
  $('repo-tags').innerHTML = tags.map((t) => `<span class="tag">${esc(t)}</span>`).join('');

  $('commit-sha').textContent = commit.short_sha || '—';
  const commitLink = $('commit-link');
  if (commit.url && safeUrl(commit.url)) {
    commitLink.href = commit.url;
  } else {
    commitLink.removeAttribute('href');
  }
  $('commit-msg').textContent = [commit.ref, commit.message].filter(Boolean).join(' · ');
  $('generated-at').textContent = `生成于 ${(report.generated_at || '').replace('T', ' ').slice(0, 19)}`;

  const pill = $('cache-pill');
  let pillText = '新扫描';
  let pillClass = 'pill';
  if (cache.stale) {
    pillText = '历史报告 · 上游异常';
    pillClass = 'pill warn';
  } else if (cache.report_hit) {
    pillText = '命中缓存 · commit 未变化';
    pillClass = 'pill ok';
  } else if (cache.blob_hits) {
    pillText = `新扫描 · 复用 ${cache.blob_hits} 个 blob`;
    pillClass = 'pill ok';
  }
  pill.textContent = pillText;
  pill.className = pillClass;
  $('check-update').hidden = Boolean(repo.is_local);
}

/* ------------------------------------------------------------------ */
/* 风险清单                                                            */
/* ------------------------------------------------------------------ */

function resetFilters() {
  document.querySelectorAll('#sev-filters .filter-chip').forEach((el) => {
    el.classList.toggle('active', el.dataset.sev === 'all');
  });
  $('category-filter').value = 'all';
  $('risk-search').value = '';
}

function riskMatches(risk) {
  if (state.sev !== 'all' && risk.severity !== state.sev) return false;
  if (state.category !== 'all' && risk.category !== state.category) return false;
  if (state.q) {
    const haystack = `${risk.title} ${risk.file} ${risk.rule} ${risk.advice}`.toLowerCase();
    if (!haystack.includes(state.q)) return false;
  }
  return true;
}

function renderRisks() {
  const report = state.report;
  if (!report) return;
  const risks = report.risks.filter(riskMatches);
  const counts = report.summary.counts;
  const shown = risks.slice(0, state.shown);
  $('risk-summary').textContent =
    `共 ${counts.total} 条风险（严重 ${counts.critical} · 高 ${counts.high} · 中 ${counts.medium} · 低 ${counts.low}），`
    + `当前筛选 ${risks.length} 条，展示 ${shown.length} 条。`;

  if (!risks.length) {
    $('risk-list').innerHTML = '<div class="empty-state">当前筛选条件下没有风险项。切换筛选或清空搜索试试。</div>';
    $('load-more').hidden = true;
    return;
  }

  $('risk-list').innerHTML = shown.map((risk) => {
    const location = risk.file
      ? `${risk.file}${risk.line ? ':' + risk.line : ''}`
      : '仓库级';
    const href = safeUrl(risk.url);
    const fileHtml = href
      ? `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer">${esc(location)}</a>`
      : esc(location);
    const snippet = risk.snippet
      ? `<pre class="snippet">${esc(truncate(risk.snippet, 300))}</pre>`
      : '';
    return `
      <article class="risk ${risk.severity}">
        <div class="risk-head">
          <span class="sev sev-${risk.severity}">${SEV_LABEL[risk.severity]}</span>
          <span class="risk-title">${esc(risk.title)}</span>
          <span class="risk-file">${fileHtml}</span>
        </div>
        ${snippet}
        <p class="advice">${esc(risk.advice)}</p>
      </article>`;
  }).join('');
  $('load-more').hidden = shown.length >= risks.length;
}

/* ------------------------------------------------------------------ */
/* 检查项                                                              */
/* ------------------------------------------------------------------ */

function renderChecks(report) {
  const groups = {};
  report.checks.forEach((check) => {
    (groups[check.group] = groups[check.group] || []).push(check);
  });
  const order = ['docs', 'deps', 'run', 'portability', 'security', 'hygiene'];
  $('check-groups').innerHTML = order.filter((key) => groups[key]).map((key) => {
    const items = groups[key];
    const failed = items.filter((c) => c.status === 'fail' || c.status === 'warn').length;
    const rows = items.map((check) => `
      <div class="check-item">
        <span class="status-dot status-${check.status}" title="${STATUS_LABEL[check.status] || ''}"></span>
        <span class="check-label">${esc(check.label)}</span>
        <span class="check-detail">${esc(check.detail)}</span>
      </div>`).join('');
    return `
      <div class="check-group">
        <div class="check-group-head">${esc(GROUP_LABEL[key] || key)}
          <span>${items.length} 项 · ${failed} 项需关注</span>
        </div>
        ${rows}
      </div>`;
  }).join('');
}

/* ------------------------------------------------------------------ */
/* 仓库画像                                                            */
/* ------------------------------------------------------------------ */

function factCard(title, subtitle, body) {
  return `<div class="fact-card"><h3>${esc(title)}<span>${esc(subtitle)}</span></h3>${body}</div>`;
}

function kvRows(rows) {
  return `<div class="kv">${rows.map(([key, value]) => `
    <div class="kv-row"><span>${esc(key)}</span><span>${value}</span></div>`).join('')}</div>`;
}

function tagList(items, empty) {
  if (!items || !items.length) return `<p class="fact-empty">${esc(empty)}</p>`;
  return `<div class="tag-list">${items.map((item) => `<span class="tag">${esc(item)}</span>`).join('')}</div>`;
}

function renderFacts(report) {
  const facts = report.facts;
  const readme = facts.readme || {};
  const deps = facts.deps || {};
  const run = facts.run || {};
  const hygiene = facts.hygiene || {};
  const cards = [];

  const readmeRows = readme.exists ? [
    ['文件', `<code>${esc(readme.path || '')}</code>`],
    ['规模', `${readme.lines || 0} 行 · ${readme.headings || 0} 个标题 · ${readme.code_blocks || 0} 段代码块`],
    ['安装说明', readme.has_install ? '<span class="reason-pos">有</span>' : '<span class="reason-neg">无</span>'],
    ['运行说明', readme.has_run ? '<span class="reason-pos">有</span>' : '<span class="reason-neg">无</span>'],
    ['许可证章节', readme.has_license_section ? '有' : '无'],
    ['徽章 / 图片', readme.has_badges ? '有' : '无'],
  ] : [['状态', '<span class="reason-neg">未找到 README</span>']];
  cards.push(factCard('README', readme.exists ? '文档完整度' : '缺失', kvRows(readmeRows)));

  const manifestRows = deps.manifests && deps.manifests.length
    ? `<table class="mini-table"><thead><tr><th>文件</th><th>类型</th><th>说明</th></tr></thead><tbody>
        ${deps.manifests.map((m) => `<tr><td>${esc(m.file)}</td><td>${esc(m.type)}</td><td>${esc(m.detail || '-')}</td></tr>`).join('')}
       </tbody></table>`
    : '<p class="fact-empty">未发现 package.json / requirements.txt / go.mod 等依赖清单</p>';
  cards.push(factCard('依赖与构建', `${(deps.lockfiles || []).length} 个锁文件`,
    `${manifestRows}
     <div class="kv" style="margin-top:10px">
       <div class="kv-row"><span>锁文件</span><span>${esc((deps.lockfiles || []).join('、') || '无')}</span></div>
       <div class="kv-row"><span>运行时约束</span><span>${esc((deps.runtime_pins || []).join('、') || '未声明')}</span></div>
     </div>`));

  const scriptRows = Object.keys(run.scripts || {}).length
    ? `<table class="mini-table fact-scroll"><thead><tr><th>script</th><th>命令</th></tr></thead><tbody>
        ${Object.entries(run.scripts).map(([name, cmd]) => `<tr><td>${esc(name)}</td><td>${esc(truncate(cmd, 70))}</td></tr>`).join('')}
       </tbody></table>`
    : '<p class="fact-empty">package.json 中未发现 scripts</p>';
  cards.push(factCard('启动与运行', `${Object.keys(run.start_like || {}).length} 个启动脚本`,
    `${scriptRows}
     <div class="kv" style="margin-top:10px">
       <div class="kv-row"><span>Makefile</span><span>${esc((run.make_targets || []).join(', ') || (run.makefile ? '有（未解析到目标）' : '无'))}</span></div>
       <div class="kv-row"><span>容器 / 进程</span><span>${esc((run.container || []).join('、') || run.procfile || '无')}</span></div>
       <div class="kv-row"><span>README 命令</span><span>${esc(run.readme_command || '未匹配到')}</span></div>
     </div>`));

  const winScripts = facts.windows_scripts || [];
  const winTable = winScripts.length
    ? `<table class="mini-table fact-scroll"><thead><tr><th>文件</th><th>类型</th><th>大小</th></tr></thead><tbody>
        ${winScripts.map((item) => `<tr><td>${esc(item.path)}</td><td>.${esc(item.ext)}</td>
          <td>${item.size > 0 ? esc((item.size / 1024).toFixed(1)) + ' KB' : '未知'}</td></tr>`).join('')}
       </tbody></table>`
    : '<p class="fact-empty">未发现 Windows 专用脚本</p>';
  const signals = facts.windows_signals || [];
  const signalList = signals.length
    ? `<div class="tag-list">${signals.map((s) => `<span class="tag">${esc(s.file)} · ${s.hits.length} 处</span>`).join('')}</div>`
    : '<p class="fact-empty">未发现 Windows 环境变量、win32 导入等专属信号</p>';
  cards.push(factCard('Windows 适配', `${winScripts.length} 个脚本`, `${winTable}<div style="margin-top:10px">${signalList}</div>`));

  const paths = facts.paths || {};
  const samples = paths.samples || [];
  const sampleTable = samples.length
    ? `<table class="mini-table fact-scroll"><thead><tr><th>位置</th><th>路径</th></tr></thead><tbody>
        ${samples.map((s) => `<tr><td>${esc(s.file)}${s.line ? ':' + s.line : ''}</td><td>${esc(truncate(s.value, 60))}</td></tr>`).join('')}
       </tbody></table>`
    : '<p class="fact-empty">未发现硬编码绝对路径</p>';
  cards.push(factCard('硬编码路径', `${paths.total || 0} 处 · ${paths.files || 0} 个文件`,
    `<div class="kv" style="margin-bottom:10px">
       <div class="kv-row"><span>个人目录 / 盘符</span><span>${paths.personal || 0} 处</span></div>
       <div class="kv-row"><span>文档示例</span><span>已排除，不计入风险</span></div>
     </div>${sampleTable}`));

  const secrets = facts.secrets || {};
  const envRisks = report.risks.filter((r) => r.rule === 'env_committed');
  const sensitive = report.risks.filter((r) => r.rule === 'sensitive_file');
  cards.push(factCard('密钥与敏感信息', `${secrets.total || 0} 处命中`,
    `<div class="kv">
       <div class="kv-row"><span>严重 / 高 / 中</span><span>${secrets.critical || 0} / ${secrets.high || 0} / ${secrets.medium || 0}</span></div>
       <div class="kv-row"><span>.env 入库</span><span>${envRisks.length ? esc(envRisks.map((r) => r.file).join('、')) : '未发现'}</span></div>
       <div class="kv-row"><span>证书 / 私钥文件</span><span>${sensitive.length ? esc(sensitive.map((r) => r.file).join('、')) : '未发现'}</span></div>
     </div>`));

  cards.push(factCard('工程规范', '仓库卫生',
    `<div class="kv">
       <div class="kv-row"><span>许可证</span><span>${hygiene.license && hygiene.license.exists ? esc(hygiene.license.name || '已声明') : '未发现 LICENSE'}</span></div>
       <div class="kv-row"><span>.gitignore</span><span>${hygiene.gitignore && hygiene.gitignore.exists
         ? (hygiene.gitignore.covers_env ? '已忽略 .env' : '未忽略 .env') : '缺失'}</span></div>
       <div class="kv-row"><span>CI</span><span>${esc((hygiene.ci || []).join('、') || '未发现')}</span></div>
       <div class="kv-row"><span>测试 / 文档目录</span><span>${hygiene.tests ? '有测试' : '无测试'} · ${hygiene.docs_dir ? '有 docs' : '无 docs'}</span></div>
     </div>`));

  const coverage = facts.coverage || {};
  cards.push(factCard('扫描范围', `${fmtNum(coverage.coverage_pct)}%`,
    `<div class="kv">
       <div class="kv-row"><span>文本文件</span><span>${coverage.scanned_files || 0} / ${coverage.tree_files || 0}</span></div>
       <div class="kv-row"><span>子目录</span><span>${esc(report.repo.subdir || '整仓')}</span></div>
       <div class="kv-row"><span>规则版本</span><span>${esc(report.tool.rule_version)}</span></div>
     </div>`));

  $('facts-grid').innerHTML = cards.join('');
}

/* ------------------------------------------------------------------ */
/* AI 建议                                                             */
/* ------------------------------------------------------------------ */

function renderAi(report) {
  const ai = report.ai || {};
  const isLlm = ai.provider === 'llm';
  const suggestions = ai.suggestions || [];
  const head = `
    <div class="ai-head">
      <span class="ai-provider ${isLlm ? '' : 'rules'}">${isLlm ? '大模型增强' : '本地规则引擎'}</span>
      <span class="muted">${esc(ai.model || '')}</span>
      ${isLlm ? '' : '<span class="ai-config-cta">未使用大模型 · <button type="button" id="open-ai-config">配置</button></span>'}
    </div>
    <p class="ai-summary">${esc(ai.summary || '暂无建议')}</p>`;

  const items = suggestions.length
    ? `<div class="ai-suggestions">${suggestions.map((item) => `
        <div class="ai-item">
          <span class="prio ${esc(item.priority || 'P1')}">${esc(item.priority || 'P1')}</span>
          <div class="ai-item-body">
            <div class="ai-item-title">
              <span>${esc(item.title)}</span>
              ${item.expected_gain ? `<span class="ai-gain">预计 ${esc(item.expected_gain)}</span>` : ''}
            </div>
            <p class="ai-item-action">${esc(item.action)}</p>
          </div>
        </div>`).join('')}</div>`
    : '<div class="empty-state">暂无建议。</div>';

  const note = ai.note ? `<p class="ai-note">${esc(ai.note)}</p>` : '';
  $('ai-panel').innerHTML = head + items + note;
  const openBtn = $('open-ai-config');
  if (openBtn) {
    openBtn.addEventListener('click', () => {
      const details = $('ai-config');
      details.open = true;
      details.scrollIntoView({ behavior: 'smooth', block: 'center' });
      $('ai-key').focus();
    });
  }
}

/* ------------------------------------------------------------------ */
/* 导出与口径                                                          */
/* ------------------------------------------------------------------ */

function renderExport(report) {
  const weights = report.dimensions.map((dim) => `
    <tr><td>${esc(dim.label)}</td><td>${dim.max} 分</td><td>${fmtNum(dim.score)}</td></tr>`).join('');
  const warnings = (report.warnings || []).length
    ? `<ul class="note-list">${report.warnings.map((w) => `<li>${esc(w)}</li>`).join('')}</ul>`
    : '<p class="fact-empty">本次扫描没有额外警告。</p>';
  const cache = report.cache || {};
  const cacheInfo = cache.stale
    ? '上游异常，展示最近一次成功报告（stale）'
    : cache.report_hit
      ? '命中报告缓存（同一 commit + 同一规则版本）'
      : `新扫描；blob 缓存命中 ${cache.blob_hits || 0} / 未命中 ${cache.blob_misses || 0}`;

  $('export-body').innerHTML = `
    <div class="fact-card">
      <h3>评分权重<span>总分 100</span></h3>
      <table class="weights">
        <thead><tr><th>维度</th><th>权重</th><th>本次得分</th></tr></thead>
        <tbody>${weights}</tbody>
      </table>
      <p class="muted" style="margin:10px 0 0">
        等级：A ≥ 85 且无严重风险；B ≥ 70；C ≥ 55；D &lt; 55。
      </p>
    </div>
    <div class="fact-card">
      <h3>更新跟踪与缓存<span>设计已落地</span></h3>
      <p class="muted" style="margin:0">
        本报告绑定 <code>${esc(report.repo.full_name)}@${esc(report.commit.short_sha)}</code> 与规则版本
        <code>${esc(report.tool.rule_version)}</code>。“检查更新”只调用一次 commits 接口比较 sha；
        未变化直接复用报告，变化后仅重新扫描 blob sha 发生变化的文件。
        文件内容按 blob sha 缓存，限流/网络失败时回退最近一次成功报告并标记 stale。
      </p>
      <p class="muted" style="margin:8px 0 0">当前缓存状态：${esc(cacheInfo)}</p>
    </div>
    <div class="fact-card">
      <h3>扫描说明与限制<span>${(report.warnings || []).length} 条</span></h3>
      ${warnings}
      <p class="muted" style="margin:10px 0 0">
        静态扫描，不克隆仓库、不执行代码；仅覆盖默认分支（或指定 ref）的前 320 个文本文件；
        二进制、锁文件与超大文件不读取。密钥命中均做脱敏，疑似真实凭据请立即轮换。
      </p>
    </div>
    <div class="fact-card">
      <h3>版本信息<span>${esc(report.tool.name)}</span></h3>
      <div class="kv">
        <div class="kv-row"><span>工具版本</span><span>v${esc(report.tool.version)}</span></div>
        <div class="kv-row"><span>规则版本</span><span>${esc(report.tool.rule_version)}</span></div>
        <div class="kv-row"><span>目标</span><span>${esc(report.target)}</span></div>
        <div class="kv-row"><span>commit</span><span>${esc(report.commit.sha || '—')}</span></div>
        <div class="kv-row"><span>生成时间</span><span>${esc(report.generated_at || '')}</span></div>
      </div>
    </div>`;
}

/* ------------------------------------------------------------------ */
/* 检查更新                                                            */
/* ------------------------------------------------------------------ */

async function checkUpdates() {
  const report = state.report;
  if (!report || report.repo.is_local) {
    toast('本地目录不提供更新检查');
    return;
  }
  const btn = $('check-update');
  const original = btn.textContent;
  btn.disabled = true;
  btn.textContent = '检查中…';
  try {
    const res = await fetch(`/api/head?url=${encodeURIComponent(report.target)}`);
    const data = await res.json().catch(() => null);
    if (!res.ok || !data) {
      throw new Error((data && data.error && data.error.message) || '检查失败');
    }
    if (data.changed) {
      $('update-text').textContent =
        `最新 commit ${data.short_sha}（${truncate(data.message || '', 60)}），当前报告基于 ${report.commit.short_sha}。`;
      $('update-banner').hidden = false;
      $('update-banner').scrollIntoView({ behavior: 'smooth', block: 'center' });
    } else if (data.has_report) {
      $('update-banner').hidden = true;
      toast(`已是最新 commit ${data.short_sha}`);
    } else {
      toast(`当前 head：${data.short_sha}`);
    }
  } catch (err) {
    toast(`检查更新失败：${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = original;
  }
}

/* ------------------------------------------------------------------ */
/* Tabs                                                                */
/* ------------------------------------------------------------------ */

function switchTab(name) {
  document.querySelectorAll('.tab').forEach((tab) => {
    tab.classList.toggle('active', tab.dataset.tab === name);
  });
  ['risks', 'checks', 'facts', 'ai', 'export'].forEach((key) => {
    const panel = $(`panel-${key}`);
    if (panel) panel.hidden = key !== name;
  });
}

init();

// 支持 ?url=<仓库地址> 直达：便于分享报告链接、嵌入自动化截图
const directUrl = new URLSearchParams(location.search).get('url');
if (directUrl) {
  $('repo-url').value = directUrl;
  runAnalyze(directUrl, false);
}
