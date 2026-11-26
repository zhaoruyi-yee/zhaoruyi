# AI 使用说明（AI_USAGE）

题目要求：说明用了哪些 AI 工具、如何验证其输出，并至少包含 1 条「AI 答错但被我发现了」的记录。
本文件全部记录来自本次开发过程，不是事后编的模板。

## 1. 用了哪些 AI 工具

| 环节 | 工具 | 用途 |
| --- | --- | --- |
| 方案与脚手架 | Trae IDE 内置 AI Agent（Vibe Coding） | 生成项目骨架、数据获取层、规则引擎、评分模型、前端页面 |
| 规则与正则 | 同上 | 起草密钥/路径/Windows 检测正则，再由我用真实仓库逐条校验 |
| 前端可视化 | 同上 | 评分环 SVG、维度条、风险表、筛选与导出逻辑 |
| 文档 | 同上 | README / AI_USAGE 初稿，我补充实测数据与设计细节 |
| 产品内置 AI 建议 | 任意 OpenAI 兼容接口（可选配置） | 基于报告的结构化摘要生成接入建议；未配置或调用失败时回退内置规则引擎 |

AI 参与的是「写代码」和「写文案」，**验收标准由我定**：每一条规则、每一个结论都要能在真实仓库上复现，否则不采纳。

## 2. 这类 AI 使用方式的关键提示词

- 「用 Python 标准库实现一个 Web 分析工具：输入 GitHub 仓库链接，通过 REST API 拿 commit 和 recursive tree，
  文件正文走 CDN，不要 clone；输出五维评分 + 风险清单 + Markdown 导出。」
- 「检测规则要区分文档与代码：文档里的示例路径、示例密钥不能算风险，但要能提示。
  先列误报场景，再写正则。」
- 「写 10 个不联网的单元测试，覆盖文档/依赖/密钥/.env/Windows 脚本/路径误报防护/Markdown/更新检查/LLM 集成与回退。」
- 「前端不要用 CDN，单页原生 JS；评分环用 SVG，风险表支持按严重程度筛选和关键字搜索。」

## 3. 如何验证 AI 输出

| 验证手段 | 具体做法 | 结果 |
| --- | --- | --- |
| 离线单元测试 | `python -m unittest discover -s tests -v`，10 项覆盖规则、评分、缓存兜底、LLM 回退 | 全部通过 |
| 真实小仓库 | `octocat/Hello-World`（1 个文件） | 3.3s 出报告，链路通 |
| 真实中型仓库 | `pallets/flask`（236 个文件） | 32s 出报告，覆盖 219 个文本文件 |
| 逐条人工复核 | 把报告里每条风险的文件/行号拉出来，对照上游源码原文 | 发现并修掉 4 类误报（见下） |
| 脱敏校验 | 断言报告文本中不出现完整密钥字符串 | 通过（`token[:4]…token[-3:]`） |
| 兜底演练 | 把 GitHub API 配额打满后再次分析 | 正确回退到最近成功报告并标注 `stale` |
| LLM 输出校验 | Mock 一个 `/chat/completions` 服务返回固定 JSON，断言解析成功；再把 base_url 指向关闭的端口 | 成功解析；失败时自动回退规则建议并标注「回退」 |

补充说明：产品内调用 LLM 时只传**结构化摘要**（评分、维度、风险标题、事实摘要），不传仓库原文，
既控制 token，也降低「仓库内容里藏提示词」的注入风险。

## 4. AI 答错但被我发现的记录

### 记录 1：把 SQL 的 WHERE 当成 Windows 命令（严重误报）

- AI 生成的 Windows 信号规则：`where\s+[A-Za-z]|copy\s+\S+\s+\S+`，理由是「Windows 有 where / copy 命令」。
- 现象：`pallets/flask` 报告里出现 11 处「Windows 专属用法：WHERE i」，全部来自 SQLAlchemy 查询语句。
- 怎么发现的：报告 medium 风险数异常偏高（27 条），我把每条的文件和行号打印出来对照源码，发现命中的是 SQL。
- 修正：`where` / `copy` 属于极常见英文单词与 SQL 关键字，不能作为弱信号；改为仅匹配**行首**的 `setx` / `chcp`，
  Windows 信号改为「文件级」判定（`%APPDATA%`、win32 导入、`C:\Windows\System32` 等）。
- 验证：同一份 Flask 快照复测，`WHERE` 类误报归零。

### 记录 2：通用口令正则把表达式当成了硬编码密钥

- AI 生成的规则的意图是抓 `password = "xxx"`，实际正则会把赋值右侧的**表达式**也吃进去。
- 现象：`request.form["password"]`、`self.secret_key`、`t.Optional[...]` 等 12 处被判为「疑似口令赋值」，
  另外 `docs/config.rst` 里的示例 `SECRET_KEY = '192b9b...'` 也被当成真密钥。
- 怎么发现的：以 `docs/config.rst`、`examples/tutorial/flaskr/auth.py` 的命中行对照原文，发现右侧全是代码而不是字面量。
- 修正：赋值右侧以 `(` `[` `{` 开头、token 内含括号、token 是点号标识符时直接跳过；
  文档中的通用示例降级为「低」。
- 验证：修复后 Flask 快照的 `generic_secret` 命中从 12 降到 0，而测试夹具里真实的
  `const password = "averylongsecretvalue123"` 仍然能被检出（单元测试覆盖）。

### 记录 3：抓文件的网络方案连错两次

- 第一次 AI 建议 `raw.githubusercontent.com`：实测 20s 超时，Flask 分析 240s 都没跑完，blob 缓存一个都没写入。
- 第二次 AI 建议改用 `cdn.jsdelivr.net`：实测本机 DNS 解析失败（`getaddrinfo failed`），又回退到 raw，依旧慢。
- 怎么发现的：写了个计时脚本分别计时各阶段，看到 `README: 网络请求失败：timed out` 与 DNS 报错。
- 修正：改为 `fastly.jsdelivr.net` / `gcore.jsdelivr.net` 优先（实测 0.5~0.7s/文件），raw 仅作最后回退。
- 验证：Flask 从「超时失败」变为 32s 完成，`octocat/Hello-World` 3.3s 完成。
- 同类问题还有一次：GitLab 的 `/-/raw/<完整sha>/` 在本机返回 403（Cloudflare「Just a moment...」挑战页），
  同一地址换成短 sha 或 API 的 `files/<path>/raw?ref=` 就正常。修复为优先走 API raw 接口、失败再回退网页 raw。
  验证：`gitlab-examples/python-getting-started` 从「0 个文件、覆盖率 0%」变为 22/24 文件、覆盖率 91.7%。

### 记录 4：把 docs/Makefile 的 help 目标当成启动方式

- AI 的启动检测逻辑是「找到任意 Makefile，取第一个目标即为启动方式」。
- 现象：Flask 报告显示启动方式为 `make getting` / `make help`——前者其实是 README 里
  “make getting started quick and easy” 这句散文，后者是文档构建目标。
- 怎么发现的：报告「启动与运行」维度给了不合常理的分，回查 `readme_command` 与 `make_targets` 字段发现是这两处。
- 修正：README 命令中的 `make` 只认 run/dev/start/serve/up/preview/app；
  Makefile 优先根目录，且只把启动型目标算作启动方式。
- 验证：同一快照复测，`readme_command` 变为正确的 `flask run`，`make_targets` 为空。

## 5. 我保留的 AI 输出边界

- 评分权重（文档 20 / 依赖 20 / 启动 15 / 可移植 20 / 安全 25）是我按「接入风险优先级」定的，
  没有让 AI 自由发挥；AI 只负责按权重实现计算与展示。
- AI 生成的每条「整改建议」都必须能对应到报告里的具体事实（维度 gap 或风险），不做无依据的泛泛而谈。
- 报告里的每一条风险都带文件路径与行号，便于人工复核——AI 的判断可以错，但必须可核对。
