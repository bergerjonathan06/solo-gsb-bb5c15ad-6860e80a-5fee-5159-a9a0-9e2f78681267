# Unicode 双向文本安全审计 API

基于 **FastAPI + SQLite + Docker** 的服务，检测文本中的 Unicode 双向控制字符（Trojan Source / CVE-2021-42574 类攻击面），按 [UAX #9](https://www.unicode.org/reports/tr9/) 的显式嵌入/隔离配对嵌套规则解析，报告每个控制符的码点、逻辑索引、影响范围与未闭合错误，并对危险区段生成**保持逻辑可读顺序**的转义预览。

> 原始文本永远不会被改写：危险区段同时返回 `raw`（原文逐字保留）与 `escaped_preview`（可读转义形式）。

## 检测的字符

| 码点 | 缩写 | 名称 | 配对方式 |
|---|---|---|---|
| U+200E / U+200F / U+061C | LRM / RLM / ALM | 左右/右左/阿拉伯字母标记 | 无配对（info） |
| U+202A / U+202B | LRE / RLE | 左向/右向嵌入 | PDF 弹出 |
| U+202D / U+202E | LRO / **RLO** | 左向/右向**覆盖** | PDF 弹出 |
| U+202C | PDF | 弹出方向格式 | 匹配最近的 LRE/RLE/LRO/RLO |
| U+2066 / U+2067 / U+2068 | LRI / RLI / FSI | 左向/右向/首强字符隔离 | PDI 弹出 |
| U+2069 | PDI | 弹出隔离 | 匹配最近的 LRI/RLI/FSI |
| U+2061–U+2064 | FSA/ITS/ISS/IPF | 隐形数学运算符 | 无配对（info） |

同时在转义预览中暴露零宽空格（U+200B）、BOM/ZWJ 等不可见格式字符。

## 配对与嵌套规则（UAX #9 X1–X9 子集）

1. LRE/RLE/LRO/RLO 入栈，由最近的 PDF 闭合；LRI/RLI/FSI 入栈，由最近的 PDI 闭合。
2. PDF 会跳过尚未终止的隔离层，向下找到属于自己的嵌入层（X7/X9）。
3. PDI 关闭隔离时，隔离内部**未显式闭合的嵌入层会被隐式终止**并报告错误。
4. 只有 PDF/PDI 而无对应开启符 → 孤立闭合符错误。
5. 文本结束时栈中仍有开启符 → 未闭合错误（未闭合的 RLO/LRO 为 **critical**，因为重排效果延伸到文本结尾）。
6. 显式嵌套深度超过上限（125，BD13 相关）→ critical 错误。

## 风险级别

| 级别 | 含义 |
|---|---|
| `info` | 仅有 LRM/RLM/ALM 等标记或无控制符 |
| `low` | 已正确闭合的 LRE/LRI/FSI 等 |
| `medium` | RLE/RLI、未闭合的隔离/嵌入、孤立 PDF/PDI |
| `high` | 存在 RLO/LRO 方向覆盖（无论是否闭合） |
| `critical` | RLO/LRO **未闭合**，或嵌套深度超限 |

记录的整体风险级别取全部控制符中的最高级别。

## 快速开始

### Docker Compose（推荐）

```bash
docker compose up --build
```

服务在 <http://localhost:8000> 启动，交互式文档：<http://localhost:8000/docs>。
SQLite 数据文件保存在命名卷 `bidi-audit-data`（容器内 `/data/audit.db`）。

### 仅用 Docker

```bash
docker build -t bidi-audit .
docker run -p 8000:8000 -v "$PWD/data:/data" bidi-audit
```

容器启动时会自动执行 schema 初始化（`python -m app.init_db`）。

### 本地运行（无 Docker）

```bash
pip install -r requirements.txt
./run.sh                     # 初始化 DB 并在 8000 端口启动
# 或：
BIDI_DB_PATH=./data/audit.db python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## API

### `POST /api/v1/audits` — 提交审计

请求体：

```json
{
  "text": "‮malware.exe‬",
  "filename": "patch.diff"
}
```

`filename` 可选；`text` 必填，原样存储不做任何改写。

```bash
curl -s -X POST http://localhost:8000/api/v1/audits \
  -H 'Content-Type: application/json' \
  -d '{"text": "x‮evil.exe‬", "filename": "patch.diff"}' | jq
```

响应（节选）：

```json
{
  "id": 1,
  "risk_level": "high",
  "stored": true,
  "result": {
    "length": 12,
    "max_depth": 1,
    "risk_level": "high",
    "error_count": 0,
    "errors": [],
    "controls": [
      {
        "codepoint": "U+202E",
        "abbreviation": "RLO",
        "name": "RIGHT-TO-LEFT OVERRIDE",
        "kind": "override",
        "logical_index": 1,
        "position": {"line": 1, "column": 2},
        "depth_after": 1,
        "scope_end": 10,
        "paired_with": "U+202C",
        "is_orphan": false,
        "risk": "high"
      }
    ],
    "dangerous_spans": [
      {
        "start": 1,
        "end": 10,
        "reason": "RLO override forces visual reordering of enclosed characters",
        "opener": "RLO",
        "risk": "high",
        "raw": "‮evil.exe",
        "escaped_preview": "⟨RLO⟩evil.exe"
      }
    ],
    "stats": {
      "total_control_chars": 2,
      "by_abbreviation": {"RLO": 1, "PDF": 1},
      "unclosed_openers": 0,
      "orphan_closers": 0,
      "dangerous_span_count": 1
    }
  }
}
```

说明：

- `logical_index` 是 Python/Unicode 码点偏移；`position.line/column` 按换行切分（1 起始）。
- `scope_end` 是配对闭合符的逻辑索引（未闭合时等于文本长度）。
- `escaped_preview` 保持**逻辑顺序**，把控制符渲染为 `⟨RLO⟩` 这类可读占位符，零宽字符渲染为 `⟨U+200B⟩`，换行/Tab 渲染为 `\n` / `\t`。

未闭合 RLO 示例（攻击字符串不以 PDF 结尾，重排延伸至文本末尾）：

```bash
curl -s -X POST http://localhost:8000/api/v1/audits \
  -H 'Content-Type: application/json' \
  -d '{"text": "‮end.js", "filename": "x.js"}' | jq '.result.risk_level, .result.errors'
# "critical"
# ["RLO at logical index 0 (line 1, col 1) is never closed by PDF"]
```

### `GET /api/v1/audits` — 查询历史记录

支持按风险级别精确过滤、按文件名（大小写不敏感子串）过滤与分页：

```bash
curl 'http://localhost:8000/api/v1/audits?risk_level=critical&filename=patch&limit=20&offset=0'
```

```json
{
  "total": 1,
  "limit": 20,
  "offset": 0,
  "items": [
    {"id": 7, "created_at": 1737540000.12, "filename": "patch.diff",
     "text_length": 12, "risk_level": "critical", "max_depth": 1,
     "error_count": 1, "control_count": 1}
  ]
}
```

`risk_level` 取值：`info | low | medium | high | critical`。

### `GET /api/v1/audits/{id}` — 单条详情

返回摘要、原始文本 `raw_text` 和完整解析结果 `result`。

### `POST /api/v1/audits/compare` — 两次审计结果回归比较

取两条**已存**记录（`before_id` 为基线、`after_id` 为回归版本），按
**控制符缩写 + 出现次序**配对（如第 2 个 `RLO` 对第 2 个 `RLO`），报告：

- `controls.added` / `controls.removed` — 仅出现在一侧的控制符（带所在侧视图与出现序号）；
- `controls.paired` — 两侧配对到的控制符，逐项给出：
  - `position_changed`：`logical_index` / 行列位置是否变化；
  - `pairing_changed`：配对范围是否变化（`scope_end` 或 `paired_with`）；
  - `risk_changed`、`is_orphan`、`depth_after` 等属性变化（汇总在 `changes` 数组中）；
- `risk_level` — 整体风险级别及方向（`increased` / `decreased` / `unchanged`）；
- `error_count` / `control_count` — 错误数与控制符总数的双侧值、差值 `delta`；
- `before` / `after` — 两条记录的摘要（不含 `raw_text` / 完整结果）；
- `changed` — 任一项（新增、消失、位置、配对、风险、错误数）有差异即为 `true`。

错误：任一 ID 不存在返回 **404**（detail 指明是 `before_id` 还是 `after_id`）；
两个 ID 相同返回 **422**；ID 小于 1 或缺字段同样返回 422。

Docker Compose 启动后（`docker compose up --build`，端口 8000）：

```bash
# 先各提交一次审计拿到 ID，再比较
curl -s -X POST http://localhost:8000/api/v1/audits/compare \
  -H 'Content-Type: application/json' \
  -d '{"before_id": 1, "after_id": 2}' | jq
```

响应示例（基线为未闭合 RLO critical，回归版本补了 PDF 变为 high）：

```json
{
  "before_id": 1,
  "after_id": 2,
  "changed": true,
  "before": {
    "id": 1, "created_at": 1790118540.29, "filename": "v1",
    "text_length": 4, "risk_level": "critical", "max_depth": 1,
    "error_count": 1, "control_count": 1
  },
  "after": {
    "id": 2, "created_at": 1790118540.30, "filename": "v2",
    "text_length": 7, "risk_level": "high", "max_depth": 1,
    "error_count": 0, "control_count": 2
  },
  "risk_level": {"before": "critical", "after": "high",
                 "direction": "decreased", "changed": true},
  "error_count": {"before": 1, "after": 0, "delta": -1, "changed": true},
  "control_count": {"before": 1, "after": 2, "delta": 1, "changed": true},
  "controls": {
    "added": [
      {"abbreviation": "PDF", "occurrence": 1,
       "after": {"codepoint": "U+202C", "logical_index": 5,
                 "scope_end": null, "paired_with": "U+202E",
                 "is_orphan": false, "risk": "high"}}
    ],
    "removed": [],
    "paired": [
      {"abbreviation": "RLO", "occurrence": 1,
       "before": {"logical_index": 0, "scope_end": 4,
                  "paired_with": null, "is_orphan": true, "risk": "critical"},
       "after":  {"logical_index": 1, "scope_end": 5,
                  "paired_with": "U+202C", "is_orphan": false, "risk": "high"},
       "changes": ["position", "pairing", "orphan", "risk"],
       "position_changed": true,
       "pairing_changed": true,
       "risk_changed": true}
    ]
  }
}
```

两条记录完全等价时（位置、配对、风险、错误数均一致）`changed` 为 `false`，
`controls.paired[*].changes` 为空数组。

### 其他

- `GET /health` — 健康检查（容器 HEALTHCHECK 使用）
- `GET /docs` / `/openapi.json` — Swagger UI 与 OpenAPI 模式

## 项目结构

```
.
├── app/
│   ├── __init__.py
│   ├── bidi.py        # UAX#9 控制符解析、配对栈、风险评级、转义预览
│   ├── compare.py     # 两条审计记录的回归比较（缩写+出现次序配对）
│   ├── database.py    # SQLite schema / CRUD / 查询
│   ├── schemas.py     # Pydantic 请求模型
│   ├── main.py        # FastAPI 路由
│   └── init_db.py     # 独立初始化入口（容器启动调用）
├── tests/
│   ├── test_bidi.py   # 解析器单元测试 + API 冒烟测试
│   └── test_compare.py # /audits/compare 端点测试（配对/404/422）
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── run.sh             # 本地启动脚本
└── README.md
```

## 测试

```bash
pip install pytest httpx
python -m pytest tests/ -q
```

覆盖：清洁文本、RLO 高风险、未闭合 RLO critical、LRE/PDF 配对、孤立 PDF/PDI、
LRI/PDI 隔离配对、隔离内嵌入隐式关闭、PDF 跳过隔离层（X9）、行列定位、
嵌套深度、转义预览，以及 API 的创建/详情/过滤/404；
另含 `/audits/compare` 的新增/消失/出现次序配对、位置与配对范围变化、
风险级别与错误数比较、双侧摘要与 `changed`，以及 404（记录不存在）和
422（两 ID 相同、参数非法）用例。

## 设计说明

- 审计只做**检测与呈现**，绝不返回"净化后"的文本，避免调用方误以为原文可安全渲染；
  需要人工复核时使用 `escaped_preview`。
- 控制符使用显式 Unicode 占位符（`⟨RLO⟩`）而非 `‮` 转义，使预览在终端/日志中一眼可见。
- SQLite 通过 WAL 友好的单文件方式持久化，位置由环境变量 `BIDI_DB_PATH` 控制。
