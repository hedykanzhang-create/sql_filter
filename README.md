# sql_filter

用 OpenRouter 的 **Jev**（`~typesafe/jev-latest`）决策模型做 SQL 过滤器。

Jev 不生成文本：你给它一段 `state` 和一组带类型的问题，它只回答
**是/否的概率**（noul）、**从你给的选项里挑一个**（choice）、
**在有序标尺上定位**（score）。判决逻辑留在你自己的代码里 —— 这正好适合做过滤器。

## 目标

**在 SQL 抵达数据库之前，拦下会造成实际损害的语句，同时不误伤正常业务，并且不让敏感数据离开本机。**

三个分句缺一不可：少了第二句，一个动辄误杀的过滤器会被运维关掉，而被关掉的过滤器防护力为零；
少了第三句，就成了「为查漏而泄密」——把 SQL 原文连同里面的卡号、密钥一起发给了第三方。

## 核心指标

不看「总体准确率」。那个数能靠语料里攻击占比刷出来（全拦即高分），
还把两种不对称的错误混为一谈：漏一条 `SELECT password FROM users`（泄露，不可逆）
和误拦一条报表查询（人工放行即可，可逆），在准确率里权重一样，这是荒谬的。

### 🎯 首要指标：危险攻击漏杀率 = **0.00%**

分母不是「所有攻击」，是**能造成实际损害的攻击**，按损害类型分层
（分层而不给总数，因为各层代价不同——漏一条命令执行 ≠ 漏一条延时）：

| 损害类型 | 样本 | 拦下 | 放行 | 漏杀率 |
|:--|--:|--:|--:|--:|
| 拖凭据 / PII | 184 | 184 | 0 | 0.00% |
| 报错回显外带 | 85 | 85 | 0 | 0.00% |
| 翻库结构 | 49 | 49 | 0 | 0.00% |
| 数据破坏（DROP / 无界删改） | 40 | 40 | 0 | 0.00% |
| 命令执行 | 16 | 16 | 0 | 0.00% |
| 文件读写（WebShell 落地） | 8 | 8 | 0 | 0.00% |
| 提权 / 后门 | 3 | 3 | 0 | 0.00% |
| 拒绝服务（延时） | 156 | 156 | 0 | 0.00% |
| **合计** | **541** | **541** | **0** | **0.00%** |

> 统计口径为三份语料（生成 1000 + 真实载荷 1500 + 现代攻击面 21）中被判定为攻击、
> 且具备实际破坏能力的语句。**目标值 0%，不容妥协。**

### ⛓ 硬约束：正常业务误杀率 = **0.00%**（一票否决）

这不是「第二重要」，是准入条件：误杀率超标 → 这版不许上线，哪怕漏杀率是 0。
上限 **≤ 0.5%**，当前 633 条正常语句 0 被拒、0 转复核。

> ⚠️ **此数字的可信度有限**：量误杀用的正常语句 94% 是生成器合成的，**0 条来自真实生产流量**。
> 合成语句的多样性必然低于真实业务（动态 `IN (...)`、ORM 巨型 JOIN、`WITH` 递归、JSON 函数等均未覆盖），
> 所以「误杀率 0%」目前**仅代表合成流量，不足以代表生产表现**。补一份脱敏后的真实慢查询日志是最高优先项。

### 辅助观测（不设目标，只看趋势）

| 指标 | 当前 | 意义 |
|:--|--:|:--|
| 噪音率（正常语句转复核） | 0.00% | 运维负担 |
| 本地拦截率 | ~21% | 这部分不外发、不花钱 |
| 单条成本 | $0.000035 | 走模型的部分 |
| 敏感数据外发 | 0 | 卡号 / 身份证 / 私钥 / 密钥本地拦死 |

## 能力边界

只写指标不写边界是误导。这三条必须清楚：

1. **它不是参数化查询的替代品。** 真正防注入靠 prepared statement，本工具是纵深防御的一层，不是唯一一道。
2. **它无状态，看不见会话。** 逐条判断，抓不住「用安全语句逐步试探」这类跨请求的攻击模式（见评测里的漏杀分析）；
   二阶注入（存入时干净、取出时才触发）同理，结构上就测不了。
3. **它不看 HTTP 层，不是 WAF 替代品。** 只认最终打到数据库的 SQL。

## 闸口结构

**串联短路**：任一闸口命中即出结果，后面的不再跑。所以 20% 的语句根本不会走到模型。

```
SQL
 │
 ├─ 第零级：敏感字面量 · 6 道闸口 · 命中即 BLOCK · **绝不外发**
 │    ① card_number_literal    银行卡号（发卡行前缀 + Luhn + 列名上下文三重确认）
 │    ② id_card_literal        身份证号（长度 + GB 11643 校验位）
 │    ③ plaintext_credential   口令/密钥与明文字面量比较（与哈希比对放行）
 │    ④ vendor_key_literal     sk- / ghp_ / xox?- / AKIA / AIza / glpat- 等密钥前缀
 │    ⑤ jwt_literal            JWT 三段式令牌
 │    ⑥ private_key_literal    PEM 私钥块
 │    ⑦ schema_column_hunt     按敏感列名模糊搜库结构（按表名查放行）
 │
 ├─ 第一级：本地正则 · 9 道闸口 · 命中即 BLOCK · 不花钱不联网
 │    ① stacked_query          分号拼接多条语句（堆叠注入）
 │    ② comment_truncation     引号紧贴注释，截断后半段校验
 │    ③ version_comment        /*!...*/ MySQL 版本注释（内容会真执行）
 │    ④ comment_as_whitespace  注释切开关键字 UN/**/ION
 │    ⑤ file_access            LOAD_FILE / INTO OUTFILE / INTO DUMPFILE
 │    ⑥ shell_exec             xp_cmdshell / COPY TO PROGRAM / pg_read_file
 │    ⑦ tautology              恒真条件 OR 1=1 / OR 'a'='a'
 │    ⑧ write_in_readonly      只读模式下的写操作（仅 -readonly 生效）
 │    ⑨ unbounded_destructive  没有 WHERE 的 DELETE / UPDATE
 │
 ├─ 脱敏：邮箱 / 手机号替换成占位符，**然后才**发出
 │
 └─ 第二级：Jev 语义判断 · 1 次 API 调用同时问 6 个维度 · 再按优先级串联裁决
      ① 注入   ≥0.50 → BLOCK
      ② 拖库   ≥0.50 → BLOCK
      ③ 只读   <0.50 → BLOCK（仅 -readonly 生效）
      ④ 探测   ≥0.60 → REVIEW
      ⑤ 风险   ≥1.50 → REVIEW
      ⑥ 注入   ≥0.20 → REVIEW
                 否则 → ALLOW
```

### 第零级为什么必须排在最前

它和其他闸口解决的不是同一类问题：**其他规则判「这条语句该不该执行」，
它判「这条语句能不能离开本机」。**

过滤器会把 SQL 原文发给第三方 API 做语义判断。如果语句里带着明文卡号、私钥、
token，那这次调用本身就是一次数据外泄 —— 为了检查有没有人拖库，反而亲手把数据送了出去。
所以这一级必须跑在任何网络调用之前，漏过去再拦就晚了。

分两档处理，不能一刀切：

| 档 | 内容 | 处理 | 为什么 |
|:--|:--|:--|:--|
| 高危字面量 | 卡号 / 身份证 / 私钥 / JWT / 云密钥 / 明文口令 | **本地 BLOCK** | 值本身就是机密，外发即泄露 |
| 中危 PII | 邮箱 / 手机号 | **脱敏后再发** | 按邮箱查单个用户是正常业务（实测语料里有 17 条），一律拦会干掉正常功能；而模型判的是语句结构，不需要真实值 |

**卡号识别踩过的坑**：只用 Luhn + 发卡行前缀会误伤 —— 实测
`WHERE order_no = '4532015112830366'` 被当成卡号拦了，因为订单号恰好 4 开头且 Luhn 通过。
所以还要看数字左边挨着的列名：`order/trade/trace/invoice/serial` 这类流水号列放行，
`card/pan/credit/acct` 这类或看不出上下文的一律拦。

两级的分工：**本地规则认语法特征**（这段字符串长得像攻击），
**Jev 认意图**（这条语句想干什么）。前者快且零成本但认死理，后者慢一点但能理解
「整表拖凭据」这种语法上毫无破绽的攻击。

六个维度是**一次调用并行问出来的**，不是问六次 —— 单条判定仍然只花 $0.00003。
裁决分支才是串联的，顺序即优先级：拒绝类先判，复核类后判。

## 用法

```bash
export OPENROUTER_API_KEY=sk-or-v1-...

go build -o sql_filter .

./sql_filter "SELECT id FROM users WHERE id = 1"
./sql_filter -readonly "UPDATE users SET role = 'admin'"
./sql_filter -json "SELECT * FROM users WHERE name = '' OR 1=1"

# 批量：每行一条
cat queries.sql | ./sql_filter -readonly

# 不想花钱/没网，只跑本地规则
./sql_filter -offline "SELECT 1; DROP TABLE users"
```

### 参数

| 参数 | 默认 | 说明 |
|:--|:--|:--|
| `-readonly` | false | 只读模式，任何写入/结构变更都拒绝 |
| `-offline` | false | 只跑本地规则，不调用 Jev |
| `-json` | false | JSON 输出，便于接入流水线 |
| `-block-at` | 0.5 | 注入概率达到此值即 BLOCK |
| `-review-at` | 0.2 | 注入概率达到此值转 REVIEW |
| `-probe-at` | 0.6 | 探测概率达到此值转 REVIEW |
| `-model` | `~typesafe/jev-latest` | 模型 slug |
| `-timeout` | 30s | 单条语句判定超时 |
| `-debug` | false | 把 Jev 原始响应打到 stderr |

### 退出码

`0` 全部放行 · `1` 存在需复核 · `2` 存在拒绝或判定失败 —— 可直接当 CI 门禁用。

## 六个判定维度

一条 SQL 会被同时问六个互不重叠的问题，任一命中即拦：

| 维度 | 类型 | 拦截线 | 为什么需要它 |
|:--|:--|:--|:--|
| `is_injection` | noul | ≥0.5 BLOCK | 注入攻击特征 |
| `is_bulk_exfil` | noul | ≥0.5 BLOCK | **整表拖凭据不是注入** —— 语法干净，注入的尺子量不出来 |
| `is_probe` | noul | ≥0.6 REVIEW | 攻击前的侦察（探版本/编码/延时） |
| `is_read_only` | noul | 只读模式下 <0.5 BLOCK | 写操作识别 |
| `category` | choice | — | read / write / schema / admin |
| `risk` | score | ≥1.5 REVIEW | 生产库上的影响面 |

后两个维度（拖库、探测）是**评测逼出来的**，不是设计时想到的：
只问「是不是注入」时，`SELECT api_key, secret FROM shops` 拿到注入概率 0.02、判 ALLOW。
它确实不是注入，是越权读取 —— 尺子上没有的刻度，量多少遍都量不出来。

## 代码结构

```
main.go                     CLI：读输入、渲染、退出码
internal/jev/client.go      Decisions API 客户端（请求构造 + 发送）
internal/jev/parse.go       响应解析 + 带 error 的取值方法
internal/filter/rules.go    本地静态规则（第一级 9 道闸口）
internal/filter/sensitive.go 敏感字面量拦截 + 脱敏（第零级）
internal/filter/filter.go   六道题定义 + 判决逻辑
internal/corpus/corpus.go   带标注的语料生成器
internal/corpus/csv.go      语料 CSV 读写
cmd/gencases/               生成均衡语料 → generated/cases.csv
cmd/realworld/             拉取真实载荷合成 → generated/realworld-1500.csv
cmd/bench/                  读语料跑评测 → 报表 + results/*.csv
testdata/curated/          手工维护的语料源（改这里）
testdata/generated/        程序生成的语料（可复现，勿手改）
testdata/results/          评测输出（可删可再生，已 gitignore）
```

> `testdata/` 各文件的职责见 [testdata/README.md](testdata/README.md)。

### 响应结构（已实测确认）

`2026-09-20` 对 `typesafe/jev-1.13-20260917` 实测到的真实响应：

```json
{
  "model": "typesafe/jev-1.13-20260917",
  "answers": {
    "is_injection": {"type": "noul", "noul": 0.97},
    "category": {"type": "choice", "choice": "read",
                 "probabilities": {"read": 1, "write": 0, "schema": 0, "admin": 0},
                 "confidence": 1},
    "risk": {"type": "score", "score": 0.24,
             "legend": {"0": "...", "1": "...", "2": "..."},
             "probabilities": {"0": 0.87, "1": 0.01, "2": 0.12},
             "confidence": 0.64}
  },
  "usage": {"input_tokens": 719, "output_tokens": 96, "cost": 0.000030198},
  "id": "gen-dec-...", "provider": "TypeSafe"
}
```

两个容易踩的点：

1. **noul 的概率字段叫 `noul`**，不叫 `probability`。
2. **`score` 是浮点数，不是档位下标**。它等于各档概率的加权平均
   （上例 `0×0.87 + 1×0.01 + 2×0.12 = 0.25 ≈ 0.24`），取值范围 `[0, 档位数-1]`。
   取文案要四舍五入到最近档位，用 `Answer.Label()`。
   判高风险用连续值比阈值（`highRiskScore = 1.5`），别拿它当数组下标。

这份响应被原样存进 `internal/jev/parse_test.go` 当黄金样本 —— 字段名再变会当场测试失败。

### 为什么解析层拒绝「猜字段名」

第一版解析层对字段名做了多形状兼容（试 `probability` / `p` / `true`…）。
结果真实字段是 `noul`，全部猜空 → **`is_injection` 的 0.97 被静默解析成 0**
→ `UNION SELECT password FROM admins` 判成 `ALLOW`。

教训有两条，都已固化进代码：

- **取不到答案就报错，绝不用零值兜底。** 注入概率的零值含义是「绝对安全」，
  恰好是最危险的方向。取值一律走 `resp.Noul(name)` 这类带 `error` 的方法。
- **输出字段不加 `omitempty`。** 概率 0 必须显式出现在 JSON 里；
  字段直接消失会让「没答上」看起来像「答了 0」。

排查同类问题用 `-debug`，它把原始响应打到 stderr：

```bash
./sql_filter -debug -json "SELECT 1" 2>&1 | head -5
```

## 评测

三份语料，都是 CSV 驱动：

```bash
# 生成 1000 条带标注语料
go run ./cmd/gencases -n 1000 -o testdata/generated/cases.csv

# 跑评测（需要 OPENROUTER_API_KEY）
go run ./cmd/bench -i testdata/generated/cases.csv -o testdata/results/cases.results.csv -c 20

# 从公开载荷库拉真实 payload + 现代攻击面，合成 1500 条真实语料
go run ./cmd/realworld -n 1500 -o testdata/generated/realworld-1500.csv
go run ./cmd/bench -i testdata/generated/realworld-1500.csv -o testdata/results/realworld-1500.results.csv -c 20

# 只跑本地规则，不花钱
go run ./cmd/bench -offline -i testdata/generated/cases.csv
```

| 语料 | 来源 | 用途 |
|:--|:--|:--|
| `cases.csv` | 生成器，1000 条均衡分布 | 量**误杀**和噪音（正常流量下的表现） |
| `realworld.csv` | 手工整理 79 条 | 量对经典手法的覆盖，含「长得像攻击的合法 SQL」 |
| `modern-2026.csv` | 手工整理 21 条 | 量 **2026 新攻击面**：JSON-based SQLi、ORM 注入、GraphQL 下游、方言载荷 |
| `realworld-1500.csv` | **893 条真实载荷** + 79 手工 + 21 现代 + 507 正常 | 量**漏杀**（真实攻击面下的表现） |

`realworld-1500.csv` 由 `cmd/realworld` 从下列**权威来源**拉取后合成，**可复现**：

| 来源 | 内容 |
|:--|:--|
| [sqlmap 源仓库](https://github.com/sqlmapproject/sqlmap/tree/master/data/xml/payloads) | 攻击工具本体的 `payloads/*.xml`（一手载荷，带方言/风险元数据） |
| [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/Databases/SQLi) | sqlmap / fuzzdb 载荷的风险分级快照 |
| [Xyntax/waf-bypass](https://github.com/Xyntax/waf-bypass) | WAF 绕过专用载荷 |

#### 关于 sqlmap 源仓库

`cmd/realworld` 直接解析 sqlmap 的 6 个载荷 XML，只取每个 `<test>` 的 `<request><payload>`
（真正拼进参数位的那段），忽略 `<vector>`（带占位符的模板）和 `<grep>`（响应匹配规则）：

| XML 文件 | 抽取的 payload |
|:--|--:|
| `error_based.xml` | 120 |
| `time_blind.xml` | 118 |
| `boolean_blind.xml` | 74 |
| `stacked_queries.xml` | 38 |
| `inline_query.xml` | 8 |
| `union_query.xml` | **0**（见下） |
| **去重后唯一载荷** | **284**，其中 **283 条进入最终语料**（1 条与 SecLists 完全重复被去重） |

两个必须说清的点：

- **`union_query.xml` 抽出 0 条不是 bug，是 sqlmap 的设计。** 它的 `<payload/>` 标签是空的 ——
  UNION 语句要靠运行时按「探测到的列数」从 `<vector>` 动态拼，静态 XML 里没有成品。
  这个缺口由 SecLists 的 `sl_union` 与手工 `union_based` 补足，语料现含 **126 条 UNION 攻击语句**，该家族零漏杀。
- **sqlmap 源仓库与 SecLists 高度重叠**（SecLists 本就是 sqlmap 的快照），所以接一手源仓库
  不是为了「数量暴增」（去重后仅净增约 47 条），而是为了**载荷跟随 sqlmap 主线更新**、拿到方言与风险等级元数据。

真正 SecLists 给不了的新东西在 `modern-2026.csv` —— JSON-based SQLi 这类 2026 新手法。
**实测这些新手法零漏杀**（语义层能理解 JSON / ORM 语法的意图，而签名式 WAF 会被绕过）。

载荷库给的是「插进参数位的那段字符串」而不是完整语句，所以流水线要做两件事：

1. **替换占位符** —— `[RANDNUM]`、`[SLEEPTIME]`、`[QUERY]`（sqlmap XML 的子查询占位符）、`__TIME__`
   这些跑的时候才填值，不替换的话方括号原样进 SQL，判的就是一串乱码而非攻击
2. **还原注入上下文** —— 按片段起始形态判断它被插进了哪种参数位：

   | 片段形态 | 还原成 |
   |:--|:--|
   | `' or 1=1--` | `SELECT id, name FROM users WHERE name = '' or 1=1--` |
   | `) or ('a'='a` | `SELECT * FROM users WHERE (name = 'x') or ('a'='a` |

载荷库给的是「插进参数位的那段字符串」而不是完整语句，所以流水线要做两件事：

1. **替换 sqlmap 占位符** —— `[RANDNUM]`、`[SLEEPTIME]`、`[RANDSTR]`、`__TIME__`
   这些跑的时候才填值，不替换的话方括号原样进 SQL，判的就是一串乱码而非攻击
2. **还原注入上下文** —— 按片段起始形态判断它被插进了哪种参数位：

   | 片段形态 | 还原成 |
   |:--|:--|
   | `' or 1=1--` | `SELECT id, name FROM users WHERE name = '' or 1=1--` |
   | `) or ('a'='a` | `SELECT * FROM users WHERE (name = 'x') or ('a'='a` |
   | `1 AND SLEEP(5)` | `SELECT * FROM users WHERE id = 1 AND SLEEP(5)` |
   | `UNION SELECT ...` | `SELECT * FROM users WHERE id = 1 UNION SELECT ...` |

`testdata/curated/realworld.csv` 是从
[OWASP WAF 绕过](https://community.owasp.org/attacks/SQL_Injection_Bypassing_WAF)、
[Xyntax/waf-bypass](https://github.com/Xyntax/waf-bypass/blob/master/payload/sql.txt)、
[Invicti SQLi Cheat Sheet](https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet)
整理的真实 payload，手工标注。两份都可以直接用表格软件打开编辑、补充自己场景的语句。

### 评测口径

每条语料标一个 `class`，跑完与判决对账：

| class | 期望 | 判错叫什么 |
|:--|:--|:--|
| `safe` | ALLOW | BLOCK = **误杀**，REVIEW = 噪音 |
| `risky` | 不放行 | ALLOW = **漏杀** |
| `hostile` | 不放行 | ALLOW = **漏杀** |

`hostile` 被判 REVIEW 算通过 —— 复核意味着有人会看一眼，攻击不会直接打到库上。

### 结果

| 语料 | 条数 | 判对 | 漏杀 | **误杀** | 噪音 | 耗时 | 花费 |
|:--|--:|--:|--:|--:|--:|--:|--:|
| 生成语料 | 1000 | **99.9%** | 1 | **0** | 0 | 28s | $0.036 |
| 真实载荷 | 1000 | **99.1%** | 9 | **0** | 0 | 24s | $0.034 |
| 手工案例 | 79 | **96.2%** | 3 | **0** | 0 | 3s | $0.003 |

真实载荷语料里 905 条攻击语句 —— 覆盖 sqlmap 全部风险等级的报错注入、布尔盲注、
时间盲注、堆叠查询、内联查询，加上 Oracle / MSSQL / MySQL 各自的专用手法、
认证绕过、本地文件读取、系统枚举、WAF 关键字拆分与编码绕过 —— 漏 9 条。

分家族全部命中的有：`sl_union`(87)、`sl_error_based`(84)、`sl_time_blind`(146)、
`sl_boolean_blind`(65)、`sl_oracle`(54)、`sl_auth_bypass`(52)、`sl_mssql`(16)、
`sl_file_enum`(12)、`sl_stacked`(4) —— **零漏杀**。

### 两层各扛多少：屏蔽 Jev 只跑正则

`-offline` 屏蔽掉 Jev，只留第零级 + 第一级正则，就能量出「正则单独能守住多少」。
这回答了一个常见质疑：既然有了语义模型，本地正则是不是多余？

**整体漏杀率（只正则 vs 含 Jev）：**

| 语料 | 只正则漏杀 | 含 Jev 漏杀 |
|:--|--:|--:|
| 生成语料 1000 | 46.3% | 0.1% |
| 真实载荷 1500 | 58.9% | 0.4% |
| 现代攻击 21 | 42.9% | 0% |

**按损害类型分层（541 条有破坏力的攻击，只跑正则）：**

| 损害类型 | 样本 | 正则拦下 | 正则漏杀率 | 含 Jev |
|:--|--:|--:|--:|--:|
| 数据破坏（DROP / 无界删改） | 40 | 40 | **0.0%** | 0% |
| 文件读写（WebShell 落地） | 8 | 8 | **0.0%** | 0% |
| 命令执行 | 16 | 15 | 6.2% | 0% |
| 翻库结构 | 49 | 17 | 65.3% | 0% |
| 提权 / 后门 | 3 | 1 | 66.7% | 0% |
| 拒绝服务（延时） | 156 | 25 | 84.0% | 0% |
| 拖凭据 / PII | 184 | 2 | **98.9%** | 0% |
| 报错回显外带 | 85 | 0 | **100%** | 0% |
| **合计** | 541 | 108 | **80.0%** | **0%** |

结论——**两层互补，谁也替不了谁**：

- **正则守得住有固定语法特征的攻击**：`DROP` / `INTO OUTFILE` 就那几个关键字，
  数据破坏、文件读写它 100% 拦，且零成本、不外发。
- **正则守不住语法干净、要靠理解意图的攻击**：`SELECT password FROM users`
  和 `SELECT name FROM users` 语法上毫无区别，`extractvalue(...)` 看着就是个正常函数调用，
  `SELECT SLEEP(5)` 是条合法语句 —— 所以拖凭据 98.9% 漏、报错外带 100% 漏、延时 84% 漏。

正则单独扛，541 条危险攻击漏掉 433 条（80%），且**最危险的直接拖数据那两类几乎全漏**；
Jev 把这 80% 补到 0。反过来，正则零成本拦下的 108 条省掉了对应的模型调用 ——
这就是「本地拦截率 ~21%」那部分的来源。**两层不是冗余，是分工。**

### 剩下 9 条漏杀是什么

```
SELECT * FROM members WHERE id = 5-1                       注入 0.06  探测 0.39
SELECT IF(1=1, 'true', 'false')                            注入 0.09  探测 0.40
SELECT id, name FROM members WHERE name = ''               注入 0.05  探测 0.35
SELECT * FROM orders WHERE id = 1 select                   注入 0.18  探测 0.27
SELECT id, username FROM sessions WHERE username = ''-'    注入 0.13  探测 0.52
SET GLOBAL foreign_key_checks = 1                          注入 0.02  探测 0.15
```

两类，都不是阈值调得出来的：

**① 模糊探测片段**（6 条）。单引号探测、截断的载荷 —— 攻击者用它们试探
「这个参数会不会报错」，拼出来就是一条平平无奇甚至语法不全的语句。
**探测的本质是一连串请求的模式，不是单条语句的特征**，一次只看一条 SQL
的过滤器先天判不准，模型给 0.27~0.52 是诚实的。要覆盖它得在调用方按会话聚合
（同一来源短时间内大量低分探测语句）。

**② 方向性缺口**（`SET GLOBAL foreign_key_checks = 1`）。这条语句本身无害
（把外键校验**打开**），危险的是它的反面 `= 0`。题目里没有一道在问
「这个参数值的方向是放松还是收紧」，所以压到 0.01 也拦不住 —— 是题目设计的缺口。

把 `-probe-at` 压到 0.35 能捞回这几条，代价是 11% 的正常查询被拖进复核 ——
实测分布显示 0.35~0.60 区间里 safe 108 条 vs 危险 28 条，噪音全堆在那儿。

### 评测暴露过的真实缺陷

评测不是为了拿个好看的数字，是为了找 bug。实际找出来这些：

| 缺陷 | 怎么发现的 | 修法 |
|:--|:--|:--|
| 整表拖凭据被放行 | 真实语料 `data_exfil` 家族 7 条漏 4 条 | 加 `is_bulk_exfil` 维度 |
| 探针语句被放行 | `SELECT 0x457578`、`SELECT SLEEP(10)` 漏 | 加 `is_probe` 维度 |
| 合法注释被误杀 | `-- 只统计已付款` 判 BLOCK | 正则改为只匹配「引号紧贴注释」 |
| 语料本身有脏数据 | 6 条标 safe 的语句被判探测 | 生成器改为类型自洽（见下） |

最后一条值得单独说：生成器原先随机配对列和值，造出 `WHERE email = 999`、
`DELETE ... WHERE id = 2024 AND id = 'alice'` 这种语法合法、业务上讲不通的语句。
模型判它们「不服务于真实业务目的」是对的，错的是语料把它们标成了 `safe`。
**语料一脏，整个评测的结论都不能信**。

生成器为此改过三版，每版都是被模型的探测概率揪出来的：

| 版本 | 取值方式 | 产出的脏数据 |
|:--|:--|:--|
| v1 | 列和值混着随机取 | `WHERE email = 999`（类型错） |
| v2 | 按类型分组随机取 | `SET name = 'active'`、`WHERE status = 'alice'`（值域错） |
| v3 | **值绑定到列** | `ON b.amount = a.id`、`WHERE id = 1 AND id = 7`（语义错） |
| v4 | 值绑定 + 外键收敛 + 排除重复列 | 干净 |

效果（safe 语料的探测概率，越低说明模型越认可它是正常业务语句）：

```
修复前   中位 0.14 | 最高 0.54 | ≥0.35 的 114 条   ← 脏数据把分数顶到阈值线附近
修复后   中位 0.10 | 最高 0.38 | ≥0.35 的   1 条   ← 离 0.6 的拦截线有 0.22 余量
```

`corpus_test.go` 里的 `TestSafeCasesAreSemanticallySound` 把这九项检查固化下来了，
守的不是代码，是整个评测的可信度。

## 测试

```bash
go test ./...
```

模型调用在测试里用 `httptest` 假服务端替代，不消耗额度。测试覆盖：

- `internal/jev` —— 真实响应黄金样本、score 档位取整、取值方法拒绝猜测
- `internal/filter` —— 本地规则边界（合法注释 vs 注入注释）、六维判决、本地规则短路
- `internal/corpus` —— 生成条数/去重/可复现、**语料类型自洽**、CSV 往返
