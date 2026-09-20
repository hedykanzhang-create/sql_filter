# 测试语料目录

三类文件分开放，一眼能看出「哪些该手改、哪些别碰、哪些可删」。

## curated/ —— 手工维护的源（要改语料，改这里）

| 文件 | 条数 | 内容 |
|:--|--:|:--|
| `realworld.csv` | 79 | 手工整理自 OWASP / Invicti 的经典手法，含「长得像攻击的合法 SQL」 |
| `modern-2026.csv` | 21 | 2026 新攻击面：JSON-based SQLi、ORM 注入、GraphQL 下游、方言载荷 |

这两份是**唯一需要人手维护**的。列 `note` 记录每条的来源与意图。

## generated/ —— 程序生成（勿手改，可复现）

| 文件 | 条数 | 由谁生成 |
|:--|--:|:--|
| `cases.csv` | 1000 | `go run ./cmd/gencases`（固定 seed，均衡分布，量误杀用） |
| `realworld-1500.csv` | 1500 | `go run ./cmd/realworld`（拉 sqlmap/SecLists/waf-bypass + 并入 curated + 补正常语句） |

手改这里的文件没意义 —— 下次重新生成就被覆盖。要改语料请改 `curated/` 或改生成器。

## results/ —— 评测输出（可删，随时可再生）

`go run ./cmd/bench -i <语料> -o results/<名>.results.csv` 的产物，含每条的判决、
各维度概率、命中规则。**这些是快照，不是源**，删掉重跑一遍就有。

| 文件 | 对应语料 |
|:--|:--|
| `cases.results.csv` | generated/cases.csv |
| `realworld-1500.results.csv` | generated/realworld-1500.csv |
| `modern-2026.results.csv` | curated/modern-2026.csv |
| `realworld.results.csv` | curated/realworld.csv |

## 复现全部

```bash
go run ./cmd/gencases                                   # → generated/cases.csv
go run ./cmd/realworld                                  # → generated/realworld-1500.csv
go run ./cmd/bench -i generated/cases.csv          -o results/cases.results.csv
go run ./cmd/bench -i generated/realworld-1500.csv -o results/realworld-1500.results.csv
go run ./cmd/bench -i curated/modern-2026.csv      -o results/modern-2026.results.csv
```
