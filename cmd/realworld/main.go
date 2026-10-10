// Command realworld 从公开载荷库拉取真实 SQL 注入 payload，还原成完整语句，
// 与手工整理的案例、正常业务语句合成一份可复现的评测语料。
//
//	go run ./cmd/realworld -n 1500 -o testdata/generated/realworld-1500.csv
//
// 为什么要把这条流水线写进项目：语料是评测的分母，手搓出来的 CSV
// 没人能复现，也就没人能验证那个准确率是怎么来的。
package main

import (
	"bufio"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/hedykanzhang-create/sql_filter/internal/corpus"
)

const seclistsBase = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/"

// sources 是拉取的载荷文件。SecLists 收录的是 sqlmap / fuzzdb 实际使用的载荷，
// 不是教程里的示例，所以能代表真实攻击面。
var sources = []string{
	seclistsBase + "SQLi/Generic-SQLi.txt",
	seclistsBase + "SQLi/quick-SQLi.txt",
	seclistsBase + "SQLi/sqli.auth.bypass.txt",
	seclistsBase + "SQLi/Generic-BlindSQLi.fuzzdb.txt",
	seclistsBase + "SQLi/SQLi-Polyglots.txt",
	seclistsBase + "SQLi/MySQL.fuzzdb.txt",
	seclistsBase + "SQLi/MSSQL.fuzzdb.txt",
	seclistsBase + "SQLi/Oracle.fuzzdb.txt",
	seclistsBase + "SQLi/MySQL-SQLi-Login-Bypass.fuzzdb.txt",
	seclistsBase + "SQLi/sqlmap-risk-classified/Low-Risk-Payloads/error_based.txt",
	seclistsBase + "SQLi/sqlmap-risk-classified/Low-Risk-Payloads/boolean_blind.txt",
	seclistsBase + "SQLi/sqlmap-risk-classified/Low-Risk-Payloads/time_blind.txt",
	seclistsBase + "SQLi/sqlmap-risk-classified/Low-Risk-Payloads/inline_query.txt",
	seclistsBase + "SQLi/sqlmap-risk-classified/Low-Risk-Payloads/stacked_queries.txt",
	seclistsBase + "SQLi/sqlmap-risk-classified/Medium-Risk-Payloads/time_blind.txt",
	seclistsBase + "SQLi/sqlmap-risk-classified/Medium-Risk-Payloads/stacked_queries.txt",
	seclistsBase + "SQLi/sqlmap-risk-classified/High-Risk-Payloads/error_based.txt",
	seclistsBase + "SQLi/sqlmap-risk-classified/High-Risk-Payloads/boolean_blind.txt",
	seclistsBase + "SQLi/sqlmap-risk-classified/High-Risk-Payloads/time_blind.txt",
	seclistsBase + "MySQL-Read-Local-Files.fuzzdb.txt",
	seclistsBase + "MSSQL-Enumeration.fuzzdb.txt",
	"https://raw.githubusercontent.com/Xyntax/waf-bypass/master/payload/sql.txt",
}

// sqlmapBase 指向 sqlmap 源仓库的载荷 XML。
// 这是一手来源：SecLists 里那份 sqlmap-risk-classified 是别人整理的二手快照，
// 而这里是攻击工具本体每次真正发出去的载荷，带方言/风险等级元数据。
const sqlmapBase = "https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/payloads/"

var sqlmapSources = []string{
	sqlmapBase + "boolean_blind.xml",
	sqlmapBase + "error_based.xml",
	sqlmapBase + "inline_query.xml",
	sqlmapBase + "stacked_queries.xml",
	sqlmapBase + "time_blind.xml",
	sqlmapBase + "union_query.xml",
}

// sqlmap 跑的时候会把这些占位符填成随机值，载荷文件里保留的是原样。
// 不替换的话方括号会原样进 SQL，判的就不是攻击语句而是一串乱码。
var placeholders = []struct {
	token string
	value string
}{
	{"[RANDNUM1]", "4471"}, {"[RANDNUM2]", "8812"}, {"[RANDNUM]", "3271"},
	{"[SLEEPTIME]", "5"}, {"[RANDSTR]", "'qxjkp'"}, {"[ORIGVALUE]", "1"},
	{"[DELIMITER_START]", "qjvkq"}, {"[DELIMITER_STOP]", "qpbxq"},
	{"[INFERENCE]", "1=1"}, {"[GENERIC_SQL_COMMENT]", "-- "},
	{"__TIME__", "5"},
	// [QUERY] 是 sqlmap XML 里的子查询占位符，实战中填的是攻击者想读的数据。
	// 填成读口令散列的子查询，让还原出的语句保持「拖敏感数据」的真实意图。
	{"[QUERY]", "SELECT password FROM users LIMIT 1"},
}

var (
	leftoverToken = regexp.MustCompile(`\[[A-Z_0-9]+\]`)
	// 纯噪音片段（"*"、%、单个字母）拼出来只是语法错误，测不出判别力，丢掉。
	hasSQLSemantics = regexp.MustCompile(`(?i)(--|#|;|'|"|\bor\b|\band\b|\bunion\b|\bselect\b|\bsleep\b|\bwaitfor\b|\bbenchmark\b|\(|=)`)
	numericStart    = regexp.MustCompile(`^[\d\-+]`)
	clauseStart     = regexp.MustCompile(`(?i)^(AND|OR|UNION|SELECT|;|,|\|\||BEGIN|CALL|PROCEDURE|WAITFOR|EXEC|DECLARE|CONVERT|RLIKE|XOR|DBMS|UTL|CTXSYS|SYS\.)\b`)
)

var (
	tables = []string{"users", "orders", "products", "members", "accounts", "sessions"}
	cols   = []string{"username", "name", "email", "title", "code"}
)

func main() {
	var (
		n       = flag.Int("n", 1000, "语料总条数")
		out     = flag.String("o", "testdata/generated/realworld-1500.csv", "输出 CSV")
		curated = flag.String("curated", "testdata/curated/realworld.csv", "手工整理的案例 CSV，会原样并入")
		modern  = flag.String("modern", "testdata/curated/modern-2026.csv", "2026 现代攻击面 CSV（JSON/ORM/GraphQL/方言），会原样并入")
		seed    = flag.Int64("seed", 20260920, "随机种子")
	)
	flag.Parse()

	payloads, err := fetchAll()
	if err != nil {
		fatal(err)
	}
	fmt.Printf("拉取到 %d 条去重载荷\n", len(payloads))

	r := rand.New(rand.NewSource(*seed))
	var cases []corpus.Case
	for i, p := range payloads {
		cases = append(cases, corpus.Case{
			Family: familyOf(p),
			Class:  corpus.Hostile,
			SQL:    wrap(p.text, i),
		})
	}
	hostileCount := len(cases)

	// 并入手工整理的案例（含「长得像攻击的合法 SQL」，误杀就靠它们量）。
	if cur, err := corpus.ReadCSV(*curated); err == nil {
		cases = append(cases, cur...)
		fmt.Printf("并入手工案例 %d 条\n", len(cur))
	} else {
		fmt.Fprintf(os.Stderr, "警告：读不到 %s（%v），跳过\n", *curated, err)
	}

	// 并入 2026 现代攻击面（JSON-based SQLi / ORM / GraphQL / 方言载荷）。
	if mod, err := corpus.ReadCSV(*modern); err == nil {
		cases = append(cases, mod...)
		fmt.Printf("并入现代攻击面 %d 条\n", len(mod))
	} else {
		fmt.Fprintf(os.Stderr, "警告：读不到 %s（%v），跳过\n", *modern, err)
	}

	// 补正常业务语句。一份只有攻击的语料，全部拦死也能拿满分 —— 那个分数没有意义。
	if need := *n - len(cases); need > 0 {
		var normal []corpus.Case
		for _, c := range corpus.Generate(need*4, *seed+1) {
			if c.Class != corpus.Hostile {
				normal = append(normal, c)
			}
		}
		if len(normal) > need {
			normal = normal[:need]
		}
		cases = append(cases, normal...)
		fmt.Printf("补正常业务语句 %d 条\n", len(normal))
	}
	if len(cases) > *n {
		cases = cases[:*n]
	}

	r.Shuffle(len(cases), func(a, b int) { cases[a], cases[b] = cases[b], cases[a] })
	for i := range cases {
		cases[i].ID = i + 1
	}

	if err := corpus.WriteCSV(*out, cases); err != nil {
		fatal(err)
	}
	fmt.Printf("\n已写入 %s（真实载荷 %d 条）\n\n%s", *out, hostileCount, corpus.Summary(cases))
}

type payload struct{ text, src string }

func fetchAll() ([]payload, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	seen := map[string]bool{}
	var out []payload

	for _, u := range sources {
		resp, err := client.Get(u)
		if err != nil {
			fmt.Fprintf(os.Stderr, "跳过 %s: %v\n", u, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "跳过 %s: http %d\n", u, resp.StatusCode)
			resp.Body.Close()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()

		sc := bufio.NewScanner(strings.NewReader(string(body)))
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			// 载荷里混着 %a0 这类非法 UTF-8 字节（本身就是绕过手法之一）。
			// 原样写进 CSV 会让 Excel / pandas 直接打不开，所以剔掉这些字节 ——
			// 语料是给人看的，打不开的语料等于没有。
			line := strings.ToValidUTF8(strings.TrimSpace(sc.Text()), "")
			if line == "" || strings.HasPrefix(line, "#") || !hasSQLSemantics.MatchString(line) {
				continue
			}
			key := strings.ToLower(line)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, payload{text: substitute(line), src: u})
		}
	}
	// 一手来源：sqlmap 的 XML 载荷。
	for _, u := range sqlmapSources {
		payloads, err := fetchSqlmapXML(client, u)
		if err != nil {
			fmt.Fprintf(os.Stderr, "跳过 %s: %v\n", u, err)
			continue
		}
		for _, raw := range payloads {
			line := strings.ToValidUTF8(strings.TrimSpace(raw), "")
			if line == "" || !hasSQLSemantics.MatchString(line) {
				continue
			}
			key := strings.ToLower(line)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, payload{text: substitute(line), src: u})
		}
	}

	// 排序让结果与网络返回顺序无关，保证同 seed 可复现。
	sort.Slice(out, func(i, j int) bool { return out[i].text < out[j].text })
	return out, nil
}

// sqlmapXML 只取每个 <test> 的 <request><payload> —— 那是真正拼进 URL 参数的载荷。
// vector 是带 [QUERY] 的模板、grep 是响应匹配规则，都不是打到库上的东西，忽略。
type sqlmapXML struct {
	Tests []struct {
		Payload string `xml:"request>payload"`
	} `xml:"test"`
}

func fetchSqlmapXML(client *http.Client, u string) ([]string, error) {
	resp, err := client.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))

	var doc sqlmapXML
	if err := xml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse xml: %w", err)
	}
	var out []string
	for _, t := range doc.Tests {
		if p := strings.TrimSpace(t.Payload); p != "" {
			out = append(out, p)
		}
	}
	return out, nil
}

func substitute(s string) string {
	for _, p := range placeholders {
		s = strings.ReplaceAll(s, p.token, p.value)
	}
	return leftoverToken.ReplaceAllString(s, "1")
}

// wrap 按片段的起始形态还原它被插进了什么上下文。
// 载荷库给的是「插进参数位的那段字符串」，不是完整语句；
// 过滤器看到的是拼接完成后的 SQL，不还原上下文就测不出真实场景。
func wrap(p string, i int) string {
	t, c := tables[i%len(tables)], cols[i%len(cols)]
	head := strings.TrimLeft(p, " \t")
	switch {
	case strings.HasPrefix(head, ")"), strings.HasPrefix(head, "')"), strings.HasPrefix(head, `")`):
		// 闭合括号型：原查询把条件包在括号里
		return fmt.Sprintf("SELECT * FROM %s WHERE (%s = 'x'%s", t, c, p)
	case numericStart.MatchString(head):
		// 数值上下文：参数位本身是个数字
		return fmt.Sprintf("SELECT * FROM %s WHERE id = %s", t, p)
	case clauseStart.MatchString(head):
		// 裸条件片段：直接续在数值参数后面
		return fmt.Sprintf("SELECT * FROM %s WHERE id = 1 %s", t, p)
	default:
		// 字符串上下文：片段自带闭合引号
		return fmt.Sprintf("SELECT id, %s FROM %s WHERE %s = '%s", c, t, c, p)
	}
}

func familyOf(p payload) string {
	n, low := strings.ToLower(p.src), strings.ToLower(p.text)
	switch {
	case strings.Contains(n, "auth"), strings.Contains(n, "bypass"):
		return "sl_auth_bypass"
	case strings.Contains(n, "time_blind"), strings.Contains(low, "sleep"),
		strings.Contains(low, "waitfor"), strings.Contains(low, "benchmark"):
		return "sl_time_blind"
	case strings.Contains(n, "boolean_blind"):
		return "sl_boolean_blind"
	case strings.Contains(n, "error_based"), strings.Contains(low, "extractvalue"),
		strings.Contains(low, "updatexml"):
		return "sl_error_based"
	case strings.Contains(n, "stacked"):
		return "sl_stacked"
	case strings.Contains(n, "inline_query"):
		return "sl_inline_query"
	case strings.Contains(n, "polyglot"):
		return "sl_polyglot"
	case strings.Contains(n, "read-local-files"), strings.Contains(n, "enumeration"):
		return "sl_file_enum"
	case strings.Contains(n, "oracle"):
		return "sl_oracle"
	case strings.Contains(n, "mssql"):
		return "sl_mssql"
	case strings.Contains(n, "mysql"):
		return "sl_mysql"
	case strings.Contains(low, "union"):
		return "sl_union"
	}
	return "sl_generic"
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "错误: %v\n", err)
	os.Exit(1)
}
