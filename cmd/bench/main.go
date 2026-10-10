// Command bench 拿 CSV 语料跑过滤器，对账判决并出准确率报表。
//
//	go run ./cmd/bench -i testdata/generated/cases.csv -o testdata/results/cases.results.csv -c 16
package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/hedykanzhang-create/sql_filter/internal/corpus"
	"github.com/hedykanzhang-create/sql_filter/internal/filter"
	"github.com/hedykanzhang-create/sql_filter/internal/jev"
)

// Verdict 是「过滤器判得对不对」，由语料的 Class 和过滤器的 Decision 对账得出。
type Verdict string

const (
	Pass     Verdict = "PASS"      // 判对了
	Miss     Verdict = "MISS"      // 漏杀：该拦的放行了 —— 唯一会真正造成损失的一类
	FalseAcc Verdict = "OVERBLOCK" // 误杀：正常语句被拒绝
	Noise    Verdict = "NOISE"     // 噪音：正常语句被要求人工复核，不致命但会烦死人
	Failed   Verdict = "FAILED"    // 判定过程本身出错
)

// judge 把「期望」和「实际」对账。
//
// 关键取舍：hostile 被判 REVIEW 算 PASS 而不是 MISS ——
// 复核意味着人会看一眼，攻击语句不会直接打到库上，风险已经被挡住了。
// 只有 ALLOW 才是真正的漏网。
func judge(class corpus.Class, d filter.Decision) Verdict {
	switch class {
	case corpus.Safe:
		switch d {
		case filter.Allow:
			return Pass
		case filter.Review:
			return Noise
		default:
			return FalseAcc
		}
	default: // risky / hostile 都不该被放行
		if d == filter.Allow {
			return Miss
		}
		return Pass
	}
}

type row struct {
	Case    corpus.Case
	Result  *filter.Result
	Err     error
	Verdict Verdict
}

func main() {
	var (
		in       = flag.String("i", "testdata/generated/cases.csv", "语料 CSV")
		out      = flag.String("o", "testdata/results/cases.results.csv", "结果 CSV")
		workers  = flag.Int("c", 16, "并发数")
		limit    = flag.Int("limit", 0, "只跑前 N 条（0 = 全跑），用于小样本试水")
		offline  = flag.Bool("offline", false, "只跑本地规则，不调用 Jev（不花钱）")
		readOnly = flag.Bool("readonly", false, "只读模式")
		timeout  = flag.Duration("timeout", 60*time.Second, "单条超时")
		probeAt  = flag.Float64("probe-at", 0.6, "探测概率达到此值转人工复核")
	)
	flag.Parse()

	cases, err := corpus.ReadCSV(*in)
	if err != nil {
		fatal(err)
	}
	if *limit > 0 && *limit < len(cases) {
		cases = cases[:*limit]
	}

	var client *jev.Client
	if !*offline {
		key := jev.ResolveKey()
		if key == "" {
			fatal(fmt.Errorf("未找到 API key：设置 OPENROUTER_API_KEY 或写入 %s（或加 -offline）", jev.KeyFilePath()))
		}
		client = jev.New(key)
	}
	f := filter.New(client, filter.Options{ReadOnly: *readOnly, ProbeThreshold: *probeAt})

	fmt.Printf("语料 %d 条，并发 %d，模式 %s\n", len(cases), *workers, modeName(*offline, *readOnly))
	start := time.Now()
	rows := run(f, cases, *workers, *timeout)
	elapsed := time.Since(start)

	if err := writeResults(*out, rows); err != nil {
		fatal(err)
	}
	report(rows, elapsed, *out)

	// 有漏杀就非零退出，方便当回归门禁挂进 CI。
	for _, r := range rows {
		if r.Verdict == Miss || r.Verdict == Failed {
			os.Exit(1)
		}
	}
}

// run 用固定大小的 worker 池并发跑。
// 结果按输入下标写回切片，所以不需要加锁，顺序也和语料一致。
func run(f *filter.Filter, cases []corpus.Case, workers int, timeout time.Duration) []row {
	rows := make([]row, len(cases))
	jobs := make(chan int)

	var wg sync.WaitGroup
	var done int64
	var mu sync.Mutex

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				c := cases[i]
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				res, err := f.Check(ctx, c.SQL)
				cancel()

				r := row{Case: c, Result: res, Err: err}
				if err != nil {
					r.Verdict = Failed
				} else {
					r.Verdict = judge(c.Class, res.Decision)
				}
				rows[i] = r

				mu.Lock()
				done++
				if done%100 == 0 {
					fmt.Printf("  已完成 %d/%d\n", done, len(cases))
				}
				mu.Unlock()
			}
		}()
	}

	for i := range cases {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return rows
}

func writeResults(path string, rows []row) error {
	fh, err := os.Create(path)
	if err != nil {
		return err
	}
	defer fh.Close()

	w := csv.NewWriter(fh)
	defer w.Flush()

	header := []string{"id", "family", "class", "verdict", "decision", "source",
		"injection", "bulk_exfil", "probe", "read_only", "category", "risk", "cost", "sql", "reason"}
	if err := w.Write(header); err != nil {
		return err
	}
	for _, r := range rows {
		rec := []string{
			strconv.Itoa(r.Case.ID), r.Case.Family, string(r.Case.Class), string(r.Verdict),
		}
		if r.Result != nil {
			rec = append(rec,
				string(r.Result.Decision), r.Result.Source,
				fmt.Sprintf("%.2f", r.Result.InjectionProbability),
				fmt.Sprintf("%.2f", r.Result.BulkExfilProbability),
				fmt.Sprintf("%.2f", r.Result.ProbeProbability),
				fmt.Sprintf("%.2f", r.Result.ReadOnlyProbability),
				r.Result.Category,
				fmt.Sprintf("%.2f", r.Result.RiskScore),
				fmt.Sprintf("%.6f", r.Result.Cost),
				r.Case.SQL, r.Result.Reason)
		} else {
			rec = append(rec, "", "", "", "", "", "", "", "", "", r.Case.SQL, fmt.Sprint(r.Err))
		}
		if err := w.Write(rec); err != nil {
			return err
		}
	}
	return w.Error()
}

func report(rows []row, elapsed time.Duration, outPath string) {
	byVerdict := map[Verdict]int{}
	byFamily := map[string]map[Verdict]int{}
	bySource := map[string]int{}
	var cost float64

	for _, r := range rows {
		byVerdict[r.Verdict]++
		if byFamily[r.Case.Family] == nil {
			byFamily[r.Case.Family] = map[Verdict]int{}
		}
		byFamily[r.Case.Family][r.Verdict]++
		if r.Result != nil {
			bySource[r.Result.Source]++
			cost += r.Result.Cost
		}
	}

	n := len(rows)
	fmt.Printf("\n===== 总览（%d 条，耗时 %s，花费 $%.4f）=====\n", n, elapsed.Round(time.Second), cost)
	fmt.Printf("  PASS      %4d  %5.1f%%   判对\n", byVerdict[Pass], pct(byVerdict[Pass], n))
	fmt.Printf("  MISS      %4d  %5.1f%%   漏杀（该拦的放行了）\n", byVerdict[Miss], pct(byVerdict[Miss], n))
	fmt.Printf("  OVERBLOCK %4d  %5.1f%%   误杀（正常语句被拒）\n", byVerdict[FalseAcc], pct(byVerdict[FalseAcc], n))
	fmt.Printf("  NOISE     %4d  %5.1f%%   噪音（正常语句要人工复核）\n", byVerdict[Noise], pct(byVerdict[Noise], n))
	fmt.Printf("  FAILED    %4d  %5.1f%%   判定出错\n", byVerdict[Failed], pct(byVerdict[Failed], n))
	fmt.Printf("\n  判决来源：本地规则 %d 条（省下这些调用），Jev %d 条\n",
		bySource["static"], bySource["jev"])

	fmt.Printf("\n===== 分家族 =====\n")
	fmt.Printf("  %-16s %6s %6s %6s %6s %6s\n", "family", "PASS", "MISS", "OVER", "NOISE", "FAIL")
	var names []string
	for k := range byFamily {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		v := byFamily[name]
		fmt.Printf("  %-16s %6d %6d %6d %6d %6d\n",
			name, v[Pass], v[Miss], v[FalseAcc], v[Noise], v[Failed])
	}

	// 漏杀逐条列出 —— 这是唯一必须人眼看的部分。
	printSamples(rows, Miss, "漏杀明细（全部）", 0)
	printSamples(rows, FalseAcc, "误杀样例", 10)
	printSamples(rows, Failed, "判定出错样例", 10)

	fmt.Printf("\n完整结果：%s\n", outPath)
}

func printSamples(rows []row, v Verdict, title string, max int) {
	var hits []row
	for _, r := range rows {
		if r.Verdict == v {
			hits = append(hits, r)
		}
	}
	if len(hits) == 0 {
		return
	}
	fmt.Printf("\n===== %s：%d 条 =====\n", title, len(hits))
	for i, r := range hits {
		if max > 0 && i >= max {
			fmt.Printf("  ...（其余 %d 条见结果 CSV）\n", len(hits)-max)
			break
		}
		fmt.Printf("  [#%d %s] %s\n", r.Case.ID, r.Case.Family, r.Case.SQL)
		if r.Result != nil {
			fmt.Printf("      → %s | 注入 %.2f | 风险 %.2f | %s\n",
				r.Result.Decision, r.Result.InjectionProbability, r.Result.RiskScore, r.Result.Reason)
		} else {
			fmt.Printf("      → 错误: %v\n", r.Err)
		}
	}
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) * 100 / float64(b)
}

func modeName(offline, readOnly bool) string {
	s := "在线(Jev)"
	if offline {
		s = "离线(仅本地规则)"
	}
	if readOnly {
		s += " + 只读"
	}
	return s
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "错误: %v\n", err)
	os.Exit(2)
}
