// Command sql_filter 用 OpenRouter 的 Jev 决策模型过滤 SQL 语句。
//
//	sql_filter "SELECT * FROM users WHERE id = 1"
//	sql_filter -readonly -json "DELETE FROM users"
//	cat queries.sql | sql_filter        # 每行一条
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hedykanzhang-create/sql_filter/internal/filter"
	"github.com/hedykanzhang-create/sql_filter/internal/jev"
)

func main() {
	var (
		readOnly = flag.Bool("readonly", false, "只读模式：任何写入或结构变更都拒绝")
		offline  = flag.Bool("offline", false, "离线模式：只跑本地规则，不调用 Jev")
		asJSON   = flag.Bool("json", false, "以 JSON 输出结果")
		blockAt  = flag.Float64("block-at", 0.5, "注入概率达到此值即拒绝")
		reviewAt = flag.Float64("review-at", 0.2, "注入概率达到此值转人工复核")
		model    = flag.String("model", jev.DefaultModel, "OpenRouter 模型 slug")
		timeout  = flag.Duration("timeout", 30*time.Second, "单条语句的判定超时")
		debug    = flag.Bool("debug", false, "把 Jev 的原始响应体打到 stderr")
	)
	flag.Parse()

	client, err := buildClient(*offline, *model, *debug)
	if err != nil {
		fatal(err)
	}

	f := filter.New(client, filter.Options{
		ReadOnly:           *readOnly,
		InjectionThreshold: *blockAt,
		ReviewThreshold:    *reviewAt,
	})

	statements, err := collectInput(flag.Args())
	if err != nil {
		fatal(err)
	}
	if len(statements) == 0 {
		fmt.Fprintln(os.Stderr, "用法: sql_filter [flags] \"<SQL>\"  或从标准输入按行读取")
		flag.PrintDefaults()
		os.Exit(2)
	}

	// 退出码让调用方能直接拿来做 CI 门禁：0 全放行，1 有复核，2 有拒绝。
	worst := 0
	for _, sql := range statements {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		res, err := f.Check(ctx, sql)
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "判定失败: %v\n", err)
			worst = max(worst, 2)
			continue
		}
		render(res, *asJSON)
		switch res.Decision {
		case filter.Block:
			worst = max(worst, 2)
		case filter.Review:
			worst = max(worst, 1)
		}
	}
	os.Exit(worst)
}

// buildClient 组装 Jev 客户端；离线模式返回 nil，过滤器会退化成只跑本地规则。
func buildClient(offline bool, model string, debug bool) (*jev.Client, error) {
	if offline {
		return nil, nil
	}
	key := jev.ResolveKey()
	if key == "" {
		return nil, fmt.Errorf(
			"未找到 API key：设置环境变量 OPENROUTER_API_KEY，或写入 %s（或加 -offline 只跑本地规则）",
			jev.KeyFilePath())
	}
	c := jev.New(key)
	c.Model = model
	c.Debug = debug
	return c, nil
}

// collectInput 优先取命令行参数，没有就按行读标准输入（空行与 -- 注释行跳过）。
func collectInput(args []string) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	stat, err := os.Stdin.Stat()
	if err != nil || stat.Mode()&os.ModeCharDevice != 0 {
		return nil, nil // 没有管道输入
	}
	var out []string
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "--") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func render(res *filter.Result, asJSON bool) {
	if asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return
	}
	fmt.Printf("%s  %s\n", icon(res.Decision), res.SQL)
	fmt.Printf("    判决: %s (来源: %s)\n", res.Decision, res.Source)
	fmt.Printf("    依据: %s\n", res.Reason)
	if res.Source == "jev" {
		fmt.Printf("    明细: 注入 %.2f | 拖库 %.2f | 探测 %.2f | 只读 %.2f | 类别 %s | 风险 %.2f | 花费 $%.6f\n",
			res.InjectionProbability, res.BulkExfilProbability, res.ProbeProbability,
			res.ReadOnlyProbability, res.Category, res.RiskScore, res.Cost)
	}
	fmt.Println()
}

func icon(d filter.Decision) string {
	switch d {
	case filter.Allow:
		return "✅"
	case filter.Review:
		return "⚠️ "
	default:
		return "⛔"
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "错误: %v\n", err)
	os.Exit(2)
}
