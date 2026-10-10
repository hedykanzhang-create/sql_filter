// Command gencases 生成带标注的 SQL 测试语料，输出 CSV。
//
//	go run ./cmd/gencases -n 1000 -o testdata/generated/cases.csv
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hedykanzhang-create/sql_filter/internal/corpus"
)

func main() {
	n := flag.Int("n", 1000, "生成多少条语料")
	seed := flag.Int64("seed", 20260920, "随机种子，固定则结果可复现")
	out := flag.String("o", "testdata/generated/cases.csv", "输出 CSV 路径")
	flag.Parse()

	cases := corpus.Generate(*n, *seed)

	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fatal(err)
	}
	if err := corpus.WriteCSV(*out, cases); err != nil {
		fatal(err)
	}

	fmt.Printf("已写入 %s\n\n%s", *out, corpus.Summary(cases))
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "错误: %v\n", err)
	os.Exit(1)
}
