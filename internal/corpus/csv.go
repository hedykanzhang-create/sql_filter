package corpus

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
)

// csvHeader 是语料文件的列。SQL 放最后一列，因为它最长，
// 用 less / 表格软件看时前面的元信息不会被挤出屏幕。
var csvHeader = []string{"id", "family", "class", "sql"}

// WriteCSV 把语料写成 CSV。encoding/csv 会自己处理引号和逗号转义，
// 所以 SQL 里的 'active'、WHERE a, b 这类内容都不用额外处理。
func WriteCSV(path string, cases []Case) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("corpus: create %s: %w", path, err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	if err := w.Write(csvHeader); err != nil {
		return err
	}
	for _, c := range cases {
		row := []string{strconv.Itoa(c.ID), c.Family, string(c.Class), c.SQL}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

// ReadCSV 读回语料。允许人手工编辑过这个文件 —— 补几条真实场景的语句进去
// 是很自然的需求，所以这里按列名定位而不是按固定下标，加列也不会读错。
func ReadCSV(path string) ([]Case, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("corpus: open %s: %w", path, err)
	}
	defer f.Close()

	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("corpus: parse %s: %w", path, err)
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("corpus: %s 里没有数据行", path)
	}

	idx := map[string]int{}
	for i, name := range rows[0] {
		idx[name] = i
	}
	for _, need := range csvHeader {
		if _, ok := idx[need]; !ok {
			return nil, fmt.Errorf("corpus: %s 缺少列 %q", path, need)
		}
	}

	var out []Case
	for lineNo, row := range rows[1:] {
		if len(row) <= idx["sql"] {
			return nil, fmt.Errorf("corpus: 第 %d 行列数不足", lineNo+2)
		}
		id, err := strconv.Atoi(row[idx["id"]])
		if err != nil {
			return nil, fmt.Errorf("corpus: 第 %d 行 id 不是数字: %w", lineNo+2, err)
		}
		class := Class(row[idx["class"]])
		switch class {
		case Safe, Risky, Hostile:
		default:
			return nil, fmt.Errorf("corpus: 第 %d 行 class %q 不合法（应为 safe/risky/hostile）", lineNo+2, class)
		}
		out = append(out, Case{
			ID:     id,
			Family: row[idx["family"]],
			Class:  class,
			SQL:    row[idx["sql"]],
		})
	}
	return out, nil
}
