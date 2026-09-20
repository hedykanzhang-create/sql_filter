package jev

import "testing"

// realResponse 是 2026-09-20 从 typesafe/jev-1.13-20260917 抓到的真实响应，
// 原样保留作为黄金样本。之前解析层靠猜字段名，把 noul 的 0.97 解析成 0，
// 注入语句因此被放行 —— 有了这份样本，字段名再变就会当场测试失败。
const realResponse = `{"model":"typesafe/jev-1.13-20260917","answers":{` +
	`"category":{"type":"choice","choice":"read","probabilities":{"read":1,"admin":0,"write":0,"schema":0},"confidence":1},` +
	`"is_injection":{"type":"noul","noul":0.97},` +
	`"is_read_only":{"type":"noul","noul":0.98},` +
	`"risk":{"type":"score","score":0.24,"legend":{"0":"只读查询，作用范围明确，无副作用","1":"会改数据但范围有限，属于常规业务操作","2":"影响面大或不可逆（批量删改、结构变更、权限调整）"},` +
	`"probabilities":{"0":0.87,"1":0.01,"2":0.12},"confidence":0.64}},` +
	`"usage":{"input_tokens":719,"output_tokens":96,"cost":0.000030198},` +
	`"id":"gen-dec-1789870311-01oxkJ1TDOwET0mljyuG","provider":"TypeSafe"}`

func TestParseRealResponse(t *testing.T) {
	resp, err := parseResponse([]byte(realResponse))
	if err != nil {
		t.Fatal(err)
	}

	if got, err := resp.Noul("is_injection"); err != nil || got != 0.97 {
		t.Fatalf("is_injection = %v, err = %v; 期望 0.97", got, err)
	}
	if got, err := resp.Noul("is_read_only"); err != nil || got != 0.98 {
		t.Fatalf("is_read_only = %v, err = %v; 期望 0.98", got, err)
	}
	if got, err := resp.Choice("category"); err != nil || got != "read" {
		t.Fatalf("category = %q, err = %v; 期望 read", got, err)
	}

	risk, err := resp.Score("risk")
	if err != nil {
		t.Fatal(err)
	}
	if risk.Score != 0.24 {
		t.Fatalf("risk.Score = %v, 期望 0.24（注意是连续值不是下标）", risk.Score)
	}
	// 0.24 四舍五入到第 0 档。
	if got := risk.Label(); got != "只读查询，作用范围明确，无副作用" {
		t.Fatalf("risk.Label() = %q", got)
	}
	if risk.Confidence != 0.64 {
		t.Fatalf("risk.Confidence = %v, 期望 0.64", risk.Confidence)
	}
	if resp.Usage.Cost != 0.000030198 {
		t.Fatalf("cost = %v", resp.Usage.Cost)
	}
}

func TestLabelRoundsToNearestRung(t *testing.T) {
	a := Answer{Type: TypeScore, Legend: map[string]string{"0": "低", "1": "中", "2": "高"}}
	for _, c := range []struct {
		score float64
		want  string
	}{
		{0.0, "低"}, {0.4, "低"}, {0.6, "中"}, {1.4, "中"}, {1.9, "高"}, {2.0, "高"},
	} {
		a.Score = c.score
		if got := a.Label(); got != c.want {
			t.Fatalf("score %.1f 的档位 = %q, 期望 %q", c.score, got, c.want)
		}
	}
}

// 取值方法必须在题目缺失或类型不符时报错，而不是返回零值 ——
// 注入概率的零值是「绝对安全」，静默降级等于全线放行。
func TestAccessorsRefuseToGuess(t *testing.T) {
	resp, err := parseResponse([]byte(realResponse))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resp.Noul("not_asked"); err == nil {
		t.Fatal("题目缺失时应报错")
	}
	if _, err := resp.Noul("category"); err == nil {
		t.Fatal("类型不符时应报错（category 是 choice 不是 noul）")
	}
	if _, err := resp.Choice("risk"); err == nil {
		t.Fatal("类型不符时应报错（risk 是 score 不是 choice）")
	}
}

func TestParseResponseNoAnswers(t *testing.T) {
	if _, err := parseResponse([]byte(`{"id":"1","model":"x"}`)); err == nil {
		t.Fatal("期望报错，实际通过")
	}
}
