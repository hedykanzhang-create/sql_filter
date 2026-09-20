package jev

import (
	"encoding/json"
	"fmt"
)

// parseResponse 解析 Decisions API 的响应。
//
// 结构以 2026-09-20 对 typesafe/jev-1.13-20260917 的实测为准。
// 这里刻意不做「字段名猜测」的兼容：早先那版兼容层因为猜错字段名，
// 把 noul 的 0.97 静默解析成 0，导致注入语句被放行 —— 静默降级比直接报错危险得多。
// 所以现在的原则是：结构对不上就报错，把原始响应打出来，让人去改代码。
func parseResponse(raw []byte) (*Response, error) {
	var out Response
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("jev: decode response: %w (body: %s)", err, truncate(string(raw), 512))
	}
	if len(out.Answers) == 0 {
		return nil, fmt.Errorf("jev: no answers in response: %s", truncate(string(raw), 512))
	}
	return &out, nil
}

// Noul 取一道 noul 题的概率；题目缺失或类型不符时返回 error。
// 之所以不让调用方直接读 map —— map 取不到键会静默给零值，
// 而 0 在这里的含义是「肯定不是」，恰好是最危险的方向。
func (r *Response) Noul(name string) (float64, error) {
	a, ok := r.Answers[name]
	if !ok {
		return 0, fmt.Errorf("jev: missing answer %q", name)
	}
	if a.Type != TypeNoul {
		return 0, fmt.Errorf("jev: answer %q is %q, want noul", name, a.Type)
	}
	return a.Noul, nil
}

// Choice 取一道 choice 题选中的键。
func (r *Response) Choice(name string) (string, error) {
	a, ok := r.Answers[name]
	if !ok {
		return "", fmt.Errorf("jev: missing answer %q", name)
	}
	if a.Type != TypeChoice {
		return "", fmt.Errorf("jev: answer %q is %q, want choice", name, a.Type)
	}
	return a.Choice, nil
}

// Score 取一道 score 题的答案本体，调用方用 .Score 拿位置、.Label() 拿文案。
func (r *Response) Score(name string) (Answer, error) {
	a, ok := r.Answers[name]
	if !ok {
		return Answer{}, fmt.Errorf("jev: missing answer %q", name)
	}
	if a.Type != TypeScore {
		return Answer{}, fmt.Errorf("jev: answer %q is %q, want score", name, a.Type)
	}
	return a, nil
}
