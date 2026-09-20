// Package jev 封装 OpenRouter Decisions API（~typesafe/jev-latest）。
//
// 这个模型不生成文本：你给它一个 state（待判断的内容）和一组带类型的 question，
// 它只回答「是/否的概率（noul）」「从你给的选项里挑一个（choice）」
// 「在有序标尺上打一个位置（score）」。
package jev

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"time"
)

const (
	// DefaultEndpoint 是 Decisions API 的地址，注意是 /api/alpha 而不是 /api/v1。
	DefaultEndpoint = "https://openrouter.ai/api/alpha/decisions"
	// DefaultModel 永远指向 Jev 家族的最新模型。
	DefaultModel = "~typesafe/jev-latest"
)

// 三种问题类型。
const (
	TypeNoul   = "noul"   // 是/否，回答是 true 的概率
	TypeChoice = "choice" // 从 criteria 的键里挑一个
	TypeScore  = "score"  // 在 criteria 数组（有序标尺）上定位
)

// Question 是一道题。Criteria 的形状随 Type 变：
//   - noul/choice: map[string]string，键是判定结果，值是判定说明
//   - score:       []string，按从低到高排列的标尺档位
type Question struct {
	Type         string `json:"type"`
	Instructions string `json:"instructions"`
	Criteria     any    `json:"criteria,omitempty"`
}

// Request 是一次决策请求。State 可以是字符串、对象或数组。
type Request struct {
	Model     string              `json:"model"`
	State     any                 `json:"state"`
	Questions map[string]Question `json:"questions"`
}

// Answer 是单道题的答案。三种类型共用一个结构，只有对应字段有意义。
//
// 字段名以真实响应为准（2026-09-20 实测 typesafe/jev-1.13-20260917）：
//
//	noul:   {"type":"noul","noul":0.97}
//	choice: {"type":"choice","choice":"read","probabilities":{...},"confidence":1}
//	score:  {"type":"score","score":0.24,"legend":{"0":"...","1":"..."},
//	         "probabilities":{"0":0.87,"1":0.01,"2":0.12},"confidence":0.64}
type Answer struct {
	Type string `json:"type"`

	// Noul 是 noul 类型的答案：判定为 true 的概率。
	Noul float64 `json:"noul"`

	// Choice 是 choice 类型选中的键。
	Choice string `json:"choice"`

	// Score 是 score 类型在标尺上的位置，**是浮点数不是下标**：
	// 它等于各档位的概率加权平均（上例 0*0.87+1*0.01+2*0.12 = 0.25 ≈ 0.24），
	// 所以 0.24 的含义是「基本贴着第 0 档，略微沾一点第 2 档」。
	Score float64 `json:"score"`

	// Legend 是 score 类型的标尺文案，键是档位下标字符串。
	// 服务端会把请求里的 criteria 原样回带，所以用它取文案比本地存一份更可靠。
	Legend map[string]string `json:"legend"`

	// Probabilities 是各候选项的概率分布。choice 的键是选项名，
	// score 的键是档位下标字符串。
	Probabilities map[string]float64 `json:"probabilities"`

	// Confidence 是模型对这道题的把握程度。noul 类型不返回此字段。
	Confidence float64 `json:"confidence"`
}

// Label 返回 score 答案落在哪一档的文案。Score 是连续值，四舍五入取最近的档位。
func (a Answer) Label() string {
	if len(a.Legend) == 0 {
		return ""
	}
	idx := int(math.Round(a.Score))
	if idx < 0 {
		idx = 0
	}
	return a.Legend[strconv.Itoa(idx)]
}

// Usage 是本次决策的计费信息。
type Usage struct {
	InputTokens  int     `json:"input_tokens"`
	OutputTokens int     `json:"output_tokens"`
	Cost         float64 `json:"cost"`
}

// Response 是一次决策的完整结果。
type Response struct {
	ID       string            `json:"id"`
	Model    string            `json:"model"`
	Provider string            `json:"provider"`
	Answers  map[string]Answer `json:"answers"`
	Usage    Usage             `json:"usage"`
}

// Client 是 Decisions API 的最小客户端。
type Client struct {
	APIKey   string
	Model    string
	Endpoint string
	HTTP     *http.Client

	// Referer / Title 对应文档里可选的 HTTP-Referer / X-Title 头，
	// 只影响 OpenRouter 排行榜展示，留空即可。
	Referer string
	Title   string

	// Debug 为 true 时把原始响应体打到 stderr。
	// Decisions API 还在 alpha、响应结构没有公开文档，解析对不上时靠它定位。
	Debug bool
}

// New 用 API Key 构造一个客户端，其余字段走默认值。
func New(apiKey string) *Client {
	return &Client{
		APIKey:   apiKey,
		Model:    DefaultModel,
		Endpoint: DefaultEndpoint,
		HTTP:     &http.Client{Timeout: 30 * time.Second},
	}
}

// Decide 发一次决策请求。state 是被判断的对象，questions 是题目集合。
func (c *Client) Decide(ctx context.Context, state any, questions map[string]Question) (*Response, error) {
	if c.APIKey == "" {
		return nil, fmt.Errorf("jev: missing API key (set OPENROUTER_API_KEY)")
	}
	model := c.Model
	if model == "" {
		model = DefaultModel
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	httpc := c.HTTP
	if httpc == nil {
		httpc = &http.Client{Timeout: 30 * time.Second}
	}

	body, err := json.Marshal(Request{Model: model, State: state, Questions: questions})
	if err != nil {
		return nil, fmt.Errorf("jev: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("jev: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	if c.Referer != "" {
		req.Header.Set("HTTP-Referer", c.Referer)
	}
	if c.Title != "" {
		req.Header.Set("X-Title", c.Title)
	}

	resp, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jev: do request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("jev: read response: %w", err)
	}
	if c.Debug {
		fmt.Fprintf(os.Stderr, "[jev debug] http %d\n%s\n", resp.StatusCode, raw)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jev: http %d: %s", resp.StatusCode, truncate(string(raw), 512))
	}
	return parseResponse(raw)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
