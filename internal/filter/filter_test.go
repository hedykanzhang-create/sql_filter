package filter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/hedykanzhang-create/sql_filter/internal/jev"
)

func TestStaticRules(t *testing.T) {
	cases := []struct {
		name     string
		sql      string
		readOnly bool
		wantRule string
	}{
		{"正常查询", "SELECT id FROM users WHERE id = 1", false, ""},
		{"堆叠注入", "SELECT 1; DROP TABLE users", false, "stacked_query"},
		{"恒真条件", "SELECT * FROM users WHERE name = 'a' OR 1=1", false, "tautology"},
		// 注释规则区分「截断条件」和「正常注释」：
		// 注入必须紧贴引号闭合字符串，中间容不下空格；合法注释前一定有空格。
		{"引号后紧跟注释", "SELECT * FROM users WHERE u = 'admin'--' AND p = 'x'", false, "comment_truncation"},
		{"合法尾注释", "SELECT COUNT(*) FROM orders WHERE status = 'paid' -- 只统计已付款", false, ""},
		{"合法块注释", "/* 月度对账 */ SELECT shop_id FROM payments", false, ""},
		{"注释切开关键字", "SELECT/*x*/password/**/FROM/**/members", false, "comment_as_whitespace"},
		{"MySQL 版本注释", "SELECT * FROM t WHERE id = 1 UNION/*!50001SELECT*/ * FROM admin", false, "version_comment"},
		{"读文件", "SELECT LOAD_FILE('/etc/passwd')", false, "file_access"},
		{"无 WHERE 的删除", "DELETE FROM users", false, "unbounded_destructive"},
		{"有 WHERE 的删除", "DELETE FROM users WHERE id = 3", false, ""},
		{"只读模式拦写入", "UPDATE users SET a = 1 WHERE id = 1", true, "write_in_readonly"},
		{"非只读模式放行写入", "UPDATE users SET a = 1 WHERE id = 1", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rule, _ := checkStatic(c.sql, c.readOnly)
			if rule != c.wantRule {
				t.Fatalf("规则 = %q, 期望 %q", rule, c.wantRule)
			}
		})
	}
}

// noul 按真实响应的形状造一个 noul 答案。
func noul(p float64) map[string]any {
	return map[string]any{"type": "noul", "noul": p}
}

// scoreAnswer 按真实响应的形状造一个 score 答案：score 是连续值，
// legend 由服务端原样回带请求里的 criteria。
func scoreAnswer(score float64) map[string]any {
	legend := map[string]string{}
	for i, s := range riskLadder {
		legend[strconv.Itoa(i)] = s
	}
	return map[string]any{"type": "score", "score": score, "legend": legend, "confidence": 0.8}
}

// fakeJev 起一个假的 Decisions API，返回指定答案，用来验证判决逻辑。
func fakeJev(t *testing.T, answers map[string]any) *jev.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "dec_1", "model": jev.DefaultModel, "answers": answers,
		})
	}))
	t.Cleanup(srv.Close)

	c := jev.New("test-key")
	c.Endpoint = srv.URL
	return c
}

func TestJudgeFromModel(t *testing.T) {
	cases := []struct {
		name     string
		answers  map[string]any
		readOnly bool
		want     Decision
	}{
		{
			name: "低风险只读查询放行",
			answers: map[string]any{
				"is_injection":  map[string]any{"type": "noul", "noul": 0.02},
				"is_bulk_exfil": noul(0.02),
				"is_probe":      noul(0.02),
				"is_read_only":  map[string]any{"type": "noul", "noul": 0.99},
				"category":      map[string]any{"type": "choice", "choice": "read"},
				"risk":          map[string]any{"type": "score", "score": 0},
			},
			want: Allow,
		},
		{
			name: "高注入概率拒绝",
			answers: map[string]any{
				"is_injection":  map[string]any{"type": "noul", "noul": 0.91},
				"is_bulk_exfil": noul(0.02),
				"is_probe":      noul(0.02),
				"is_read_only":  map[string]any{"type": "noul", "noul": 0.8},
				"category":      map[string]any{"type": "choice", "choice": "read"},
				"risk":          scoreAnswer(1.0),
			},
			want: Block,
		},
		{
			name: "中等注入概率转人工",
			answers: map[string]any{
				"is_injection":  map[string]any{"type": "noul", "noul": 0.35},
				"is_bulk_exfil": noul(0.02),
				"is_probe":      noul(0.02),
				"is_read_only":  map[string]any{"type": "noul", "noul": 0.9},
				"category":      map[string]any{"type": "choice", "choice": "read"},
				"risk":          scoreAnswer(1.0),
			},
			want: Review,
		},
		{
			name: "最高风险档转人工",
			answers: map[string]any{
				"is_injection":  map[string]any{"type": "noul", "noul": 0.01},
				"is_bulk_exfil": noul(0.02),
				"is_probe":      noul(0.02),
				"is_read_only":  map[string]any{"type": "noul", "noul": 0.05},
				"category":      map[string]any{"type": "choice", "choice": "schema"},
				"risk":          scoreAnswer(1.9),
			},
			want: Review,
		},
		{
			name: "只读模式下写操作被拒",
			answers: map[string]any{
				"is_injection":  map[string]any{"type": "noul", "noul": 0.01},
				"is_bulk_exfil": noul(0.02),
				"is_probe":      noul(0.02),
				"is_read_only":  map[string]any{"type": "noul", "noul": 0.03},
				"category":      map[string]any{"type": "choice", "choice": "write"},
				"risk":          scoreAnswer(1.0),
			},
			readOnly: true,
			want:     Block,
		},
		{
			name: "批量拖敏感数据被拒",
			answers: map[string]any{
				"is_injection":  noul(0.03),
				"is_bulk_exfil": noul(0.88),
				"is_probe":      noul(0.05),
				"is_read_only":  noul(0.99),
				"category":      map[string]any{"type": "choice", "choice": "read"},
				"risk":          scoreAnswer(0.2),
			},
			want: Block,
		},
		{
			name: "数据库探测行为转复核",
			answers: map[string]any{
				"is_injection":  noul(0.10),
				"is_bulk_exfil": noul(0.02),
				"is_probe":      noul(0.82),
				"is_read_only":  noul(0.99),
				"category":      map[string]any{"type": "choice", "choice": "read"},
				"risk":          scoreAnswer(0.1),
			},
			want: Review,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := New(fakeJev(t, c.answers), Options{ReadOnly: c.readOnly})
			// 用一条本地规则挡不住的语句，确保判决确实来自模型。
			res, err := f.Check(context.Background(), "SELECT id FROM users WHERE id = 1")
			if err != nil {
				t.Fatal(err)
			}
			if res.Source != "jev" {
				t.Fatalf("来源 = %q, 期望 jev", res.Source)
			}
			if res.Decision != c.want {
				t.Fatalf("判决 = %s, 期望 %s（依据: %s）", res.Decision, c.want, res.Reason)
			}
		})
	}
}

func TestStaticShortCircuitsModel(t *testing.T) {
	// 本地规则命中时不应该再发请求，所以这里给一个会 t.Fatal 的服务端。
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("本地规则已命中，不应再调用 Jev")
	}))
	defer srv.Close()

	c := jev.New("test-key")
	c.Endpoint = srv.URL

	res, err := New(c, Options{}).Check(context.Background(), "SELECT 1; DROP TABLE users")
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != Block || res.Source != "static" {
		t.Fatalf("判决 = %s / 来源 = %s", res.Decision, res.Source)
	}
}

func TestOfflineMode(t *testing.T) {
	f := New(nil, Options{})
	res, err := f.Check(context.Background(), "SELECT id FROM users WHERE id = 1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != Allow || res.Source != "static" {
		t.Fatalf("判决 = %s / 来源 = %s", res.Decision, res.Source)
	}
}
