package filter

import (
	"strings"
	"testing"
)

func TestSensitiveLiteralBlocks(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want string // 期望命中的规则名，空串表示应放行
	}{
		// —— 必须拦：这些值一旦外发就是泄露 ——
		{"卡号", "SELECT * FROM payments WHERE card_no = '4111111111111111'", "card_number_literal"},
		{"带空格的卡号", "SELECT * FROM p WHERE pan = '4111 1111 1111 1111'", "card_number_literal"},
		{"无上下文的卡号", "SELECT * FROM t WHERE x = '4111111111111111'", "card_number_literal"},
		{"身份证", "INSERT INTO users (id_no) VALUES ('11010519491231002X')", "id_card_literal"},
		{"明文口令", "SELECT * FROM users WHERE password = 'hunter2'", "plaintext_credential"},
		{"云厂商密钥", "UPDATE cfg SET v = 'sk-or-v1-abcdefghijklmnop12345'", "vendor_key_literal"},
		{"AWS 密钥", "UPDATE cfg SET v = 'AKIAIOSFODNN7EXAMPLE'", "vendor_key_literal"},
		{"JWT", "SELECT * FROM t WHERE tk = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij'", "jwt_literal"},
		{"私钥", "INSERT INTO k (v) VALUES ('-----BEGIN RSA PRIVATE KEY-----MIIE')", "private_key_literal"},
		{"按敏感列名搜库结构", "SELECT table_name FROM information_schema.columns WHERE column_name LIKE '%password%'", "schema_column_hunt"},

		// —— 必须放行：误拦这些会直接干掉正常业务 ——
		// 订单号可能恰好 4 开头且 Luhn 通过（实测踩过），靠左边的列名区分。
		{"订单号恰好像卡号", "SELECT id FROM orders WHERE order_no = '4532015112830366'", ""},
		{"交易流水号", "SELECT id FROM t WHERE trade_no = '4111111111111111'", ""},
		// 和哈希比对是正常登录校验，和明文比对才是问题。
		{"口令哈希比对", "SELECT * FROM users WHERE password_hash = '5f4dcc3b5aa765d61d8327deb882cf99'", ""},
		{"bcrypt 比对", "SELECT * FROM u WHERE password = '$2y$10$abcdefghijklmnopqrstuv'", ""},
		// 正常的结构查询按表名定位，不是拿敏感列名全库捞。
		{"按表名查结构", "SELECT column_name FROM information_schema.columns WHERE table_name = 'orders'", ""},
		{"普通金额", "SELECT * FROM orders WHERE amount = 1299.00", ""},
		{"普通自增 ID", "SELECT * FROM orders WHERE id = 1234567890123456", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rule, _ := checkSensitiveLiteral(c.sql)
			if rule != c.want {
				t.Fatalf("规则 = %q, 期望 %q", rule, c.want)
			}
		})
	}
}

// 脱敏发生在发往第三方之前，所以它必须真的把值换掉，
// 同时保留语句结构 —— 模型靠结构判断，换掉值不影响判决。
func TestRedact(t *testing.T) {
	cases := []struct {
		sql        string
		wantChange bool
		mustGone   string
	}{
		{"SELECT id FROM users WHERE email = 'alice@example.com'", true, "alice@example.com"},
		{"SELECT id FROM users WHERE phone = '13812345678'", true, "13812345678"},
		{"SELECT id FROM users WHERE id = 42", false, ""},
	}
	for _, c := range cases {
		out, changed := redact(c.sql)
		if changed != c.wantChange {
			t.Fatalf("changed = %v, 期望 %v（%s）", changed, c.wantChange, c.sql)
		}
		if c.mustGone != "" && strings.Contains(out, c.mustGone) {
			t.Fatalf("脱敏后仍含 %q: %s", c.mustGone, out)
		}
		// 列名必须留着，否则模型判不出查的是什么
		if c.wantChange && !strings.Contains(out, "FROM users WHERE") {
			t.Fatalf("脱敏破坏了语句结构: %s", out)
		}
	}
}

// 敏感检查必须跑在所有其他规则之前 —— 它管的是「能不能离开本机」，
// 排在后面就可能先被别的规则放行、然后原样发出去。
func TestSensitiveCheckRunsFirst(t *testing.T) {
	// 这条既含卡号、又含恒真条件；应该报卡号而不是恒真。
	sql := "SELECT * FROM p WHERE card = '4111111111111111' OR 1=1"
	rule, _ := checkStatic(sql, false)
	if rule != "card_number_literal" {
		t.Fatalf("规则 = %q, 期望 card_number_literal（敏感检查应优先）", rule)
	}
}
