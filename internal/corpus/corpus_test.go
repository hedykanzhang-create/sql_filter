package corpus

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestGenerateHitsExactCount(t *testing.T) {
	// 生成器要真的产出 n 条 —— 早先某些家族模板空间不够，
	// 1000 条只产出 915 条，评测的分母就悄悄变了。
	for _, n := range []int{100, 1000} {
		cases := Generate(n, 20260920)
		if len(cases) != n {
			t.Fatalf("Generate(%d) 得到 %d 条", n, len(cases))
		}
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	a, b := Generate(200, 42), Generate(200, 42)
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("同一 seed 结果不一致，第 %d 条：%q vs %q", i, a[i].SQL, b[i].SQL)
		}
	}
}

func TestGenerateHasNoDuplicates(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Generate(1000, 20260920) {
		if seen[c.SQL] {
			t.Fatalf("重复语句: %s", c.SQL)
		}
		seen[c.SQL] = true
	}
}

// 语料质量守门测试。
//
// 三次踩坑换来的九项检查：
//
//	v1 所有列值混着随机取 → WHERE email = 999（类型错）
//	v2 按类型分组随机取   → SET name = 'active'、WHERE status = 'alice'（值域错）
//	v3 值绑定到列         → 仍有 ON b.amount = a.id、WHERE id = 1 AND id = 7（语义错）
//
// 这三类脏数据模型都会判成「不服务于真实业务目的」，探测概率被顶到 0.45~0.54，
// 于是标成 safe 的语料实际不 safe。**语料一脏，评测结论全部不可信** ——
// 所以这条测试守的不是代码，是整个评测的可信度。
func TestSafeCasesAreSemanticallySound(t *testing.T) {
	type check struct {
		what string
		re   *regexp.Regexp
	}
	checks := []check{
		{"字符串列比数字", regexp.MustCompile(`\b(name|email|status|title)\s*=\s*[\d.]+`)},
		{"数字列比字符串", regexp.MustCompile(`\b(id|user_id|shop_id)\s*=\s*'`)},
		{"name 列被赋状态值", regexp.MustCompile(`\bname\s*=\s*'(active|paid|pending|refunded|cancelled)'`)},
		{"status 列被赋人名", regexp.MustCompile(`status\s*=\s*'(Alice|Bob|Carol|Daniel)`)},
		{"email 列的值不是邮箱", regexp.MustCompile(`email\s*=\s*'[^'@]*'`)},
		{"JOIN 拿非外键列当主键", regexp.MustCompile(`ON b\.(amount|name|email|status|title|created_at|updated_at)\s*=\s*a\.id`)},
		{"自相矛盾条件（id 出现两次）", regexp.MustCompile(`\bid\s*=\s*\d+\s+AND\s+id\s*=`)},
	}
	// 重复列要比较两个捕获组是否相等，而 Go 的 RE2 不支持反向引用 —— 抓出来在代码里比。
	selCols := regexp.MustCompile(`SELECT (\w+), (\w+) FROM`)
	insCols := regexp.MustCompile(`INSERT INTO \w+ \((\w+), (\w+)\)`)

	for _, c := range Generate(1000, 20260920) {
		if c.Class != Safe {
			continue
		}
		for _, ck := range checks {
			if ck.re.MatchString(c.SQL) {
				t.Errorf("%s: %s", ck.what, c.SQL)
			}
		}
		if m := selCols.FindStringSubmatch(c.SQL); m != nil && m[1] == m[2] {
			t.Errorf("重复选同一列: %s", c.SQL)
		}
		if m := insCols.FindStringSubmatch(c.SQL); m != nil && m[1] == m[2] {
			t.Errorf("INSERT 列重复: %s", c.SQL)
		}
	}
}

func TestCSVRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cases.csv")
	want := Generate(50, 7)
	if err := WriteCSV(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("读回 %d 条，写入 %d 条", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 条不一致:\n写入 %+v\n读回 %+v", i, want[i], got[i])
		}
	}
}

func TestReadCSVRejectsBadClass(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.csv")
	os.WriteFile(path, []byte("id,family,class,sql\n1,x,unknown,SELECT 1\n"), 0o644)
	if _, err := ReadCSV(path); err == nil {
		t.Fatal("class 非法时应报错")
	}
}
