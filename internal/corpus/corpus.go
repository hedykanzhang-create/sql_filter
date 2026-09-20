// Package corpus 生成带标注的 SQL 测试语料。
//
// 只生成语句没有意义 —— 跑完只会得到一堆输出、无从判断对错。
// 所以每条语句都带一个 Class（期望的安全等级），评测时拿它和过滤器的判决对账。
package corpus

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
)

// Class 是一条语句**应该**被怎么对待。
//
// 刻意不直接标「期望判决等于 ALLOW/REVIEW/BLOCK」：
// 危险语句被拦成 BLOCK 还是 REVIEW 都算拦住了，强行要求某一个具体值
// 会把「策略偏保守」误判成「过滤器有 bug」。
type Class string

const (
	// Safe 是正常业务语句，期望放行。判成 BLOCK 即误杀。
	Safe Class = "safe"
	// Risky 是合法但影响面大的语句（改结构、调权限、无界删改），
	// 期望至少拦下来复核，放行即失职。
	Risky Class = "risky"
	// Hostile 是带攻击意图的语句，期望直接拒绝，放行就是漏杀。
	Hostile Class = "hostile"
)

// Case 是一条语料。
type Case struct {
	ID     int    `json:"id"`
	SQL    string `json:"sql"`
	Class  Class  `json:"class"`
	Family string `json:"family"` // 细分类型，用于定位是哪一类拖了后腿
}

// 语料的零件库。用组合而不是硬写 1000 条，是为了在有限模板下拿到足够的多样性。
//
// 值**绑定到列**，不是按类型随机配。两次踩坑换来的：
//
//	第一版所有列和值混着随机取 → WHERE email = 999（类型都不对）
//	第二版按类型分组随机取     → SET name = 'active'、WHERE status = 'alice'
//	                             （类型对了，值域还是错的）
//
// 两种脏数据模型都会判成「不服务于真实业务目的」，于是标成 safe 的语料实际不 safe，
// 评测的分母就烂掉了。所以每个列自带值池，取列即取值。
var (
	tables  = []string{"users", "orders", "products", "payments", "sessions", "coupons", "shops", "refunds", "reviews", "carts"}
	secrets = []string{"password", "password_hash", "api_key", "token", "secret", "credit_card"}

	// colValues 是每个列的合法取值。键的集合就是可用列的全集。
	colValues = map[string][]string{
		"id":         {"1", "42", "100", "317", "2048", "9912"},
		"user_id":    {"3", "88", "501", "1204"},
		"shop_id":    {"11", "27", "364", "902"},
		"amount":     {"19.99", "100.00", "250.50", "8.00", "1299.00"},
		"name":       {"'Alice Chen'", "'Bob Lee'", "'Carol Wu'", "'Daniel Ma'"},
		"email":      {"'alice@example.com'", "'bob@shop.io'", "'carol@mail.com'"},
		"status":     {"'active'", "'paid'", "'pending'", "'refunded'", "'cancelled'"},
		"title":      {"'Summer Sale'", "'Welcome Coupon'", "'VIP Upgrade'", "'Free Shipping'"},
		"created_at": {"'2026-01-01'", "'2026-06-30'", "'2026-09-01'"},
		"updated_at": {"'2025-12-31'", "'2026-03-15'", "'2026-08-20'"},
	}

	// 下面几组是 colValues 的键的子集，按用途切分。
	allCols  = []string{"id", "user_id", "shop_id", "amount", "name", "email", "status", "title", "created_at", "updated_at"}
	dateCols = []string{"created_at", "updated_at"}
	// fkCols 是真正能当外键指向另一张表主键的列。
	// 早先 JOIN 的外键从所有数字列里随机取，造出 ON b.amount = a.id —— 拿金额当主键。
	fkCols = []string{"user_id", "shop_id"}
	// setCols 是业务上真会被 UPDATE 改的列（id 之类主键不在内）。
	setCols = []string{"status", "title", "amount", "updated_at"}

	limits  = []string{"10", "20", "50", "100"}
	privs   = []string{"ALL PRIVILEGES", "SELECT", "INSERT", "UPDATE", "DELETE", "ALTER", "DROP"}
	dbUsers = []string{"app", "readonly", "etl", "analytics", "ops", "migration"}
	sysVars = []string{"max_connections", "wait_timeout", "long_query_time",
		"innodb_buffer_pool_size", "sql_mode", "foreign_key_checks"}
	sysVals = []string{"0", "1", "64", "500", "3600"}
)

// family 是一类语料的生成器。
type family struct {
	name  string
	class Class
	gen   func(r *rand.Rand, t generator) string
}

// generator 把随机取零件的动作收成一个小接口，模板里写起来短。
type generator struct{ r *rand.Rand }

func (g generator) table() string  { return pick(g.r, tables) }
func (g generator) col() string    { return pick(g.r, allCols) }
func (g generator) secret() string { return pick(g.r, secrets) }
func (g generator) limit() string  { return pick(g.r, limits) }
func (g generator) num() string    { return pick(g.r, colValues["id"]) }
func (g generator) fk() string     { return pick(g.r, fkCols) }
func (g generator) priv() string   { return pick(g.r, privs) }
func (g generator) dbUser() string { return pick(g.r, dbUsers) }
func (g generator) sysVar() string { return pick(g.r, sysVars) }
func (g generator) sysVal() string { return pick(g.r, sysVals) }

// val 返回该列的一个合法取值。列和值必须一起取 —— 分开取就会退化成
// SET name = 'active' 这种类型对、值域错的胡话。
func (g generator) val(col string) string { return pick(g.r, colValues[col]) }

// cond 返回一个条件，可排除若干列，用来避免 WHERE id = 100 AND id = 999
// 这类自相矛盾（恒假）的条件 —— 它是合法 SQL，但没有任何业务含义。
func (g generator) cond(exclude ...string) string {
	col := g.pickColExcept(exclude)
	if contains(dateCols, col) {
		return fmt.Sprintf("%s >= %s", col, g.val(col))
	}
	return fmt.Sprintf("%s = %s", col, g.val(col))
}

// assign 返回一个 SET 子句，只改业务列，不动主键。
func (g generator) assign() string {
	col := pick(g.r, setCols)
	return fmt.Sprintf("%s = %s", col, g.val(col))
}

func (g generator) pickColExcept(exclude []string) string {
	for i := 0; i < 30; i++ {
		if c := g.col(); !contains(exclude, c) {
			return c
		}
	}
	return "status"
}

// twoCols 取两个**不重复**的列，避免生成 SELECT name, name 这种废话。
func (g generator) twoCols() (string, string) {
	a := g.col()
	for i := 0; i < 30; i++ {
		if b := g.col(); b != a {
			return a, b
		}
	}
	return a, "id"
}

func pick(r *rand.Rand, xs []string) string { return xs[r.Intn(len(xs))] }

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func total(groups [][]string) int {
	n := 0
	for _, g := range groups {
		n += len(g)
	}
	return n
}

// families 覆盖八类场景：三类安全、三类高危、三类攻击。
var families = buildFamilies()

func buildFamilies() []family {
	return []family{
		{"read_simple", Safe, func(r *rand.Rand, t generator) string {
			a, b := t.twoCols()
			return fmt.Sprintf("SELECT %s, %s FROM %s WHERE %s LIMIT %s",
				a, b, t.table(), t.cond(), t.limit())
		}},
		{"read_join_agg", Safe, func(r *rand.Rand, t generator) string {
			a, b := t.table(), t.table()
			col := t.col()
			// 外键只从 fkCols 取：ON b.amount = a.id 是拿金额当主键，业务上讲不通。
			return fmt.Sprintf(
				"SELECT a.%s, COUNT(b.id) AS cnt FROM %s a JOIN %s b ON b.%s = a.id "+
					"WHERE a.%s GROUP BY a.%s ORDER BY cnt DESC LIMIT 50",
				col, a, b, t.fk(), t.cond(), col)
		}},
		{"write_bounded", Safe, func(r *rand.Rand, t generator) string {
			switch r.Intn(3) {
			case 0:
				return fmt.Sprintf("UPDATE %s SET %s WHERE id = %s",
					t.table(), t.assign(), t.num())
			case 1:
				c1, c2 := t.twoCols()
				return fmt.Sprintf("INSERT INTO %s (%s, %s) VALUES (%s, %s)",
					t.table(), c1, c2, t.val(c1), t.val(c2))
			default:
				// 排除 id：WHERE id = 100 AND id = 999 是恒假条件，没有业务含义。
				return fmt.Sprintf("DELETE FROM %s WHERE id = %s AND %s",
					t.table(), t.num(), t.cond("id"))
			}
		}},
		{"schema_change", Risky, func(r *rand.Rand, t generator) string {
			switch r.Intn(4) {
			case 0:
				return fmt.Sprintf("ALTER TABLE %s DROP COLUMN %s", t.table(), t.col())
			case 1:
				return fmt.Sprintf("DROP TABLE %s", t.table())
			case 2:
				return fmt.Sprintf("TRUNCATE TABLE %s", t.table())
			default:
				return fmt.Sprintf("ALTER TABLE %s MODIFY COLUMN %s VARCHAR(32) NOT NULL",
					t.table(), t.col())
			}
		}},
		{"admin_op", Risky, func(r *rand.Rand, t generator) string {
			switch r.Intn(3) {
			case 0:
				return fmt.Sprintf("GRANT %s ON %s.* TO '%s'@'%%'", t.priv(), t.table(), t.dbUser())
			case 1:
				return fmt.Sprintf("SET GLOBAL %s = %s", t.sysVar(), t.sysVal())
			default:
				return fmt.Sprintf("REVOKE %s ON %s FROM '%s'@'%%'", t.priv(), t.table(), t.dbUser())
			}
		}},
		{"unbounded_write", Risky, func(r *rand.Rand, t generator) string {
			if r.Intn(2) == 0 {
				return fmt.Sprintf("DELETE FROM %s", t.table())
			}
			return fmt.Sprintf("UPDATE %s SET %s", t.table(), t.assign())
		}},
		{"inject_classic", Hostile, func(r *rand.Rand, t generator) string {
			switch r.Intn(4) {
			case 0:
				return fmt.Sprintf("SELECT * FROM %s WHERE %s OR 1=1", t.table(), t.cond())
			case 1:
				return fmt.Sprintf("SELECT * FROM %s WHERE id = %s -- AND is_delete = 0", t.table(), t.num())
			case 2:
				return fmt.Sprintf("SELECT %s FROM %s WHERE id = %s; DROP TABLE %s",
					t.col(), t.table(), t.num(), t.table())
			default:
				return fmt.Sprintf("SELECT * FROM %s WHERE %s OR 'a'='a'", t.table(), t.cond())
			}
		}},
		{"inject_union", Hostile, func(r *rand.Rand, t generator) string {
			a, b := t.twoCols()
			return fmt.Sprintf("SELECT %s, %s FROM %s WHERE id = %s UNION SELECT %s, %s FROM users",
				a, b, t.table(), t.num(), t.secret(), t.secret())
		}},
		{"inject_subtle", Hostile, func(r *rand.Rand, t generator) string {
			switch r.Intn(4) {
			case 0: // 盲注：按字符逐位试探
				return fmt.Sprintf(
					"SELECT * FROM %s WHERE id = %s AND SUBSTRING((SELECT %s FROM users LIMIT 1), %s, 1) = 'a'",
					t.table(), t.num(), t.secret(), t.num())
			case 1: // 时间盲注
				return fmt.Sprintf("SELECT * FROM %s WHERE id = %s AND IF(1=1, SLEEP(5), 0)",
					t.table(), t.num())
			case 2: // 翻库结构找敏感字段
				return fmt.Sprintf(
					"SELECT table_name, column_name FROM information_schema.columns WHERE column_name LIKE '%%%s%%'",
					t.secret())
			default: // 整表拖密码
				return fmt.Sprintf("SELECT %s, %s FROM users", t.col(), t.secret())
			}
		}},
	}
}

// Generate 生成 n 条去重后的语料，按家族均分。
// seed 固定则结果可复现 —— 评测要能复跑，不然没法对比两次改动的效果。
func Generate(n int, seed int64) []Case {
	r := rand.New(rand.NewSource(seed))
	t := generator{r}

	seen := map[string]bool{}
	byFamily := make([][]string, len(families))

	// 第一轮：每个家族各自生成到目标条数。
	// attempts 兜底，防止模板空间不够时死循环。
	per := n / len(families)
	for i, f := range families {
		want := per
		if i < n%len(families) {
			want++ // 除不尽的余数分给前几个家族
		}
		for attempts := 0; len(byFamily[i]) < want && attempts < want*200; attempts++ {
			sql := f.gen(r, t)
			if sql == "" || seen[sql] {
				continue
			}
			seen[sql] = true
			byFamily[i] = append(byFamily[i], sql)
		}
	}

	// 第二轮补齐：有的家族模板空间就是比别的小（比如 admin_op 只有那么几种写法），
	// 第一轮产不满时总数会缺口。这里轮流找还能产出新语句的家族补足，
	// 让 n 是个实数而不是上限 —— 说好 1000 条就得真有 1000 条。
	for total(byFamily) < n {
		progressed := false
		for i, f := range families {
			if total(byFamily) >= n {
				break
			}
			for attempts := 0; attempts < 200; attempts++ {
				sql := f.gen(r, t)
				if sql == "" || seen[sql] {
					continue
				}
				seen[sql] = true
				byFamily[i] = append(byFamily[i], sql)
				progressed = true
				break
			}
		}
		if !progressed {
			break // 所有家族都榨干了，如实返回现有条数
		}
	}

	var out []Case
	for i, f := range families {
		for _, sql := range byFamily[i] {
			out = append(out, Case{SQL: sql, Class: f.class, Family: f.name})
		}
	}

	// 打散顺序，避免同类连续命中时看不出规律；再统一编号。
	r.Shuffle(len(out), func(a, b int) { out[a], out[b] = out[b], out[a] })
	for i := range out {
		out[i].ID = i + 1
	}
	return out
}

// Families 返回所有家族名，供报表按家族分组。
func Families() []string {
	var names []string
	for _, f := range families {
		names = append(names, f.name)
	}
	sort.Strings(names)
	return names
}

// Summary 给出语料的构成概览，跑之前先确认分布合理。
func Summary(cases []Case) string {
	byClass := map[Class]int{}
	byFamily := map[string]int{}
	for _, c := range cases {
		byClass[c.Class]++
		byFamily[c.Family]++
	}
	var b strings.Builder
	fmt.Fprintf(&b, "共 %d 条：safe %d / risky %d / hostile %d\n",
		len(cases), byClass[Safe], byClass[Risky], byClass[Hostile])
	for _, name := range Families() {
		fmt.Fprintf(&b, "  %-16s %d\n", name, byFamily[name])
	}
	return b.String()
}
