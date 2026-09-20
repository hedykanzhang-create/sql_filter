package filter

import (
	"regexp"
	"strings"
)

// 本文件处理「SQL 里带着敏感数据」这件事。
//
// 它要解决的不是安全策略问题，是**隐私泄露**问题：
// 过滤器会把完整 SQL 原文发给第三方 API 做语义判断。
// 如果语句里带着明文卡号、私钥、token，那这次调用本身就是一次外泄 ——
// 为了检查有没有人拖库，反而亲手把数据送出去了。
//
// 分两档处理，不能一刀切：
//   · 高危字面量（卡号/身份证/私钥/JWT/云密钥/明文口令）→ 本地直接拒绝，绝不外发
//   · 中危 PII（邮箱/手机号）→ 脱敏后再发。按邮箱查单个用户是正常业务，
//     一律拦掉会把正常功能一起干掉；而模型判的是语句结构，不需要真实值。

var (
	// 连续数字串，允许中间有空格或短横线（卡号常见写法）。
	digitRun = regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`)

	// 私钥 PEM 块。
	pemPrivateKey = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)

	// JWT：三段 base64url 用点连接，头部固定以 eyJ 开头。
	jwtToken = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)

	// 各家云厂商/平台的密钥前缀。前缀本身就是强特征，不用猜熵。
	vendorKey = regexp.MustCompile(`\b(sk-[A-Za-z0-9-]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|glpat-[A-Za-z0-9_-]{16,})`)

	// 口令列与字面量比较。
	passwordCompare = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|api_key|access_token|private_key)\s*(=|LIKE)\s*'([^']{3,})'`)

	// 哈希/密文的样子：纯十六进制，或 bcrypt/argon 这类带前缀的。
	hashLike = regexp.MustCompile(`^([0-9a-fA-F]{32,128}|\$2[aby]\$.+|\$argon2.+|\$6\$.+|[A-Za-z0-9+/]{43,}=*)$`)

	// 按敏感列名模糊搜库结构 —— 这是在画攻击地图。
	// 正常的结构查询按**表名**定位（table_name = 'orders'），
	// 不会拿 column_name LIKE '%password%' 去全库捞。
	schemaColumnHunt = regexp.MustCompile(`(?i)information_schema.*\bcolumn_name\b\s*(LIKE|REGEXP|RLIKE)\s*'[%_]*(password|passwd|pwd|secret|token|api_?key|credit|card|cvv|ssn|passport|bank|salt)`)

	// 中危 PII，脱敏而非拦截。
	emailLiteral = regexp.MustCompile(`'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'`)
	phoneLiteral = regexp.MustCompile(`'(?:\+?\d{1,3}[- ]?)?1[3-9]\d{9}'`)
)

// 数字串左边紧挨着的列名/字段名，用来判断这串数字到底是什么。
// 光看数字判不出来 —— 订单号也可能 4 开头且 Luhn 恰好通过（实测踩过）。
var leftContext = regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|LIKE|IN\s*\()\s*'?$`)

var (
	// 这些列名摆明了装的就是卡号/账号，命中即拦。
	cardishCol = regexp.MustCompile(`(?i)(card|pan|cc_?(no|num)|credit|debit|bank|acct|account_?(no|num))`)
	// 这些列名装的是业务流水号，长度和 Luhn 都可能碰巧撞上，放行。
	serialCol = regexp.MustCompile(`(?i)(order|trade|trace|track|invoice|receipt|serial|batch|ticket|seq|imei|iccid|barcode|sku)`)
)

// 卡号的发卡行前缀。只靠 Luhn 校验会误伤 —— 任意 16 位数字有约 1/10 概率碰巧通过，
// 订单号、雪花 ID 都可能中招。加上发卡行前缀后，误判概率降到可以忽略。
var cardPrefixes = []string{"4", "51", "52", "53", "54", "55", "34", "37", "6011", "65", "62", "35"}

// checkSensitiveLiteral 检查 SQL 里有没有绝不能外发的东西。
// 它必须在任何网络调用之前跑完 —— 这是这个函数存在的全部意义。
func checkSensitiveLiteral(sql string) (rule string, reason string) {
	switch {
	case pemPrivateKey.MatchString(sql):
		return "private_key_literal", "语句里带着 PEM 私钥明文"
	case jwtToken.MatchString(sql):
		return "jwt_literal", "语句里带着 JWT 令牌明文"
	case vendorKey.MatchString(sql):
		return "vendor_key_literal", "语句里带着云服务/平台的密钥明文（按前缀识别）"
	case schemaColumnHunt.MatchString(sql):
		return "schema_column_hunt", "按敏感列名模糊搜索库结构，正常的结构查询按表名定位而不是全库捞"
	}

	if m := passwordCompare.FindStringSubmatch(sql); m != nil {
		// 和哈希比对是正常的登录校验；和明文比对说明口令就是明文存的，
		// 这种值更不能外发。
		if !hashLike.MatchString(m[3]) {
			return "plaintext_credential", "语句里把口令/密钥与明文字面量比较（" + m[1] + "）"
		}
	}

	if n := findCardNumber(sql); n != "" {
		return "card_number_literal", "语句里带着疑似银行卡号明文（发卡行前缀 + Luhn 校验均通过）"
	}
	if findChinaID(sql) != "" {
		return "id_card_literal", "语句里带着疑似身份证号明文（长度 + 校验位均通过）"
	}
	return "", ""
}

// findCardNumber 找出疑似卡号：长度 13~19、发卡行前缀命中、Luhn 校验通过，三条全中才算。
func findCardNumber(sql string) string {
	for _, loc := range digitRun.FindAllStringIndex(sql, -1) {
		raw := sql[loc[0]:loc[1]]
		n := strings.NewReplacer(" ", "", "-", "").Replace(raw)
		if len(n) < 13 || len(n) > 19 || !hasCardPrefix(n) || !luhn(n) {
			continue
		}
		// 看这串数字左边挨着的是什么列。流水号类列放行，
		// 否则（卡号列，或看不出上下文）一律当卡号拦 —— 泄露卡号的代价远大于误拦一条查询。
		if col := columnBefore(sql, loc[0]); col != "" && serialCol.MatchString(col) && !cardishCol.MatchString(col) {
			continue
		}
		return n
	}
	return ""
}

// columnBefore 取数字串左边最近的那个标识符。取不到返回空串。
func columnBefore(sql string, at int) string {
	start := at - 48
	if start < 0 {
		start = 0
	}
	if m := leftContext.FindStringSubmatch(sql[start:at]); m != nil {
		return m[1]
	}
	return ""
}

func hasCardPrefix(n string) bool {
	for _, p := range cardPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// luhn 是卡号的校验算法：从右往左，偶数位翻倍（超过 9 就减 9），总和能被 10 整除。
func luhn(n string) bool {
	sum, double := 0, false
	for i := len(n) - 1; i >= 0; i-- {
		d := int(n[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

var idCardRun = regexp.MustCompile(`\b\d{17}[\dXx]\b`)

// 身份证校验位用的加权因子与余数映射，是国标 GB 11643 定死的。
var (
	idWeights = [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	idCheck   = [11]byte{'1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'}
)

func findChinaID(sql string) string {
	for _, s := range idCardRun.FindAllString(sql, -1) {
		sum := 0
		for i := 0; i < 17; i++ {
			sum += int(s[i]-'0') * idWeights[i]
		}
		want := idCheck[sum%11]
		got := s[17]
		if got == 'x' {
			got = 'X'
		}
		if got == want {
			return s
		}
	}
	return ""
}

// redact 把中危 PII 换成占位符，用于**发给第三方之前**。
//
// 模型判的是语句结构（查了哪个列、范围收没收敛），不需要真实值，
// 所以脱敏不影响判决，却能让真实邮箱和手机号不出本机。
func redact(sql string) (string, bool) {
	out := emailLiteral.ReplaceAllString(sql, "'<email>'")
	out = phoneLiteral.ReplaceAllString(out, "'<phone>'")
	return out, out != sql
}
