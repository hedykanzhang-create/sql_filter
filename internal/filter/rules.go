package filter

import "regexp"

// 本地硬规则：不花钱、不联网，先挡掉一眼就有问题的语句。
// 它只负责「确定有问题」的场景；拿不准的一律交给 Jev 做语义判断。
//
// 这里刻意用正则而不是完整 SQL 解析器：目标是快速兜底，不是做语法分析。
// 真正的语义判断（这条 DELETE 到底危不危险）是 Jev 的活儿。

type staticRule struct {
	name   string
	reason string
	re     *regexp.Regexp
}

// alwaysBlocked 是无论什么模式都直接拒绝的模式。
var alwaysBlocked = []staticRule{
	{
		name:   "stacked_query",
		reason: "单次请求里塞了多条语句（分号拼接），典型的堆叠注入手法",
		re:     regexp.MustCompile(`;\s*\S`),
	},
	{
		name:   "comment_truncation",
		reason: "引号后紧跟注释，把后半段条件截断 —— 这是闭合字符串再注释掉校验的经典手法",
		// 匹配的是「引号紧挨注释」，不是「出现了注释」。
		// 合法 SQL 里 -- 前面一定有空格（WHERE status = 'paid' -- 说明），
		// 注入则要紧贴引号闭合字符串（user = 'admin'--），中间容不下空格。
		re: regexp.MustCompile(`['"]\)?(--|#)`),
	},
	{
		name:   "version_comment",
		reason: "MySQL 版本注释 /*!...*/ 里的内容会被真正执行，正常业务 SQL 不会用它",
		re:     regexp.MustCompile(`/\*!`),
	},
	{
		name:   "comment_as_whitespace",
		reason: "用注释切开关键字（如 UN/**/ION），专门用来绕过基于关键字的过滤",
		// \w/\* 或 \*/\w：注释紧贴单词字符，说明它被当成分隔符而不是说明文字。
		// 正常的 /* 月度对账 */ SELECT 两侧有空格，不会命中。
		re: regexp.MustCompile(`\w/\*|\*/\w`),
	},
	{
		name:   "file_access",
		reason: "试图读写服务器文件（LOAD_FILE / INTO OUTFILE / INTO DUMPFILE）",
		re:     regexp.MustCompile(`(?i)\b(load_file|into\s+(out|dump)file|load\s+data\s+infile)\b`),
	},
	{
		name:   "shell_exec",
		reason: "试图执行系统命令或调用扩展存储过程",
		re:     regexp.MustCompile(`(?i)\b(xp_cmdshell|sys_exec|sys_eval|pg_read_file|copy\s+\w+\s+from\s+program)\b`),
	},
}

// tautologyPair 抓 OR 两侧的字面量（数字或带引号的串）。
// Go 的正则引擎是 RE2，不支持反向引用，所以「两边是否相等」只能抓出来再比，
// 这样反而更准：能同时认出 OR 1=1 和 OR 'a'='a'。
var tautologyPair = regexp.MustCompile(`(?i)\bor\b\s+('[^']*'|"[^"]*"|\d+)\s*=\s*('[^']*'|"[^"]*"|\d+)`)

// hasTautology 判断是否存在恒真条件（OR 两边是同一个字面量）。
func hasTautology(sql string) bool {
	for _, m := range tautologyPair.FindAllStringSubmatch(sql, -1) {
		if unquote(m[1]) == unquote(m[2]) {
			return true
		}
	}
	return false
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// writeOps 是会改数据或改结构的操作，只在只读模式下被拒。
var writeOps = regexp.MustCompile(
	`(?i)^\s*(insert|update|delete|drop|truncate|alter|create|replace|grant|revoke|rename|merge|call|set|lock)\b`)

// destructiveHead 匹配 DELETE / UPDATE 开头，whereClause 匹配 WHERE。
// RE2 没有否定前瞻，所以「有没有 WHERE」拆成两个正则在代码里组合判断。
var (
	destructiveHead = regexp.MustCompile(`(?i)^\s*(delete\s+from|update)\b`)
	whereClause     = regexp.MustCompile(`(?i)\bwhere\b`)
)

// isUnboundedDestructive 判断是不是没有 WHERE 的 DELETE / UPDATE ——
// 这种语句一条就能干掉整张表。
func isUnboundedDestructive(sql string) bool {
	return destructiveHead.MatchString(sql) && !whereClause.MatchString(sql)
}

// checkStatic 跑一遍本地规则。返回空 reason 表示本地这关过了。
func checkStatic(sql string, readOnly bool) (rule string, reason string) {
	// 敏感字面量排在最前面。它和别的规则不是一类问题：
	// 别的规则判「这条语句该不该执行」，它判「这条语句能不能离开本机」。
	// 一旦漏过去就会被原样发给第三方 API，那时候再拦已经晚了。
	if rule, reason := checkSensitiveLiteral(sql); reason != "" {
		return rule, reason
	}
	for _, r := range alwaysBlocked {
		if r.re.MatchString(sql) {
			return r.name, r.reason
		}
	}
	if hasTautology(sql) {
		return "tautology", "存在恒真条件（如 OR 1=1），会让 WHERE 形同虚设"
	}
	if readOnly && writeOps.MatchString(sql) {
		return "write_in_readonly", "只读模式下不允许写入或变更结构的语句"
	}
	if isUnboundedDestructive(sql) {
		return "unbounded_destructive", "DELETE / UPDATE 没有 WHERE，会作用于整张表"
	}
	return "", ""
}
