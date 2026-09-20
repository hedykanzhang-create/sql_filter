// Package filter 实现 SQL 过滤器：本地硬规则兜底 + Jev 语义判断。
package filter

import (
	"context"
	"fmt"
	"strings"

	"github.com/channelwill/sql_filter/internal/jev"
)

// Decision 是过滤结论。
type Decision string

const (
	Allow  Decision = "ALLOW"  // 放行
	Review Decision = "REVIEW" // 拿不准，交给人看
	Block  Decision = "BLOCK"  // 拒绝
)

// Result 是一次过滤的完整结果，含判决依据，方便审计。
type Result struct {
	SQL      string   `json:"sql"`
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`

	// Source 是判决来自哪一层：static（本地规则）或 jev（模型）。
	Source string `json:"source"`

	// 以下是 Jev 的原始答案，Source == "static" 时为零值。
	//
	// 这里刻意不加 omitempty：概率为 0 必须显式出现在输出里。
	// 早先加了 omitempty，解析失败导致的 0 在 JSON 里整个字段消失，
	// 看上去像「模型没回答这道题」，实际是「判定为绝对安全」—— 两者差了十万八千里。
	InjectionProbability float64 `json:"injection_probability"`
	ReadOnlyProbability  float64 `json:"read_only_probability"`
	Category             string  `json:"category"`
	RiskLevel            string  `json:"risk_level"`
	RiskScore            float64 `json:"risk_score"`

	// BulkExfilProbability / ProbeProbability 是后补的两个维度。
	// 起因：用真实 payload 语料评测时发现，只问「是不是注入」会漏掉两类东西 ——
	//   · SELECT api_key, secret FROM shops —— 语法干净的整表拖密钥，不是注入，是越权
	//   · SELECT 0x457578 / SELECT SLEEP(10) —— 孤立看无害，实为注入前的探测指纹
	// 尺子上没有的刻度，量多少遍都量不出来。
	BulkExfilProbability float64 `json:"bulk_exfil_probability"`
	ProbeProbability     float64 `json:"probe_probability"`
	Confidence           float64 `json:"risk_confidence"`

	// Cost 是这次判定花掉的美元，便于核算。
	Cost float64 `json:"cost"`

	// Redacted 表示发给第三方之前对语句做过脱敏（邮箱/手机号换成了占位符）。
	Redacted bool `json:"redacted"`
}

// highRiskScore 是转人工的风险线。
//
// score 类型返回的不是档位下标，而是各档概率的加权平均（连续值），
// 取值范围 [0, len(riskLadder)-1]。1.5 是第 1 档与第 2 档的中点，
// 即「模型认为这条语句更偏向最高危那一档」时才拦下来。
const highRiskScore = 1.5

// riskLadder 是 score 类型问题的有序标尺，下标即风险等级。
// 服务端会把它原样回带在 legend 里，所以读文案用 Answer.Label() 而不是这个变量。
var riskLadder = []string{
	"只读查询，作用范围明确，无副作用",
	"会改数据但范围有限，属于常规业务操作",
	"影响面大或不可逆（批量删改、结构变更、权限调整）",
}

// Options 控制过滤器的严格程度。
type Options struct {
	// ReadOnly 为 true 时，任何写操作都拒绝。
	ReadOnly bool
	// InjectionThreshold：注入概率超过它直接拒绝，默认 0.5。
	InjectionThreshold float64
	// ReviewThreshold：注入概率超过它转人工，默认 0.2。
	ReviewThreshold float64

	// ProbeThreshold：探测行为概率超过它转人工，默认 0.6。
	//
	// 两个结论都来自 1079 条语料的实测，不是拍脑袋：
	//
	// ① 探测只转复核、不直接拒绝。概率密集落在 0.40~0.55 这条模糊带里 ——
	//    真探针（SELECT IF(1=1,..)、id = 5-1）拿 0.40~0.45，
	//    而合法的健康检查 SELECT SLEEP(0) 拿 0.54，数值上根本分不开。
	//    「像在试探」是弱信号，不足以支撑拒绝。
	//
	// ② 0.6 是信噪比的分水岭。实测分布：
	//      区间 [0.35,0.60)  safe 108 条 vs 危险 28 条  —— 噪音全堆在这
	//      区间 [0.60,1.00]  safe   6 条 vs 危险 185 条 —— 干净
	//    线压到 0.35 会把 11% 的正常查询拖进复核，运维会先被烦死。
	//
	// 代价要说清楚：孤立的探针（单条 id = 5-1）会从这条线下面漏过去。
	// 这是结构性的 —— 探测的本质是一连串请求的模式，不是单条语句的特征，
	// 一次只看一条 SQL 的过滤器先天判不准。要真正覆盖它得在调用方按会话聚合。
	ProbeThreshold float64
}

func (o Options) withDefaults() Options {
	if o.InjectionThreshold <= 0 {
		o.InjectionThreshold = 0.5
	}
	if o.ReviewThreshold <= 0 {
		o.ReviewThreshold = 0.2
	}
	if o.ProbeThreshold <= 0 {
		o.ProbeThreshold = 0.6
	}
	return o
}

// Filter 是 SQL 过滤器。
type Filter struct {
	client *jev.Client
	opts   Options
}

// New 构造过滤器。client 为 nil 时退化成「只有本地规则」的离线模式。
func New(client *jev.Client, opts Options) *Filter {
	return &Filter{client: client, opts: opts.withDefaults()}
}

// questions 是喂给 Jev 的题目集合。四道题各管一个维度，互不重叠：
// 是不是注入 / 是不是只读 / 属于哪类操作 / 风险多高。
func questions() map[string]jev.Question {
	return map[string]jev.Question{
		"is_injection": {
			Type:         jev.TypeNoul,
			Instructions: "这条 SQL 是否包含注入攻击特征或试图绕过既定的查询边界？",
			Criteria: map[string]string{
				"true":  "存在恒真条件、注释截断、堆叠语句、UNION 拼接外部数据、探测系统表等绕过意图",
				"false": "是一条意图正常、边界清晰的业务语句",
			},
		},
		"is_read_only": {
			Type:         jev.TypeNoul,
			Instructions: "这条 SQL 是否只读取数据、不产生任何写入或结构变更？",
			Criteria: map[string]string{
				"true":  "仅 SELECT / SHOW / EXPLAIN 等读取操作",
				"false": "会写入数据、变更结构、调整权限或执行存储过程",
			},
		},
		"is_bulk_exfil": {
			Type: jev.TypeNoul,
			Instructions: "这条 SQL 是否在批量导出凭据、密钥或个人敏感信息，" +
				"而不是为某个具体业务操作取用单条数据？",
			Criteria: map[string]string{
				"true": "成批读取密码、口令散列、API 密钥、令牌、银行卡号等敏感字段，" +
					"或读取数据库自身的账号表（mysql.user、pg_shadow）；" +
					"典型特征是没有把范围收敛到单个主体",
				"false": "不涉及敏感字段，或虽然读了敏感字段但已收敛到单条记录" +
					"（例如登录校验时按邮箱取一个人的口令散列）",
			},
		},
		"is_probe": {
			Type:         jev.TypeNoul,
			Instructions: "这条 SQL 是否不服务于任何真实业务目的，而是在试探数据库？",
			Criteria: map[string]string{
				"true": "用于摸清数据库的版本、字符编码、表结构、权限或响应延时，" +
					"常见形态是常量运算、编码转换函数、延时函数、逐字符比较；" +
					"这类语句是攻击前的侦察",
				"false": "服务于明确的业务目的，或是常规连接健康检查（如 SELECT 1、SELECT SLEEP(0)）",
			},
		},
		"category": {
			Type:         jev.TypeChoice,
			Instructions: "这条 SQL 属于哪一类操作？",
			Criteria: map[string]string{
				"read":   "查询数据：SELECT、SHOW、EXPLAIN",
				"write":  "修改数据：INSERT、UPDATE、DELETE、MERGE",
				"schema": "变更结构：CREATE、ALTER、DROP、TRUNCATE",
				"admin":  "权限与系统操作：GRANT、REVOKE、SET、系统函数、存储过程",
			},
		},
		"risk": {
			Type:         jev.TypeScore,
			Instructions: "在生产库上执行这条 SQL 的风险有多高？",
			Criteria:     riskLadder,
		},
	}
}

// Check 过滤一条 SQL。先跑本地规则，命中就直接拒绝、不再调用模型；
// 本地放行才发给 Jev 做语义判断。
func (f *Filter) Check(ctx context.Context, sql string) (*Result, error) {
	sql = strings.TrimSpace(sql)
	if sql == "" {
		return nil, fmt.Errorf("filter: empty sql")
	}

	res := &Result{SQL: sql}

	if rule, reason := checkStatic(sql, f.opts.ReadOnly); reason != "" {
		res.Decision, res.Source = Block, "static"
		res.Reason = fmt.Sprintf("[%s] %s", rule, reason)
		return res, nil
	}

	if f.client == nil {
		res.Decision, res.Source = Allow, "static"
		res.Reason = "本地规则未命中（离线模式，未做语义判断）"
		return res, nil
	}

	// 发出去之前脱敏。高危字面量已经在 checkStatic 里拦掉了，
	// 这里处理的是邮箱、手机号这类「业务上合法、但没必要外发」的值。
	payload, redacted := redact(sql)
	res.Redacted = redacted

	resp, err := f.client.Decide(ctx, payload, questions())
	if err != nil {
		return nil, err
	}

	res.Source = "jev"
	res.Cost = resp.Usage.Cost

	// 每道题都检查「有没有答上」。取不到就整条判定失败，绝不用零值兜底 ——
	// 注入概率的零值是「绝对安全」，拿它当默认值等于解析一坏就全线放行。
	if res.InjectionProbability, err = resp.Noul("is_injection"); err != nil {
		return nil, err
	}
	if res.ReadOnlyProbability, err = resp.Noul("is_read_only"); err != nil {
		return nil, err
	}
	if res.BulkExfilProbability, err = resp.Noul("is_bulk_exfil"); err != nil {
		return nil, err
	}
	if res.ProbeProbability, err = resp.Noul("is_probe"); err != nil {
		return nil, err
	}
	if res.Category, err = resp.Choice("category"); err != nil {
		return nil, err
	}
	risk, err := resp.Score("risk")
	if err != nil {
		return nil, err
	}
	res.RiskScore = risk.Score
	res.RiskLevel = risk.Label()
	res.Confidence = risk.Confidence

	f.judge(res)
	return res, nil
}

// judge 把模型给的概率翻译成放行/复核/拒绝，判定顺序即优先级。
func (f *Filter) judge(res *Result) {
	switch {
	case res.InjectionProbability >= f.opts.InjectionThreshold:
		res.Decision = Block
		res.Reason = fmt.Sprintf("注入嫌疑概率 %.2f，超过拒绝阈值 %.2f",
			res.InjectionProbability, f.opts.InjectionThreshold)

	case res.BulkExfilProbability >= f.opts.InjectionThreshold:
		res.Decision = Block
		res.Reason = fmt.Sprintf("批量导出敏感数据的概率 %.2f，超过拒绝阈值 %.2f",
			res.BulkExfilProbability, f.opts.InjectionThreshold)

	case f.opts.ReadOnly && res.ReadOnlyProbability < 0.5:
		res.Decision = Block
		res.Reason = fmt.Sprintf("只读模式：判定为只读的概率仅 %.2f（类别 %s）",
			res.ReadOnlyProbability, res.Category)

	case res.ProbeProbability >= f.opts.ProbeThreshold:
		res.Decision = Review
		res.Reason = fmt.Sprintf("探测行为概率 %.2f 超过复核线 %.2f，需人工确认用途",
			res.ProbeProbability, f.opts.ProbeThreshold)

	case res.RiskScore >= highRiskScore:
		res.Decision = Review
		res.Reason = fmt.Sprintf("风险位置 %.2f 已越过高风险线 %.1f（%s），需人工确认",
			res.RiskScore, highRiskScore, res.RiskLevel)

	case res.InjectionProbability >= f.opts.ReviewThreshold:
		res.Decision = Review
		res.Reason = fmt.Sprintf("注入嫌疑概率 %.2f，介于复核阈值 %.2f 与拒绝阈值 %.2f 之间",
			res.InjectionProbability, f.opts.ReviewThreshold, f.opts.InjectionThreshold)

	default:
		res.Decision = Allow
		res.Reason = fmt.Sprintf("类别 %s，风险 %s；注入 %.2f / 拖库 %.2f / 探测 %.2f 均低于阈值",
			res.Category, res.RiskLevel,
			res.InjectionProbability, res.BulkExfilProbability, res.ProbeProbability)
	}
}
