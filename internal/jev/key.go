package jev

import (
	"os"
	"path/filepath"
	"strings"
)

// ResolveKey 按优先级找 OpenRouter API key：先环境变量，再配置文件。
//
// 加配置文件兜底，是因为通过别的程序（比如另一个 AI 工具）调用时，
// 它起的往往是非交互 shell，根本不 source ~/.zshrc，环境变量就丢了。
// 把 key 落到一个固定文件，谁调都读得到，不依赖 shell 配置。
//
// 放在 jev 包里而非某个 main，是为了让所有命令（sql_filter / bench / …）
// 共用同一套解析，不必各写一份。
func ResolveKey() string {
	if k := strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY")); k != "" {
		return k
	}
	if b, err := os.ReadFile(KeyFilePath()); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}

// KeyFilePath 返回 key 文件路径：~/.config/sql_filter/key。
func KeyFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".config", "sql_filter", "key")
	}
	return filepath.Join(home, ".config", "sql_filter", "key")
}
