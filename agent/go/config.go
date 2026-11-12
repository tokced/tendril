package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// dataDirOverride 由 --data-dir 设置；用户级安装用它把数据放到 %LOCALAPPDATA%，
// 避免写 ProgramData（那需要管理员）。
var dataDirOverride string

// 配置目录：服务以 LocalSystem 运行，%APPDATA% 会落到 systemprofile，
// 所以必须用 %ProgramData%（实测：SYSTEM 的 USERPROFILE 是 system32\config\systemprofile）。
func dataDir() (string, error) {
	if dataDirOverride != "" {
		return dataDirOverride, nil
	}
	if d := os.Getenv("ProgramData"); d != "" {
		return filepath.Join(d, "Tendril"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "tendril"), nil
}

func configPath() (string, error) {
	d, err := dataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "agent.json"), nil
}

func loadConfig() (*settings, error) {
	p, err := configPath()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("读不到 %s（先跑 --install-service）：%w", p, err)
	}
	var s settings
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("配置损坏 %s：%w", p, err)
	}
	if s.Mother == "" || s.Device == "" || s.Secret == "" {
		return nil, fmt.Errorf("配置缺少必要字段：%s", p)
	}
	return &s, nil
}

func saveConfig(s *settings) (string, error) {
	d, err := dataDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(d, "agent.json")
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		return "", err
	}
	return p, nil
}
