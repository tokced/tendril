//go:build windows

package main

// 免管理员的用户级安装：不建服务、不写 ProgramData、不触发 UAC。
//
// 代价（安装输出里也会打印）：没有服务 = 只有该用户登录后才在线；
// 命令以当前用户权限执行，而不是 SYSTEM。
//
// 自启用 HKCU\...\Run —— 纯用户级注册表，普通用户可写，不会弹提权框。

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	userRunKey  = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	userRunName = "TendrilAgent"
)

func userDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local")
	}
	return filepath.Join(base, "Tendril")
}

func selfExe() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		return real
	}
	return p
}

func runInstallUser() int {
	if *invite == "" {
		fmt.Fprintln(os.Stderr, "用户级安装需要 --invite（内含母端地址、设备密钥与证书）")
		return 2
	}
	inv, err := parseInvite(*invite)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	dir := userDir()
	rootsList := []string(roots)
	if len(rootsList) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "无法确定用户目录：", err)
			return 2
		}
		rootsList = []string{home}
	}

	cfg := &settings{Mother: inv.URL, Device: inv.Device, Secret: inv.Secret, CertPEM: inv.Cert,
		Roots: rootsList, AllowExec: *allowExec, HostMode: "user", TLS: inv.TLS,
		Addrs: inv.Addrs} // 入口地址必须落盘，否则重启后又只能靠 DNS 抽签
	dirOverride := dir
	dataDirOverride = dirOverride
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "创建目录失败：", err)
		return 2
	}
	if _, err := saveConfig(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "写配置失败：", err)
		return 2
	}

	self := selfExe()
	target := filepath.Join(dir, "tendril-agent.exe")
	if self != "" && filepath.Clean(self) != filepath.Clean(target) {
		if err := copyFile(self, target); err != nil {
			fmt.Fprintln(os.Stderr, "复制程序失败：", err)
			return 2
		}
	}
	// 自启：用 --from-config 直接跑主循环，不碰 SCM
	if err := regAdd(userRunKey, userRunName,
		fmt.Sprintf(`"%s" --from-config --data-dir "%s"`, target, dir)); err != nil {
		fmt.Fprintln(os.Stderr, "注册自启失败：", err)
		return 2
	}
	cmd := exec.Command(target, "--from-config", "--data-dir", dir)
	// 先尝试脱离父进程的 Job（如果有人从"会被整树回收"的环境里发起安装，
	// 例如别的编排器；普通用户直接跑时这一步无所谓）。
	const (
		createNoWindow   = 0x08000000
		breakawayFromJob = 0x01000000
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow | breakawayFromJob, HideWindow: true}
	if err := cmd.Start(); err != nil {
		cmd = exec.Command(target, "--from-config", "--data-dir", dir)
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow, HideWindow: true}
		if err := cmd.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "启动失败：", err)
			return 2
		}
	}
	// 记下自己拉起的 PID：卸载时只能杀这一个，绝不能按镜像名杀——
	// 服务模式的进程同样叫 tendril-agent.exe，按名字杀会把正式服务一起干掉。
	os.WriteFile(filepath.Join(dir, "agent.pid"), []byte(fmt.Sprintf("%d\n", cmd.Process.Pid)), 0o600)
	cmd.Process.Release()

	fmt.Printf("已安装为用户级（无需管理员，未创建服务）：\n")
	fmt.Printf("  程序    %s\n", target)
	fmt.Printf("  配置    %s\n", filepath.Join(dir, "agent.json"))
	fmt.Printf("  设备    %s → %s\n", cfg.Device, cfg.Mother)
	fmt.Printf("  授权目录 %v\n", cfg.Roots)
	fmt.Printf("  命令执行 %v（本机确认；未开启时母端无法执行命令）\n", cfg.AllowExec)
	fmt.Printf("  自启    %s\\%s（仅当前用户，登录后生效）\n", userRunKey, userRunName)
	fmt.Printf("  在线条件 该用户已登录；未登录时离线\n")
	fmt.Printf("  卸载    \"%s\" --uninstall-user\n", target)
	return 0
}

func runUninstallUser() int {
	dir := userDir()
	// 如果正在运行的就是这个目录里的 exe，先把自己复制到临时目录再执行卸载：
	// Windows 不允许删除正在运行的镜像文件，直接删必然 Access denied。
	if self := selfExe(); self != "" && strings.HasPrefix(strings.ToLower(self), strings.ToLower(dir)+strings.ToLower(string(os.PathSeparator))) {
		tmp := filepath.Join(os.TempDir(), "tendril-uninstall.exe")
		if err := copyFile(self, tmp); err != nil {
			fmt.Fprintln(os.Stderr, "准备卸载程序失败：", err)
			return 2
		}
		cmd := exec.Command(tmp, "--uninstall-user")
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000, HideWindow: true}
		if err := cmd.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "启动卸载程序失败：", err)
			return 2
		}
		return 0
	}
	_ = exec.Command("reg.exe", "delete", userRunKey, "/v", userRunName, "/f").Run()
	// 只停本目录启动的那一个进程（pid 文件 + 路径双重确认）
	if raw, err := os.ReadFile(filepath.Join(dir, "agent.pid")); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && pid > 0 {
			if exePath, err := processPath(pid); err == nil && strings.HasPrefix(strings.ToLower(exePath), strings.ToLower(dir)) {
				_ = exec.Command("taskkill.exe", "/PID", strconv.Itoa(pid), "/F").Run()
			}
		}
	}
	var err error
	for i := 0; i < 10; i++ {
		if err = os.RemoveAll(dir); err == nil {
			break
		}
		sleepMS(400)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "删除目录失败：", err)
		return 2
	}
	fmt.Printf("已卸载用户级安装：%s\n", dir)
	return 0
}

// processPath 查询某个 PID 的可执行文件路径（用于确认"这个进程属于我"）。
func sleepMS(ms int) {
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

func processPath(pid int) (string, error) {
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("(Get-CimInstance Win32_Process -Filter \"ProcessId=%d\").ExecutablePath", pid)).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func regAdd(key, name, value string) error {
	out, err := exec.Command("reg.exe", "add", key, "/v", name, "/t", "REG_SZ", "/d", value, "/f").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(out))
	}
	return nil
}
