//go:build windows

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "TendrilAgent"

func isWindowsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// runService 把主循环交给 SCM 托管：Stop/Shutdown 时取消 ctx 并退出。
func runService(loop func(context.Context)) int {
	h := &svcHandler{loop: loop}
	if err := svc.Run(serviceName, h); err != nil {
		logf("服务启动失败：%v", err)
		return 1
	}
	return 0
}

type svcHandler struct{ loop func(context.Context) }

func (h *svcHandler) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.loop(ctx)
	}()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			cancel()
			select {
			case <-done:
			case <-time.After(20 * time.Second):
				logf("主循环未在 20s 内退出，强制结束")
			}
			return false, 0
		}
	}
	cancel()
	return false, 0
}

// doInstall：写配置 + 把可执行文件复制到 ProgramData + 注册并启动服务。
func doInstall() int {
	if *invite == "" {
		fmt.Fprintln(os.Stderr, "安装服务需要 --invite（里面带母端地址、设备密钥和证书）")
		return 2
	}
	inv, err := parseInvite(*invite)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if len(roots) == 0 {
		fmt.Fprintln(os.Stderr, "安装服务需要至少一个 --root（服务身份能访问的目录）")
		return 2
	}
	cfg := &settings{
		Mother: inv.URL, Device: inv.Device, Secret: inv.Secret, CertPEM: inv.Cert,
		Roots: []string(roots), AllowExec: *allowExec, HostMode: "service", TLS: inv.TLS,
		Addrs: inv.Addrs,
	}
	dir, err := dataDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "创建目录失败（需要管理员）：", err)
		return 2
	}
	cfgPath, err := saveConfig(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "写配置失败（需要管理员）：", err)
		return 2
	}

	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	target := filepath.Join(dir, "tendril-agent.exe")
	if err := copyFile(self, target); err != nil {
		fmt.Fprintln(os.Stderr, "复制可执行文件失败：", err)
		return 2
	}

	m, err := mgr.Connect()
	if err != nil {
		fmt.Fprintln(os.Stderr, "连接服务管理器失败（需要管理员）：", err)
		return 2
	}
	defer m.Disconnect()

	if existing, err := m.OpenService(serviceName); err == nil {
		existing.Close()
		fmt.Fprintf(os.Stderr, "服务 %s 已存在；先跑 --uninstall-service 再装\n", serviceName)
		return 2
	}
	s, err := m.CreateService(serviceName, target, mgr.Config{
		DisplayName: "Tendril Agent",
		Description: "Tendril 设备子端：开机即向母端保持连接，执行授权的文件与命令操作。",
		StartType:   mgr.StartAutomatic,
	}, "--service")
	if err != nil {
		fmt.Fprintln(os.Stderr, "创建服务失败：", err)
		return 2
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "服务已创建但启动失败：", err)
		return 2
	}

	fmt.Println("已安装并启动：")
	fmt.Printf("  服务名   %s（自动启动，账户 LocalSystem）\n", serviceName)
	fmt.Printf("  程序     %s\n", target)
	fmt.Printf("  配置     %s\n", cfgPath)
	fmt.Printf("  设备     %s → %s\n", cfg.Device, cfg.Mother)
	fmt.Printf("  授权目录 %v\n", cfg.Roots)
	fmt.Printf("  命令执行 %v（本机确认；未开启时母端无法执行命令）\n", cfg.AllowExec)
	fmt.Println("  卸载     tendril-agent.exe --uninstall-service")
	return 0
}

func doUninstall() int {
	m, err := mgr.Connect()
	if err != nil {
		fmt.Fprintln(os.Stderr, "连接服务管理器失败（需要管理员）：", err)
		return 2
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "服务 %s 不存在，无需卸载\n", serviceName)
		return 0
	}
	defer s.Close()
	if _, err := s.Control(svc.Stop); err == nil {
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			st, err := s.Query()
			if err != nil || st.State == svc.Stopped {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
	if err := s.Delete(); err != nil {
		fmt.Fprintln(os.Stderr, "删除服务失败：", err)
		return 2
	}
	dir, _ := dataDir()
	fmt.Printf("服务 %s 已停止并删除\n", serviceName)
	fmt.Printf("程序与配置目录仍在：%s（含 agent.json；确认不再需要后可手工删除）\n", dir)
	return 0
}

func doStatus() int {
	m, err := mgr.Connect()
	if err != nil {
		fmt.Fprintln(os.Stderr, "连接服务管理器失败：", err)
		return 2
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		fmt.Printf("服务 %s 未安装\n", serviceName)
		return 1
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		fmt.Fprintln(os.Stderr, "查询失败：", err)
		return 2
	}
	fmt.Printf("服务 %s：state=%v pid=%d\n", serviceName, st.State, st.ProcessId)
	return 0
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
