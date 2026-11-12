//go:build !windows

package main

import (
	"context"
	"fmt"
	"os"
)

// 非 Windows 平台：服务宿主只存在于 Windows，这里给出明确说明而不是静默失败。

func isWindowsService() bool { return false }

func runService(loop func(context.Context)) int {
	fmt.Fprintln(os.Stderr, "服务模式只在 Windows 上有意义；Linux 请用 systemd 单元")
	return 2
}

func doInstall() int {
	fmt.Fprintln(os.Stderr, "服务安装只在 Windows 上支持；Linux 请用 systemd")
	return 2
}

func doUninstall() int {
	fmt.Fprintln(os.Stderr, "服务卸载只在 Windows 上支持")
	return 2
}

func doStatus() int {
	fmt.Fprintln(os.Stderr, "服务状态只在 Windows 上支持")
	return 2
}
