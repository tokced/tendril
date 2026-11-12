//go:build !windows

package main

import (
	"fmt"
	"os"
)

// 非 Windows 平台没有"用户级安装"这个概念（也没有 UAC），直接说明。
func runInstallUser() int {
	fmt.Fprintln(os.Stderr, "用户级安装仅适用于 Windows；Linux 直接把二进制放到任意目录前台运行即可")
	return 2
}

func runUninstallUser() int {
	fmt.Fprintln(os.Stderr, "用户级安装仅适用于 Windows")
	return 2
}
