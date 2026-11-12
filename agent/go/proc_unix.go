//go:build !windows

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// runCommand 在 POSIX 上把整棵进程树一起结束：新进程组 + 组级 SIGKILL。
func runCommand(ctx context.Context, command, shell string, timeoutS int, cwd string) result {
	if shell != "" && shell != "bash" {
		return result{OK: false, Error: "POSIX 子端只支持 bash，收到 " + shell}
	}
	// shell 为空 = 用平台默认（POSIX 就是 bash）
	if timeoutS <= 0 {
		timeoutS = 120
	}
	started := time.Now()
	cmd := exec.Command("bash", "-c", command)
	if cwd != "" {
		cmd.Dir = cwd
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out := &capped{buflimit: execCap, buf: &bytes.Buffer{}}
	errBuf := &capped{buflimit: execCap, buf: &bytes.Buffer{}}
	cmd.Stdout, cmd.Stderr = out, errBuf
	if err := cmd.Start(); err != nil {
		return result{OK: false, Error: "启动失败：" + err.Error()}
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	timedOut, cancelled := false, false
	select {
	case <-done:
	case <-ctx.Done():
		cancelled = true
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
	case <-time.After(time.Duration(timeoutS) * time.Second):
		timedOut = true
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
	}
	elapsed := time.Since(started).Seconds()
	code := cmd.ProcessState.ExitCode()
	res := result{OK: !timedOut && !cancelled, TimedOut: timedOut, Cancelled: cancelled,
		Stdout: out.buf.String(), Stderr: errBuf.buf.String(),
		// 真实字节数在 written 里；buf.Len() 是被截断后的长度，拿它当大小就是谎报
		OutBytes: out.written, ErrBytes: errBuf.written, Elapsed: elapsed,
		OutCut: out.written > execCap, ErrCut: errBuf.written > execCap}
	res.ExitCode = &code
	commandOK := code == 0 && !timedOut && !cancelled
	res.CommandOK = &commandOK
	if cancelled {
		res.Error = "已按取消请求终止进程组"
	} else if timedOut {
		res.Error = "超时，已终止进程组"
	}
	return res
}

// osLabel 上报真实内核版本，避免与其他子端口径不一致。
func osLabel() string {
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		return fmt.Sprintf("Linux %s %s", strings.TrimSpace(string(b)), runtime.GOARCH)
	}
	return fmt.Sprintf("Linux %s", runtime.GOARCH)
}

// identityLabel：POSIX 直接报登录名
func identityLabel() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "?"
}
