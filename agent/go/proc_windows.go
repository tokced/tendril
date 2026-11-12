//go:build windows

package main

import (
	"bytes"
	"context"
	"os/exec"
	"os/user"
	"runtime"
	"syscall"

	"golang.org/x/sys/windows"
	"time"
	"unsafe"
)

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject       = kernel32.NewProc("TerminateJobObject")
	procCloseHandle              = kernel32.NewProc("CloseHandle")
)

const (
	jobObjectExtendedLimitInformation = 9
	jobObjectLimitKillOnJobClose      = 0x2000
	createNoWindow                    = 0x08000000
)

type ioCounters struct {
	ReadOperationCount, WriteOperationCount, OtherOperationCount uint64
	ReadTransferCount, WriteTransferCount, OtherTransferCount    uint64
}

type jobBasicLimit struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobExtendedLimit struct {
	BasicLimitInformation jobBasicLimit
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

// newKillOnCloseJob 建一个「最后一个句柄关闭就杀掉全部进程」的 Job Object。
func newKillOnCloseJob() (syscall.Handle, error) {
	h, _, err := procCreateJobObjectW.Call(0, 0)
	if h == 0 {
		return 0, err
	}
	info := jobExtendedLimit{}
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	ok, _, err := procSetInformationJobObject.Call(h, jobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	if ok == 0 {
		procCloseHandle.Call(h)
		return 0, err
	}
	return syscall.Handle(h), nil
}

// runCommand：PowerShell / cmd 执行；整棵进程树由 Job Object 托管，取消或超时用
// TerminateJobObject 一次性结束全部子孙进程（比 taskkill /T 可靠）。
// 已知限制：进程在 Start 之后才加入 Job，极短窗口内的孙进程可能逃逸；
// 彻底解决要用 CREATE_SUSPENDED 先挂起再加 Job 再恢复，留待下一片。
func runCommand(ctx context.Context, command, shell string, timeoutS int, cwd string) result {
	if timeoutS <= 0 {
		timeoutS = 120
	}
	var cmd *exec.Cmd
	switch shell {
	case "", "powershell": // 未指定 → 平台默认
		// Windows PowerShell 默认按控制台代码页（zh-CN 是 936）输出；重定向时按 OEM 编码，
		// 母端拿到会变乱码。先把它切成 UTF-8，再执行用户命令。
		prefix := "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $OutputEncoding=[Console]::OutputEncoding; "
		cmd = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", prefix+command)
	case "cmd":
		// cmd 同理：先切 65001，再执行
		cmd = exec.Command("cmd", "/c", "chcp 65001 >nul & "+command)
	default:
		return result{OK: false, Error: "Windows 子端只支持 powershell / cmd，收到 " + shell}
	}
	if cwd != "" {
		cmd.Dir = cwd
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}

	job, jerr := newKillOnCloseJob()
	out := &capped{buflimit: execCap, buf: &bytes.Buffer{}}
	errBuf := &capped{buflimit: execCap, buf: &bytes.Buffer{}}
	cmd.Stdout, cmd.Stderr = out, errBuf

	started := time.Now()
	if err := cmd.Start(); err != nil {
		if jerr == nil {
			procCloseHandle.Call(uintptr(job)) // 否则每次启动失败都漏一个内核句柄
		}
		return result{OK: false, Error: "启动失败：" + err.Error()}
	}
	assigned := false
	if jerr == nil {
		// 坑：AssignProcessToJobObject 要的是「进程句柄」，传 PID 会失败（实测 Windows 11
		// 上一直 assign 失败，于是每次都退化成只杀外壳）。这里显式打开句柄再分配。
		const processAllAccess = 0x1F0FFF
		ph, oerr := syscall.OpenProcess(processAllAccess, false, uint32(cmd.Process.Pid))
		if oerr == nil {
			ok, _, _ := procAssignProcessToJobObject.Call(uintptr(job), uintptr(ph))
			assigned = ok != 0
			procCloseHandle.Call(uintptr(ph))
		}
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	timedOut, cancelled := false, false
	stop := func() {
		if jerr == nil {
			procTerminateJobObject.Call(uintptr(job), 1)
		}
		_ = cmd.Process.Kill() // Job 不可用时的兜底
	}
	select {
	case <-done:
	case <-ctx.Done():
		cancelled = true
		stop()
		<-done
	case <-time.After(time.Duration(timeoutS) * time.Second):
		timedOut = true
		stop()
		<-done
	}
	if jerr == nil {
		procCloseHandle.Call(uintptr(job))
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
		res.Error = "已按取消请求终止进程树（Job Object）"
	} else if timedOut {
		res.Error = "超时，已终止进程树（Job Object）"
	}
	if !assigned {
		// Job 没挂上时退化成只杀外壳：必须说出来，不能让调用方以为整棵树都结束了
		res.Warning = "未能把进程挂到 Job Object，进程树终止可能不完整"
	}
	return res
}

// identityLabel：user.Current() 在 LocalSystem 下返回 "WORKGROUP\ZEN-PC$"（机器账户），
// 对操作者毫无意义。用进程令牌的 SID 判定，SYSTEM 明确显示为 NT AUTHORITY\SYSTEM。
func identityLabel() string {
	tok := windows.GetCurrentProcessToken()
	if u, err := tok.GetTokenUser(); err == nil {
		if sid := u.User.Sid.String(); sid == "S-1-5-18" {
			return "NT AUTHORITY\\SYSTEM"
		} else if sid == "S-1-5-19" {
			return "NT AUTHORITY\\LOCAL SERVICE"
		} else if sid == "S-1-5-20" {
			return "NT AUTHORITY\\NETWORK SERVICE"
		}
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "?"
}

// osLabel：Windows 上先报架构；详细 build number 留到 M2 用注册表补。
func osLabel() string {
	return "Windows " + runtime.GOARCH
}
