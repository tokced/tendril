// Tendril 子端（Go）：与 Python 参考实现语义一致，用于投放 Windows/Linux。
//
// 三件事：连母端、执行、回传事实。不调用模型、不保存上下文、不自主规划。
// M2 增补：TLS 固定证书校验（--ca）、执行期收取消（__cancel__）、Windows Job Object。
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"
)

const execCap = 256 * 1024
const maxList = 500

var (
	mother = flag.String("mother", "https://127.0.0.1:8911", "母端地址")
	device = flag.String("device", "", "设备 id")
	secret = flag.String("secret", "", "设备密钥")
	caFile = flag.String("ca", "", "母端证书路径（https 必填，固定校验）")
	invite = flag.String("invite", "", "TENDRIL1:... 邀请串（替代 mother/device/secret/ca）")
	roots  multiFlag
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// logOut 默认 stderr；用户级安装没有控制台，失败时看不到任何东西，
// 所以 --from-config 启动时同时写一份文件日志。
var logOut io.Writer = os.Stderr

func logf(format string, args ...any) {
	fmt.Fprintf(logOut, "[tendril-agent] "+format+"\n", args...)
}

type task struct {
	TaskID  string          `json:"task_id"`
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}

type entry struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Size    int64  `json:"size"`
	Mtime   int64  `json:"mtime"`
	Symlink bool   `json:"symlink"`
}

type result struct {
	OK        bool    `json:"ok"`
	CommandOK *bool   `json:"command_ok,omitempty"`
	ExitCode  *int    `json:"exit_code,omitempty"`
	TimedOut  bool    `json:"timed_out,omitempty"`
	Cancelled bool    `json:"cancelled,omitempty"`
	Stdout    string  `json:"stdout,omitempty"`
	Stderr    string  `json:"stderr,omitempty"`
	OutCut    bool    `json:"stdout_truncated,omitempty"`
	ErrCut    bool    `json:"stderr_truncated,omitempty"`
	OutBytes  int     `json:"stdout_bytes,omitempty"`
	ErrBytes  int     `json:"stderr_bytes,omitempty"`
	Elapsed   float64 `json:"elapsed_s,omitempty"`
	Error     string  `json:"error,omitempty"`
	Warning   string  `json:"warning,omitempty"`

	Path       string  `json:"path,omitempty"`
	Type       string  `json:"type,omitempty"`
	From       string  `json:"from,omitempty"`
	Size       int64   `json:"size"`
	Offset     int64   `json:"offset,omitempty"`
	NextOffset int64   `json:"next_offset,omitempty"`
	Truncated  bool    `json:"truncated,omitempty"`
	Binary     bool    `json:"binary,omitempty"`
	Encoding   *string `json:"encoding,omitempty"`
	Content    string  `json:"content,omitempty"`
	ContentB64 string  `json:"content_base64,omitempty"`
	Sha256     string  `json:"sha256,omitempty"`
	Entries    []entry `json:"entries,omitempty"`
}

var client *http.Client

var caPEM []byte // 邀请里带的证书直接放内存，不落盘

func buildClient() error {
	tr := &http.Transport{}
	if !strings.HasPrefix(*mother, "https://") {
		client = &http.Client{Transport: tr, Timeout: 70 * time.Second}
		return nil
	}

	host := strings.Split(strings.Split(strings.TrimPrefix(*mother, "https://"), "/")[0], ":")
	serverName := host[0]
	port := "443"
	if len(host) == 2 {
		port = host[1]
	}

	tlsCfg := &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
	if !tlsSystem {
		// 固定证书模式：只信邀请里带（或 --ca 指定）的那张证书
		if len(caPEM) == 0 {
			if *caFile == "" {
				return fmt.Errorf("母端是 https，必须用 --ca 指定母端证书（固定校验，不允许跳过）")
			}
			pem, err := os.ReadFile(*caFile)
			if err != nil {
				return fmt.Errorf("读不到 --ca 证书：%w", err)
			}
			caPEM = pem
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return fmt.Errorf("--ca 不是有效 PEM 证书")
		}
		tlsCfg.RootCAs = pool
	}

	if len(entryAddrs) > 0 {
		// 域名后面的入口 IP 未必都可达（实测 Funnel 三选一），按列表轮换拨号，
		// 完全不复用 DNS 结果；TLS 仍按主机名校验，所以不是"跳过校验"。
		dialer := &net.Dialer{Timeout: 12 * time.Second}
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			var lastErr error
			for i := 0; i < len(entryAddrs); i++ {
				idx := int(atomic.AddUint32(&addrCursor, 1)) % len(entryAddrs)
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(entryAddrs[idx], port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("没有可用的入口地址")
			}
			return nil, lastErr
		}
		tr.DisableKeepAlives = true // 入口切换后旧连接会挂在坏节点上
	}

	tr.TLSClientConfig = tlsCfg
	client = &http.Client{Transport: tr, Timeout: 70 * time.Second}
	return nil
}

func call(path string, body any) (int, []byte, error) {
	return callCtx(context.Background(), path, body)
}

// callCtx 让请求可以被取消：服务 Stop 时不必再等一个 25s 的长轮询返回。
func callCtx(ctx context.Context, path string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(*mother, "/")+path, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tendril-Device-Id", *device)
	req.Header.Set("X-Tendril-Device-Key", *secret)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, data, nil
}

// os.Root：句柄级路径限制，拒绝 ../ 与重解析点/符号链接逃逸。
type confined struct{ roots []string }

func (c confined) open(raw string) (*os.Root, string, error) {
	if raw == "" || strings.ContainsRune(raw, 0) {
		return nil, "", fmt.Errorf("路径为空或含空字符")
	}
	if len(c.roots) == 0 {
		return nil, "", fmt.Errorf("此设备未授权任何目录")
	}
	if !filepath.IsAbs(raw) {
		return nil, "", fmt.Errorf("只接受绝对路径")
	}
	clean := filepath.Clean(raw)
	for _, root := range c.roots {
		root = filepath.Clean(root)
		rel, err := filepath.Rel(root, clean)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		r, err := os.OpenRoot(root)
		if err != nil {
			return nil, "", err
		}
		return r, rel, nil
	}
	return nil, "", fmt.Errorf("路径不在授权目录内：%s", raw)
}

func fsList(c confined, p struct {
	Path string `json:"path"`
}) result {
	root, rel, err := c.open(p.Path)
	if err != nil {
		return result{OK: false, Error: err.Error()}
	}
	defer root.Close()
	// 注意：rel 为 "." 表示「根目录本身」，必须原样传给 os.Root。
	// 早先把它改成空字符串，os.Root 直接报 openat : empty path —— 列根目录必失败。
	f, err := root.Open(rel)
	if err != nil {
		return result{OK: false, Error: "打不开：" + err.Error()}
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.IsDir() {
		return result{OK: false, Error: "不是目录"}
	}
	items, err := f.ReadDir(-1)
	if err != nil {
		return result{OK: false, Error: err.Error()}
	}
	entries := make([]entry, 0, len(items))
	for _, it := range items {
		if len(entries) >= maxList {
			break
		}
		info, err := it.Info()
		if err != nil {
			continue
		}
		kind := "file"
		if it.IsDir() {
			kind = "dir"
		}
		entries = append(entries, entry{Name: it.Name(), Type: kind, Size: info.Size(),
			Mtime: info.ModTime().Unix(), Symlink: it.Type()&os.ModeSymlink != 0})
	}
	sort.Slice(entries, func(i, j int) bool {
		if (entries[i].Type == "dir") != (entries[j].Type == "dir") {
			return entries[i].Type == "dir"
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	return result{OK: true, Path: filepath.Clean(p.Path), Entries: entries, Truncated: len(entries) >= maxList}
}

func fsRead(c confined, p struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset"`
	Limit  int    `json:"limit"`
	Raw    bool   `json:"raw"`
}) result {
	root, rel, err := c.open(p.Path)
	if err != nil {
		return result{OK: false, Error: err.Error()}
	}
	defer root.Close()
	f, err := root.Open(rel)
	if err != nil {
		return result{OK: false, Error: "打不开：" + err.Error()}
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		return result{OK: false, Error: "不是文件"}
	}
	// 纵深防御：母端已限制 1 MiB，子端自己再夹一次，别让一个坏请求申请超大缓冲
	if p.Limit <= 0 || p.Limit > 1024*1024 {
		p.Limit = 65536
	}
	if p.Offset < 0 {
		return result{OK: false, Error: "offset 不能为负"}
	}
	if _, err := f.Seek(p.Offset, io.SeekStart); err != nil {
		return result{OK: false, Error: err.Error()}
	}
	buf := make([]byte, p.Limit)
	n, _ := io.ReadFull(f, buf)
	chunk := buf[:n]
	// Windows 的 [Text.Encoding]::UTF8 会写 BOM；把它当文件内容返回，模型会看到开头一个怪字符
	bom := len(chunk) >= 3 && chunk[0] == 0xEF && chunk[1] == 0xBB && chunk[2] == 0xBF
	if bom {
		chunk = chunk[3:]
	}
	// 判定二进制要看文件头，不能只看本次返回的分片：
	// limit=100 时对随机数据几乎永远判定不出 NUL，会被当成文本返回乱码。
	probe := make([]byte, 8192)
	if _, err := f.Seek(0, io.SeekStart); err == nil {
		if n, _ := io.ReadFull(f, probe); n > 0 {
			probe = probe[:n]
		} else {
			probe = probe[:0]
		}
		if _, err := f.Seek(int64(min(int(p.Offset), int(st.Size()))), io.SeekStart); err != nil {
			return result{OK: false, Error: err.Error()}
		}
	}
	// UTF-16 文本天然充满 NUL 字节，只按 NUL 判定会把它当二进制退回 base64。
	// 有 BOM 就按文本处理，并在返回前转成 UTF-8。
	utf16le := len(probe) >= 2 && probe[0] == 0xFF && probe[1] == 0xFE
	utf16be := len(probe) >= 2 && probe[0] == 0xFE && probe[1] == 0xFF
	binary := p.Raw || (!utf16le && !utf16be && bytes.IndexByte(probe, 0) >= 0)
	next := p.Offset + int64(n)
	r := result{OK: true, Path: filepath.Clean(p.Path), Size: st.Size(), Offset: p.Offset,
		NextOffset: next, Truncated: next < st.Size(), Binary: binary}
	if binary {
		r.ContentB64 = base64.StdEncoding.EncodeToString(chunk)
	} else if utf16le || utf16be {
		body := chunk
		if p.Offset == 0 && len(body) >= 2 {
			body = body[2:] // 去掉 BOM，否则第一个字符是 U+FEFF
		}
		enc := "utf-16-le"
		if utf16be {
			enc = "utf-16-be"
		}
		r.Encoding = &enc
		r.Content = utf16ToUTF8(body, utf16le)
	} else {
		enc := "utf-8"
		if bom {
			enc = "utf-8-sig"
		}
		r.Encoding = &enc
		r.Content = string(chunk)
	}
	return r
}

// utf16ToUTF8 手工转换，不引第三方依赖。分片边界上若切断代理对会出现一个替换字符，
// 这比整个文件被当成二进制要有用得多。
func utf16ToUTF8(b []byte, le bool) string {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		if le {
			units = append(units, uint16(b[i])|uint16(b[i+1])<<8)
		} else {
			units = append(units, uint16(b[i])<<8|uint16(b[i+1]))
		}
	}
	return string(utf16.Decode(units))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func handle(c confined, t task, ctx context.Context) result {
	switch t.Kind {
	case "exec":
		if !allowExecLocal {
			return result{OK: false, Error: "本机未授权命令执行（安装服务时未加 --allow-exec）"}
		}
		var p struct {
			Command  string `json:"command"`
			Shell    string `json:"shell"`
			TimeoutS int    `json:"timeout_s"`
			Cwd      string `json:"cwd"`
		}
		if err := json.Unmarshal(t.Payload, &p); err != nil {
			return result{OK: false, Error: "payload 解析失败"}
		}
		return runCommand(ctx, p.Command, p.Shell, p.TimeoutS, p.Cwd)
	case "fs.list":
		var p struct {
			Path string `json:"path"`
		}
		json.Unmarshal(t.Payload, &p)
		return fsList(c, p)
	case "fs.mkdir":
		var p struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(t.Payload, &p); err != nil {
			return result{OK: false, Error: "payload 解析失败"}
		}
		return fsMkdir(c, p)
	case "fs.rename":
		var p struct {
			From string `json:"from"`
			To   string `json:"to"`
		}
		if err := json.Unmarshal(t.Payload, &p); err != nil {
			return result{OK: false, Error: "payload 解析失败"}
		}
		return fsRename(c, p)
	case "fs.remove":
		var p struct {
			Path      string `json:"path"`
			Recursive bool   `json:"recursive"`
		}
		if err := json.Unmarshal(t.Payload, &p); err != nil {
			return result{OK: false, Error: "payload 解析失败"}
		}
		return fsRemove(c, p)
	case "fs.write":
		var p writeReq
		if err := json.Unmarshal(t.Payload, &p); err != nil {
			return result{OK: false, Error: "payload 解析失败"}
		}
		return fsWrite(c, p)
	case "fs.read":
		var p struct {
			Path   string `json:"path"`
			Offset int64  `json:"offset"`
			Limit  int    `json:"limit"`
			Raw    bool   `json:"raw"`
		}
		json.Unmarshal(t.Payload, &p)
		return fsRead(c, p)
	}
	return result{OK: false, Error: "未知任务类型 " + t.Kind}
}

type invitePayload struct {
	V      int      `json:"v"`
	URL    string   `json:"url"`
	TLS    string   `json:"tls"`
	Addrs  []string `json:"addrs"`
	Device string   `json:"device"`
	Secret string   `json:"secret"`
	Cert   string   `json:"cert"`
	FP     string   `json:"fp"`
	Exp    int64    `json:"exp"`
}

// parseInvite 解析 TENDRIL1:<base64> 邀请，并校验到期与证书指纹。
func parseInvite(raw string) (*invitePayload, error) {
	text := strings.TrimSpace(raw)
	if strings.HasPrefix(text, "TENDRIL1:") {
		text = strings.TrimPrefix(text, "TENDRIL1:")
	} else if b, err := os.ReadFile(text); err == nil {
		text = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(b)), "TENDRIL1:"))
	}
	if pad := len(text) % 4; pad != 0 {
		text += strings.Repeat("=", 4-pad)
	}
	blob, err := base64.URLEncoding.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("邀请编码无效：%w", err)
	}
	var inv invitePayload
	if err := json.Unmarshal(blob, &inv); err != nil {
		return nil, fmt.Errorf("邀请内容无效：%w", err)
	}
	if inv.URL == "" || inv.Device == "" || inv.Secret == "" {
		return nil, fmt.Errorf("邀请缺少字段")
	}
	// tls=system：母端用公网 CA 签发（Tailscale Funnel 等），不携带自签证书与指纹
	if inv.TLS == "system" {
		if !strings.HasPrefix(inv.URL, "https://") {
			return nil, fmt.Errorf("tls=system 必须配 https:// 地址")
		}
		if inv.Exp != 0 && inv.Exp < time.Now().Unix() {
			return nil, fmt.Errorf("邀请已过期，请在母端重新生成")
		}
		return &inv, nil
	}
	if inv.Cert == "" || inv.FP == "" {
		return nil, fmt.Errorf("邀请缺少证书或指纹")
	}
	if inv.Exp != 0 && inv.Exp < time.Now().Unix() {
		return nil, fmt.Errorf("邀请已过期，请在母端重新生成")
	}
	block, _ := pem.Decode([]byte(inv.Cert))
	if block == nil {
		return nil, fmt.Errorf("邀请里的证书不是有效 PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	if hex.EncodeToString(sum[:]) != inv.FP {
		return nil, fmt.Errorf("邀请里的证书与指纹不符，拒绝使用")
	}
	return &inv, nil
}

type settings struct {
	Mother    string   `json:"mother"`
	Device    string   `json:"device"`
	Secret    string   `json:"secret"`
	CertPEM   string   `json:"cert_pem"`
	Roots     []string `json:"roots"`
	AllowExec bool     `json:"allow_exec"`
	HostMode  string   `json:"host_mode"`       // console / service / user
	TLS       string   `json:"tls,omitempty"`   // 空=固定证书；system=系统根（公网 CA）
	Addrs     []string `json:"addrs,omitempty"` // 入口 IP 列表：DNS 轮询里有坏节点时按这里轮换
}

// tlsSystem=true 表示母端用公网 CA 签发（如 Tailscale Funnel），改用系统根校验。
var tlsSystem bool

// entryAddrs 非空时，连接只走这些 IP（按游标轮换），忽略 DNS 解析结果；
// 用于绕过「域名解析出多个入口、其中部分节点在本网络不可达」的情况。
var (
	entryAddrs []string
	addrCursor uint32
)

var (
	installSvc     = flag.Bool("install-service", false, "安装为 Windows 服务（开机即在线，无需登录；需管理员）")
	uninstallSvc   = flag.Bool("uninstall-service", false, "停止并删除 Windows 服务")
	svcStatus      = flag.Bool("service-status", false, "查看服务状态")
	allowExec      = flag.Bool("allow-exec", false, "在本机授权命令执行（console 运行与安装时都需要；等同本地确认）")
	installUser    = flag.Bool("install-user", false, "安装为当前用户（免管理员：不建服务，登录后在线）")
	uninstallUser  = flag.Bool("uninstall-user", false, "卸载用户级安装")
	fromConfigFlag = flag.Bool("from-config", false, "读取 agent.json 直接运行（用户级自启用）")
	dataDirFlag    = flag.String("data-dir", "", "配置目录（默认 ProgramData/Tendril）")
	runAsService   = flag.Bool("service", false, "由 SCM 以服务方式运行（安装时自动带上）")
)

// hostMode / allowExecLocal 由启动方式决定，供 handle() 判定
var (
	hostMode       = "console"
	// 默认不授权执行：console 直接跑也要显式 --allow-exec。
	// 安装成服务/用户级时，以安装时写入的配置为准（安装默认也是关闭）。
	allowExecLocal = false
)

func main() {
	flag.Var(&roots, "root", "允许访问的目录（可重复）")
	flag.Parse()

	if *dataDirFlag != "" {
		dataDirOverride = *dataDirFlag
		if dir, err := dataDir(); err == nil {
			logPath := filepath.Join(dir, "agent.log")
			if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
				logOut = io.MultiWriter(os.Stderr, f)
				logf("启动（配置文件模式），日志 %s", logPath)
			}
		}
	}

	switch {
	case *installUser:
		os.Exit(runInstallUser())
	case *uninstallUser:
		os.Exit(runUninstallUser())
	case *installSvc:
		os.Exit(doInstall())
	case *uninstallSvc:
		os.Exit(doUninstall())
	case *svcStatus:
		os.Exit(doStatus())
	}

	// 服务模式：配置来自安装时写入的文件，而不是命令行
	if *runAsService || isWindowsService() {
		hostMode = "service"
		cfg, err := loadConfig()
		if err != nil {
			logf("读取服务配置失败：%v", err)
			os.Exit(2)
		}
		*mother, *device, *secret = cfg.Mother, cfg.Device, cfg.Secret
		caPEM = []byte(cfg.CertPEM)
		roots = cfg.Roots
		allowExecLocal = cfg.AllowExec
		tlsSystem = cfg.TLS == "system"
		entryAddrs = cfg.Addrs
		if err := buildClient(); err != nil {
			logf("%v", err)
			os.Exit(2)
		}
		logf("服务模式启动：设备 %s → %s，授权目录 %v，命令執行=%v", *device, *mother, roots, allowExecLocal)
		os.Exit(runService(runLoop))
	}

	if *fromConfigFlag {
		cfg, err := loadConfig()
		if err != nil {
			logf("%v", err)
			os.Exit(2)
		}
		hostMode = cfg.HostMode
		*mother, *device, *secret = cfg.Mother, cfg.Device, cfg.Secret
		caPEM = []byte(cfg.CertPEM)
		roots = cfg.Roots
		allowExecLocal = cfg.AllowExec
		tlsSystem = cfg.TLS == "system"
		entryAddrs = cfg.Addrs
		if err := buildClient(); err != nil {
			logf("%v", err)
			os.Exit(2)
		}
		logf("用户级模式启动：设备 %s → %s，授权目录 %v，命令执行=%v", *device, *mother, roots, allowExecLocal)
		runLoop(context.Background())
		os.Exit(0)
	}

	if *invite != "" {
		inv, err := parseInvite(*invite)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		*mother, *device, *secret = inv.URL, inv.Device, inv.Secret
		caPEM = []byte(inv.Cert)
		allowExecLocal = *allowExec   // console 模式：只有显式 --allow-exec 才允许执行
		tlsSystem = inv.TLS == "system"
		entryAddrs = inv.Addrs
		if tlsSystem {
			logf("使用邀请：设备 %s → %s（公网证书模式，系统根校验）", *device, *mother)
		} else {
			logf("使用邀请：设备 %s → %s", *device, *mother)
		}
	} else if *device == "" || *secret == "" {
		fmt.Fprintln(os.Stderr, "要么给 --invite，要么同时给 --device/--secret")
		os.Exit(2)
	}
	if err := buildClient(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	runLoop(context.Background())
}

// runLoop 是唯一的主循环：控制台与服务模式共用，ctx 取消即退出。
func runLoop(ctx context.Context) {
	c := confined{roots: roots}
	who := identityLabel()
	info := map[string]string{"os": osLabel(), "identity": who,
		"host_mode": hostMode, "can_exec": fmt.Sprint(allowExecLocal),
		"roots": strings.Join(roots, "|")}
	if hostMode == "service" {
		info["os"] = osLabel() + " (服务)"
	}
	logf("连接 %s 设备 %s 身份 %s 授权目录 %v", *mother, *device, who, []string(roots))

	var mu sync.Mutex
	running := map[string]context.CancelFunc{}
	backoff := time.Second

	for {
		select {
		case <-ctx.Done():
			logf("收到停止请求，退出主循环")
			return
		default:
		}
		mu.Lock()
		busy := len(running) > 0
		mu.Unlock()
		wait := 25
		if busy {
			wait = 1
		}
		code, data, err := callCtx(ctx, fmt.Sprintf("/agent/poll?wait=%d", wait), info)
		if err != nil {
			logf("poll 失败：%v，%v 后重试", err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		switch code {
		case 204:
			continue
		case 200:
			var t task
			if err := json.Unmarshal(data, &t); err != nil || t.TaskID == "" {
				logf("任务格式异常：%s", truncate(string(data), 200))
				continue
			}
			if t.Kind == "__cancel__" {
				mu.Lock()
				cancel := running[t.TaskID]
				mu.Unlock()
				if cancel != nil {
					logf("收到取消 %s", t.TaskID)
					cancel()
				}
				continue
			}
			if code, _, err := call("/agent/ack", map[string]any{"task_id": t.TaskID}); err != nil || code != 200 {
				logf("ack 失败（%v / HTTP %d），继续执行", err, code)
			}
			tctx, cancel := context.WithCancel(ctx)
			mu.Lock()
			running[t.TaskID] = cancel
			mu.Unlock()
			go func(t task, tctx context.Context, cancel context.CancelFunc) {
				defer func() {
					cancel()
					mu.Lock()
					delete(running, t.TaskID)
					mu.Unlock()
				}()
				res := handle(c, t, tctx)
				logf("任务 %s (%s) ok=%v", t.TaskID, t.Kind, res.OK)
				body := map[string]any{"task_id": t.TaskID, "result": res}
				if _, _, err := call("/agent/result", body); err != nil {
					logf("回传失败：%v（结果丢失，母端会显示未知）", err)
				}
			}(t, tctx, cancel)
		case 403:
			// 两种 403：等批准 / 被母端主动暂停。都保留重试，但暂停时慢一些，
			// 否则界面上的"暂停"只等于"每 30 秒失败一次"。
			wait := backoff
			if bytes.Contains(data, []byte("paused")) {
				logf("母端已暂停本设备，30 秒后再试")
				wait = 30 * time.Second
			} else {
				logf("母端尚未批准此设备，稍后自动重试")
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		default:
			logf("poll 返回 HTTP %d：%s", code, truncate(string(data), 200))
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// capped 写满上限后继续计数但不留内容：既不撑爆内存，也仍能报告真实字节数。
type capped struct {
	buflimit int
	buf      *bytes.Buffer
	written  int
}

func (c *capped) Write(p []byte) (int, error) {
	c.written += len(p)
	if left := c.buflimit - c.buf.Len(); left > 0 {
		if len(p) < left {
			left = len(p)
		}
		c.buf.Write(p[:left])
	}
	return len(p), nil
}
