package main

import (
	"crypto/tls"
	"net/http"
	"testing"
)

// tls=system（公网证书）以前会在 addrs 之前直接 return，入口地址形同废纸：
// 子端照旧用 DNS 结果拨号，遇到解析到 tailnet IP 的机器就永久超时。
// 这个测试盯住"公网模式也必须走 addrs"。
func TestBuildClientHonoursEntryAddrsWithSystemTLS(t *testing.T) {
	oldMother, oldSystem, oldAddrs := mother, tlsSystem, entryAddrs
	defer func() { mother, tlsSystem, entryAddrs = oldMother, oldSystem, oldAddrs }()

	url := "https://mother.example.ts.net:8443"
	mother = &url
	tlsSystem = true
	entryAddrs = []string{"185.40.234.75"}

	if err := buildClient(); err != nil {
		t.Fatalf("buildClient: %v", err)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport 类型不对：%T", client.Transport)
	}
	if tr.DialContext == nil {
		t.Fatal("tls=system 时必须安装按 addrs 拨号的 DialContext")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.ServerName != "mother.example.ts.net" {
		t.Fatalf("SNI 必须是主机名而不是入口 IP：%+v", tr.TLSClientConfig)
	}
	if tr.TLSClientConfig.RootCAs != nil {
		t.Fatal("公网模式应当用系统根证书")
	}
	if !tr.DisableKeepAlives {
		t.Fatal("按入口轮换时必须禁用连接复用")
	}
}

// 没有 addrs 时不得凭空造 DialContext，固定证书模式的根证书仍要装上。
func TestBuildClientPinnedCertWithoutAddrs(t *testing.T) {
	oldMother, oldSystem, oldAddrs, oldPEM := mother, tlsSystem, entryAddrs, caPEM
	defer func() { mother, tlsSystem, entryAddrs, caPEM = oldMother, oldSystem, oldAddrs, oldPEM }()

	url := "https://mother.example:8911"
	mother = &url
	tlsSystem = false
	entryAddrs = nil
	caPEM = []byte(testCertPEM)

	if err := buildClient(); err != nil {
		t.Fatalf("buildClient: %v", err)
	}
	tr := client.Transport.(*http.Transport)
	if tr.DialContext != nil {
		t.Fatal("没有 addrs 时不该接管拨号")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("固定证书模式必须装 RootCAs")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("最低 TLS 版本应为 1.2")
	}
}
