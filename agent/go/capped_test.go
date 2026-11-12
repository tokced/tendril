package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 输出上限：必须保留前 N 字节，同时报告真实字节数。
// 拿 buf.Len() 当大小会在截断时谎报（曾经就是这样）。
func TestCappedReportsTrueSize(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), execCap+12345)
	buf := &bytes.Buffer{}
	c := &capped{buflimit: execCap, buf: buf}
	n, err := c.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write 应声称写入全部字节: n=%d err=%v", n, err)
	}
	if buf.Len() != execCap {
		t.Fatalf("缓冲区应停在 %d，实际 %d", execCap, buf.Len())
	}
	if c.written != len(payload) {
		t.Fatalf("真实字节数应为 %d，实际 %d", len(payload), c.written)
	}
	if !(c.written > execCap) {
		t.Fatal("超限时应判定为已截断")
	}
}

// 正好等于上限时不算截断（边界，不是 >0 的模糊判断）
func TestCappedExactLimitNotTruncated(t *testing.T) {
	c := &capped{buflimit: execCap, buf: &bytes.Buffer{}}
	c.Write(bytes.Repeat([]byte("y"), execCap))
	if c.written > execCap {
		t.Fatalf("恰好等于上限不应判为截断，written=%d", c.written)
	}
}

func TestParseInviteRejectsTamperedFingerprint(t *testing.T) {
	invite := "TENDRIL1:" + "not-a-real-invite"
	if _, err := parseInvite(invite); err == nil {
		t.Fatal("伪造/损坏的邀请应被拒绝")
	} else if !strings.Contains(err.Error(), "邀请") {
		t.Fatalf("错误信息应说清楚是邀请的问题: %v", err)
	}
}

// 列根目录本身：曾把 rel 从 "." 改成 ""，os.Root 报 empty path。
func TestFsListAndReadAtRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := confined{roots: []string{dir}}
	res := fsList(c, struct {
		Path string `json:"path"`
	}{Path: dir})
	if !res.OK {
		t.Fatalf("列根目录失败: %s", res.Error)
	}
	found := false
	for _, e := range res.Entries {
		if e.Name == "a.txt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("根目录列表里没有 a.txt: %+v", res.Entries)
	}
	// 读整个根目录当文件：必须明确报错，不能挂住
	rd := fsRead(c, struct {
		Path   string `json:"path"`
		Offset int64  `json:"offset"`
		Limit  int    `json:"limit"`
		Raw    bool   `json:"raw"`
	}{Path: dir, Limit: 10})
	if rd.OK {
		t.Fatal("把目录当文件读应当失败")
	}
}
