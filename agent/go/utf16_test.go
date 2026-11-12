package main

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// Windows 的 ntuser.ini / 注册表导出 / 部分日志是 UTF-16LE 带 BOM，
// 里面天然含 NUL。只看 NUL 判二进制会把它们整份退回 base64，
// 界面上就是"点了文本文件却没打开"。
func TestUtf16ToUtf8(t *testing.T) {
	text := "第一行\r\nsecond line\r\n"
	units := utf16.Encode([]rune(text))
	le := make([]byte, 0, len(units)*2)
	for _, u := range units {
		le = binary.LittleEndian.AppendUint16(le, u)
	}
	if got := utf16ToUTF8(le, true); got != text {
		t.Fatalf("UTF-16LE 解码错误：%q", got)
	}
	be := make([]byte, 0, len(units)*2)
	for _, u := range units {
		be = binary.BigEndian.AppendUint16(be, u)
	}
	if got := utf16ToUTF8(be, false); got != text {
		t.Fatalf("UTF-16BE 解码错误：%q", got)
	}
	// BOM 已在调用方剥掉；这里只验证内容转换不碰代理对边界之外的字节
	if got := utf16ToUTF8([]byte{0x41, 0x00}, true); got != "A" {
		t.Fatalf("单字符解码错误：%q", got)
	}
}
