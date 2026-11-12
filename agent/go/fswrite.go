package main

// 分块写入：临时文件 → 校验 → 原子替换。
//
// 语义（与规划 §7 对齐）：
// - 每块带 offset，写入 <目标>.tendril-part；final=true 时才替换目标文件。
// - expect_size / expect_mtime 用来检测「我们读完之后别人改了它」，不匹配就拒写，
//   绝不无声覆盖。
// - 同一路径的写入用进程内互斥，防止两块并发交错。
// - 任何失败都删掉临时文件，磁盘上不会留下半成品当成成品。

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
)

type writeReq struct {
	Path        string `json:"path"`
	Offset      int64  `json:"offset"`
	Data        string `json:"data_b64"`
	Final       bool   `json:"final"`
	ExpectSize  *int64 `json:"expect_size"`
	ExpectMtime *int64 `json:"expect_mtime"`
	Hash        bool   `json:"hash"`
}

var writeLocks sync.Map // path -> *sync.Mutex

func lockFor(path string) *sync.Mutex {
	m, _ := writeLocks.LoadOrStore(path, &sync.Mutex{})
	return m.(*sync.Mutex)
}

func fsWrite(c confined, p writeReq) result {
	if p.Offset < 0 {
		return result{OK: false, Error: "offset 不能为负"}
	}
	raw, err := base64.StdEncoding.DecodeString(p.Data)
	if err != nil {
		return result{OK: false, Error: "data_b64 不是合法 base64"}
	}
	if int64(len(raw))+p.Offset > 1<<31 {
		return result{OK: false, Error: "单文件写入上限 2 GiB（本版）"}
	}
	root, rel, err := c.open(p.Path)
	if err != nil {
		return result{OK: false, Error: err.Error()}
	}
	defer root.Close()

	mu := lockFor(p.Path)
	mu.Lock()
	defer mu.Unlock()

	tmpRel := rel + ".tendril-part"
	flags := os.O_WRONLY | os.O_CREATE
	if p.Offset == 0 {
		flags |= os.O_TRUNC
	}
	f, err := root.OpenFile(tmpRel, flags, 0o600)
	if err != nil {
		return result{OK: false, Error: "打开临时文件失败：" + err.Error()}
	}
	if _, err := f.WriteAt(raw, p.Offset); err != nil {
		f.Close()
		root.Remove(tmpRel)
		return result{OK: false, Error: "写入失败：" + err.Error()}
	}
	if !p.Final {
		if err := f.Close(); err != nil {
			root.Remove(tmpRel)
			return result{OK: false, Error: "关闭临时文件失败：" + err.Error()}
		}
		return result{OK: true, Path: p.Path, Offset: p.Offset, NextOffset: p.Offset + int64(len(raw))}
	}

	// ---- 收尾：尺寸校验 → 目标版本校验 → 原子替换 ----
	if err := f.Sync(); err != nil {
		f.Close()
		root.Remove(tmpRel)
		return result{OK: false, Error: "sync 失败：" + err.Error()}
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		root.Remove(tmpRel)
		return result{OK: false, Error: "stat 临时文件失败：" + err.Error()}
	}
	want := p.Offset + int64(len(raw))
	if st.Size() != want {
		f.Close()
		root.Remove(tmpRel)
		return result{OK: false, Error: fmt.Sprintf("收到 %d 字节，期望 %d：分块缺失或乱序", st.Size(), want)}
	}
	// 临时文件是以只写方式打开的，读不了；算校验和要另开一个只读句柄。
	f.Close()
	var digest string
	if p.Hash {
		rf, err := root.Open(tmpRel)
		if err != nil {
			root.Remove(tmpRel)
			return result{OK: false, Error: "重开临时文件失败：" + err.Error()}
		}
		h := sha256.New()
		_, cerr := io.Copy(h, rf)
		rf.Close()
		if cerr != nil {
			root.Remove(tmpRel)
			return result{OK: false, Error: "计算校验和失败：" + cerr.Error()}
		}
		digest = hex.EncodeToString(h.Sum(nil))
	}

	if p.ExpectSize != nil || p.ExpectMtime != nil {
		if cur, err := root.Stat(rel); err == nil {
			if p.ExpectSize != nil && cur.Size() != *p.ExpectSize {
				root.Remove(tmpRel)
				return result{OK: false, Error: fmt.Sprintf("目标文件已变化（大小 %d，期望 %d），拒绝覆盖", cur.Size(), *p.ExpectSize)}
			}
			if p.ExpectMtime != nil && cur.ModTime().Unix() != *p.ExpectMtime {
				root.Remove(tmpRel)
				return result{OK: false, Error: "目标文件修改时间已变化，拒绝覆盖"}
			}
		} else if !os.IsNotExist(err) {
			root.Remove(tmpRel)
			return result{OK: false, Error: "检查目标文件失败：" + err.Error()}
		}
	}
	if err := root.Rename(tmpRel, rel); err != nil {
		root.Remove(tmpRel)
		return result{OK: false, Error: "替换目标文件失败：" + err.Error()}
	}
	return result{OK: true, Path: p.Path, Size: want, Offset: p.Offset,
		NextOffset: want, Sha256: digest}
}
