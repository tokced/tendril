package main

// 文件结构操作：新建目录、重命名、删除。
//
// 为什么必须走协议而不是借 exec：
//   - exec 跑的是 PowerShell，路径授权对它没有约束，等于给了一条绕过授权目录的旁路。
//   - 界面上的「新建文件夹 / 改名 / 删除」需要的是明确、可审计的原子操作。
//
// 全部限制在同一条 os.Root 内：重命名要求源和目标在同一个授权根目录，
// 删除拒绝作用于授权根目录本身。

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// locate 把绝对路径规约到授权根目录 + 相对路径，不打开句柄。
func (c confined) locate(raw string) (string, string, error) {
	if raw == "" || strings.ContainsRune(raw, 0) {
		return "", "", fmt.Errorf("路径为空或含空字符")
	}
	if len(c.roots) == 0 {
		return "", "", fmt.Errorf("此设备未授权任何目录")
	}
	if !filepath.IsAbs(raw) {
		return "", "", fmt.Errorf("只接受绝对路径")
	}
	clean := filepath.Clean(raw)
	for _, root := range c.roots {
		root = filepath.Clean(root)
		rel, err := filepath.Rel(root, clean)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return root, rel, nil
	}
	return "", "", fmt.Errorf("路径不在授权目录内：%s", raw)
}

func fsMkdir(c confined, p struct {
	Path string `json:"path"`
}) result {
	rootDir, rel, err := c.locate(p.Path)
	if err != nil {
		return result{OK: false, Error: err.Error()}
	}
	r, err := os.OpenRoot(rootDir)
	if err != nil {
		return result{OK: false, Error: err.Error()}
	}
	defer r.Close()
	if rel == "." {
		return result{OK: false, Error: "目标已是授权根目录，无需创建"}
	}
	if err := r.Mkdir(rel, 0o755); err != nil {
		if os.IsExist(err) {
			return result{OK: false, Error: "已存在：" + p.Path}
		}
		return result{OK: false, Error: "创建目录失败：" + err.Error()}
	}
	return result{OK: true, Path: p.Path, Type: "dir"}
}

func fsRename(c confined, p struct {
	From string `json:"from"`
	To   string `json:"to"`
}) result {
	srcRoot, srcRel, err := c.locate(p.From)
	if err != nil {
		return result{OK: false, Error: "源：" + err.Error()}
	}
	dstRoot, dstRel, err := c.locate(p.To)
	if err != nil {
		return result{OK: false, Error: "目标：" + err.Error()}
	}
	if srcRoot != dstRoot {
		return result{OK: false, Error: "源和目标不在同一个授权目录内，跨目录移动不支持"}
	}
	if srcRel == "." || dstRel == "." {
		return result{OK: false, Error: "不允许重命名授权根目录本身"}
	}
	r, err := os.OpenRoot(srcRoot)
	if err != nil {
		return result{OK: false, Error: err.Error()}
	}
	defer r.Close()
	// 目标已存在时不做静默覆盖：调用方要显式先删。
	if _, err := r.Lstat(dstRel); err == nil {
		return result{OK: false, Error: "目标已存在，拒绝覆盖：" + p.To}
	}
	if err := r.Rename(srcRel, dstRel); err != nil {
		return result{OK: false, Error: "重命名失败：" + err.Error()}
	}
	return result{OK: true, Path: p.To, From: p.From}
}

func fsRemove(c confined, p struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
}) result {
	rootDir, rel, err := c.locate(p.Path)
	if err != nil {
		return result{OK: false, Error: err.Error()}
	}
	if rel == "." {
		return result{OK: false, Error: "不允许删除授权根目录本身"}
	}
	r, err := os.OpenRoot(rootDir)
	if err != nil {
		return result{OK: false, Error: err.Error()}
	}
	defer r.Close()
	info, err := r.Lstat(rel)
	if err != nil {
		if os.IsNotExist(err) {
			return result{OK: false, Error: "不存在：" + p.Path}
		}
		return result{OK: false, Error: err.Error()}
	}
	if info.IsDir() && !p.Recursive {
		// 非空目录要求显式递归，避免「以为删了个空文件夹，结果连内容一起没了」。
		if err := r.Remove(rel); err != nil {
			return result{OK: false, Error: "删除失败（非空目录需显式 recursive）：" + err.Error()}
		}
		return result{OK: true, Path: p.Path, Type: "dir"}
	}
	if p.Recursive {
		if err := r.RemoveAll(rel); err != nil {
			return result{OK: false, Error: "递归删除失败：" + err.Error()}
		}
	} else if err := r.Remove(rel); err != nil {
		return result{OK: false, Error: "删除失败：" + err.Error()}
	}
	kind := "file"
	if info.IsDir() {
		kind = "dir"
	}
	return result{OK: true, Path: p.Path, Type: kind}
}
