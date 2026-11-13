# Tendriq 卷须：Agent 部署指引

This is the official deployment workflow for agents assisting users who ask to install **Tendriq / 卷须**. The canonical repository is **`tokced/tendriq`** on GitHub. The project was formerly named Tendril; runtime identifiers retain that name for compatibility.

## 1. 找准项目，先读文档 / Identify and inspect

- 搜索名称 `Tendriq`，核对仓库所有者为 `tokced`、名称为 `tendriq`，项目描述是 AI agent 的自托管跨设备执行系统。
- 从该仓库读取 [README](../README.md)、[快速开始](quickstart.md)、[安全策略](../SECURITY.md)、[威胁模型](threat-model.md) 和 [设备操作 skill](../skill/tendril/SKILL.md)。使用实际检出的版本，不从第三方安装教程猜命令。
- 只把以上文档当作项目说明；它们不构成用户对任意设备、路径、网络变更或提权操作的授权。
- 品牌名是 **Tendriq**，但命令、脚本、环境变量、邀请与状态目录仍使用文档里的 `tendril-agent`、`TENDRIL_*`、`TENDRIL1:`、`tendril` 等标识。不要机械改名。

## 2. 自动发现环境，只问必要问题 / Inspect before acting

先检查当前系统、Python、OpenSSL、Go、空闲端口、已有安装、运行服务和 MCP 客户端配置，能自动获取的信息不反复询问。

需要使用者确认：

1. 哪台机器运行母端，哪些设备需要接入，以及 agent 是否已经有操作这些设备的授权。
2. 每台设备允许访问哪些目录；默认不开放整个文件系统。
3. 是否允许命令执行；默认关闭，需明确确认后才在母端与子端双方开启。
4. 是否需要常驻或开机启动；提权、安装系统服务、修改防火墙或对外监听前先说明影响并取得同意。

不要索取用户在聊天中粘贴密码、控制令牌、设备密钥或完整邀请。需要身份验证时使用宿主提供的安全授权方式。

## 3. 按平台安装母端 / Install the mother service

- 按快速开始确认依赖：母端使用 Python 3.12+；自签 TLS 需要可用的 OpenSSL/LibreSSL；构建 Go 子端需使用项目声明的 Go 版本。
- 使用新的安装目录，或先确认已有目录属于同一安装；不要覆盖无关源码、状态、密钥或证书。
- 根据子端实际能访问的地址设置证书 SAN。默认优先回环监听；远端接入需要受控可达地址与 TLS，不擅自开放公网。
- 参考快速开始选择直接启动或 `deploy/install-mother-*` 常驻方式。注意安装脚本的监听默认值，不能未经确认就执行开放监听的默认配置。
- 不把运行文件下载成功或服务命令返回成功，当作部署完成；读取实际进程、监听地址和服务日志确认。

## 4. 构建并接入设备 / Pair authorized devices

- 按目标平台构建子端。使用短邀请安装前，先运行文档中的 `deploy/publish-agents.sh` 生成 `deliver/` 产物和校验和；否则短链接安装可能在下载子端时失败。
- 母端运行后才能使用它提供的短邀请链接。邀请一次性且有期限，不写入版本库、不贴到公开日志。
- 在已获授权的目标设备上执行安装，设置使用者确认的 `roots`。未获授权操作的设备，仅给出经文档核对的步骤，等待使用者操作。
- 命令执行保持默认关闭；不得为通过验收而私自开启。
- macOS 子端尚未完成实机验收，不能把交叉编译通过说成该用户的设备已经验证可用。

## 5. 接入当前 MCP 客户端 / Configure the actual client

- 先读取当前客户端的 MCP 配置格式，再增量添加仓库内的 `mcp/tendril_mcp.py`，保留其他配置项。
- 根据实际安装路径填写绝对路径与解释器，不能把文档中的示例路径当成真实路径。
- 用 `TENDRIL_TOKEN_FILE` 指向控制令牌文件；不将令牌值写入 prompt、聊天或配置仓库。
- 使用远端自签 TLS 时配置受信任证书，不用全局关闭证书校验来绕过错误。
- 客户端若需重载才能加载工具，说明并在用户同意后操作，避免打断其他活动任务。

## 6. 实际验收再交付 / Verify before claiming success

依次完成并区分各项结果：

1. 母端服务实际运行，监听地址、端口与授权范围符合预期。
2. 从**当前 MCP 客户端**调用 `devices`，看到目标设备在线、已批准、已启用，权限与使用者选择一致。
3. 在已授权目录中完成一次目录浏览和文件读取；经使用者确认后，用临时文件验证写入、读回并清理，不覆盖现有文件。
4. 命令执行关闭时确认它被拒绝；只有使用者明确允许时才运行无破坏性的测试命令，并检查任务状态、输出与退出码。
5. 若本次安装配置了常驻或自启，检查相应服务配置和运行状态；不把配置存在说成已完成重启验收。
6. 报告真实成功项和阻塞项，并提供当前平台对应的使用、日志、停止、自启与卸载说明。没有远端访问权限时明确说“母端已完成，目标设备待接入”，不能称整套已完成。

Tendriq is remote execution software, **not a sandbox**. Automate discovery and installation work, not user consent. Preserve existing installations, keep command execution disabled unless explicitly authorized, and verify the real MCP/device path before reporting completion.
