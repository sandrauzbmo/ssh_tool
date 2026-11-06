# 第三方组件

本仓库发布 AgentSSH Linux 客户端源码及静态构建文件。未在此为项目自行添加新的开源授权条款。

构建锁定的第三方组件：

| 组件 | 版本 | 许可证副本 |
| --- | --- | --- |
| Go 标准库 | Go 1.27.3（发行构建） | `third_party/go-standard-library.LICENSE` |
| github.com/coder/websocket | v1.8.15 | `third_party/coder-websocket.LICENSE` |
| golang.org/x/crypto | v0.58.1-0.20261009181718-2f1f834330b2 | `third_party/golang-crypto.LICENSE` |
| golang.org/x/sys | v0.49.0 | `third_party/golang-sys.LICENSE` |

具体依赖与校验锁定于 `go.mod`、`go.sum`。第三方许可证保留其自身授予的权利和要求。
