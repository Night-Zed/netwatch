# Netwatch 网络监控面板

Netwatch 由主控和 Linux Agent 组成，用来监控 3x-ui / Xray 的 VLESS Reality TCP 入站。Agent 每分钟采集一次已建立的连接，经 SSH 隧道上报。主控提供域名 HTTPS 面板、来源 IP 历史、按端口封禁和下载总限速。

主控支持生成 Agent 部署命令，以及按节点导出和恢复监控数据。安装、迁移、备份和回滚见 [部署说明](deploy/README.md) 和 [Docker 主控说明](deploy/DOCKER.md)。

部署请使用固定版本的 Release。正式环境的数据库、来源 IP 备份、密码、令牌和私钥应留在服务器或受保护的备份中。
