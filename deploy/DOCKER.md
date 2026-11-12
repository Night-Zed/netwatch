# Netwatch Docker 主控

Netwatch 使用独立 Compose 项目，IPBest 的 Caddy 继续提供 80 和 443。Agent 通过宿主机 OpenSSH 转发到 `127.0.0.1:8787`。公网 Caddy 拦截 `/ingest`。

- 保留宿主机的 `netwatch`、`netwatch-tunnel` 账户、SSH Match 规则和 `/etc/netwatch/server.env`。用于首次部署的对应配置见 [部署说明](README.md)。
- 将发布包解压到永久目录，创建外部网络 `netwatch-proxy`。在解压目录的 `.env` 设置 `NETWATCH_UID` 和 `NETWATCH_GID`，值为宿主机 `id -u netwatch` 和 `id -g netwatch`。
- 创建 `/var/lib/netwatch-docker`，属主为宿主机 `netwatch:netwatch`，权限 `0700`。Docker 服务的数据保存在该目录。清空起步时让容器自行创建数据库。
- 先用 `NETWATCH_HOST_PORT=18787 docker compose up -d --build --wait` 验证容器，并访问 `http://127.0.0.1:18787/health`。切换时停用宿主机的 `netwatch-server.service`，再运行 `docker compose up -d --wait`，让 Docker 接手宿主机回环端口 8787。
- 宿主机的 `netwatch-authorized-keys` 查询程序应读取 `/var/lib/netwatch-docker/netwatch.db`。以宿主机 `netwatch` 账户读取数据库验证权限，保持原来的 sshd Match 和公钥限制。
- 将 `deploy/netwatch.Caddyfile` 里的 `monitor.example.com` 替换为正式域名后，加入 IPBest 当前 Caddyfile，合并文件放到 `/etc/netwatch/ipbest.Caddyfile`，保留 IPBest 原有站点。用 `deploy/ipbest-compose.override.yml` 持久挂载该配置，并让 IPBest 的 web 服务加入 `netwatch-proxy`。已有 Compose override 时合并配置。升级 IPBest 并变更其站点配置时，也更新这份合并后的 Caddyfile。
- 验收公网面板登录、`/health`、安装文件下载、`/ingest` 返回 404，以及 IPBest API 健康状态。然后用一台 Agent 验证 SSH 公钥注册和首次上报。

升级时解压新的固定版本发布包，保留宿主机配置、`.env` 和数据库目录。设置 `NETWATCH_IMAGE_TAG` 为发布版本，执行 `docker compose up -d --build --wait`。
