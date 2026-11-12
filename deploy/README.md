# Netwatch 正式部署

适用于 Debian 系 Linux、Python 3.9+、systemd。主控安装 Nginx、OpenSSH 服务端和 SQLite 工具。Agent 需要 OpenSSH 客户端、`ss`、`nft`，启用下载限速时还需要 `ip`、`tc` 和内核 IFB 支持。主控使用独立服务账户。Agent 用 root 读取 Xray 配置并应用封禁和限速。

## 主控

1. 创建服务账户 `netwatch`，禁用交互登录。另建 `netwatch-tunnel` 账户用于 Agent 的 SSH 转发。
2. 将 `netwatch.py` 和 `index.html` 安装到 `/opt/netwatch/`。用 root 持有程序文件，权限设为 `0644`。将 `deploy/netwatch-server.service` 安装到 `/etc/systemd/system/`。
3. 创建 root 专用的 `/etc/netwatch`（`0700`）及 `/etc/netwatch/server.env`（`0600`）。为管理员和每个 Agent 单独生成随机密钥，例如运行 `openssl rand -hex 32`。

   ```ini
   NETWATCH_ADMIN_PASSWORD=replace-with-generated-password
   NETWATCH_NODE_TOKENS={"agent-01":"replace-with-generated-agent-token"}
   ```

4. 如需迁入旧主控历史，先在旧机上用 SQLite 在线备份生成数据库副本。例如在受保护目录运行 `sqlite3 /opt/netwatch/netwatch.db '.backup netwatch-migration.db'`。通过 SSH 传到新主控，在新服务首次启动前放到 `/var/lib/netwatch/netwatch.db`，目录权限 `0700`，文件权限 `0600`，两者归 `netwatch:netwatch`。备份包含历史、别名、封禁和限速。沿用旧 Agent 的节点 ID 前逐项核对这些规则。
5. 运行 `systemctl daemon-reload` 和 `systemctl enable --now netwatch-server`。用 `ss -ltn` 确认 Python 服务监听 `127.0.0.1:8787`。
6. 将域名的 A 记录指向正式主控。仅在主控和 Nginx 确实提供公网 IPv6 时添加 AAAA。将 Nginx 模板中的 `monitor.example.com` 替换为正式域名。先启用模板的 HTTP 段，创建 `/var/www/netwatch-acme`，开放公网 80 和 443，然后签发域名证书。

   ```sh
   certbot certonly --webroot -w /var/www/netwatch-acme -d monitor.example.com
   ```

7. 启用模板的 HTTPS 段，运行 `nginx -t` 并重载 Nginx。确认 Certbot 的续期定时器和续期后重载 Nginx 的部署钩子可用，再运行 `certbot renew --dry-run`。从外网验证 HTTPS 登录、历史查询和 `/ingest` 返回 404。

## 面板添加 Agent 与换机

先在主控启用注册。下面的正式域名和 SSH 入口换成实际值。网页经 HTTP CDN 时，SSH 入口填写直连地址。

```ini
NETWATCH_ENROLL_ORIGIN=https://monitor.example.com
NETWATCH_ENROLL_SSH_HOST=monitor.example.com
NETWATCH_ENROLL_SSH_PORT=22
```

把这三项加入主控的 `/etc/netwatch/server.env`，并重启主控。如果全部节点都通过面板注册，`NETWATCH_NODE_TOKENS` 可省略。确认 `/etc/ssh/ssh_host_ed25519_key.pub` 对服务账户可读。安装 SSH 公钥查询程序和下载文件。

```sh
install -D -o root -g root -m 0755 deploy/netwatch-authorized-keys /usr/local/libexec/netwatch-authorized-keys
install -d -o root -g root -m 0755 /var/www/netwatch-install
install -o root -g root -m 0644 netwatch.py deploy/agent-install.sh \
  deploy/netwatch-agent.service deploy/netwatch-tunnel.service /var/www/netwatch-install/
```

将 `deploy/netwatch-sshd.conf` 的 Match 段合并到主控现有 SSH 配置末尾。已有同账户规则时替换该段，避免重复。检查 `sshd -t` 及该账户的生效配置，再重载 SSH。使用新版 Nginx 模板并检查 `nginx -t`。主控的 `8787` 仍是回环监听，公网 `/ingest` 仍返回 404。

1. 面板点「添加 Agent」，填写独立节点 ID、名称、Xray 配置路径和可选的限速出口网卡。将生成的命令复制到新 Agent 运行。命令包含节点令牌和 SSH 私钥，请勿转发或保存到公共日志。
2. 确认主控收到上报。Agent 下载安装文件走 HTTPS，实际采样和规则同步走 SSH 隧道。
3. 换机前点「备份监控」，导出节点按日来源记录、采样峰值、封禁和限速。可以在已上报的新 Agent 点「恢复监控」，上传 JSON（请求上限 8 MiB），先预览再确认。仅合并端口、监听地址和 Xray tag 匹配的入站。已有封禁保留，同端口限速有冲突时保留新 Agent 的配置并显示两个值。历史按来源 IP 和日期合并，同一天的采样计数取较大值。若要恢复整台主控，仍用下面的 SQLite 一致备份。
4. 先在新服务器恢复 3x-ui 并确认入站，再在旧节点点「换机」。生成命令时旧上报凭据立即失效。用命令安装新 Agent，保持同一节点 ID。主控继续使用原历史、封禁和限速。入站应保留原端口、监听地址和 Xray tag，才能在同一详情里查到原记录。核对新机网卡，并确认规则生效后再将客户端切到新 IP。3x-ui 自己的数据库、证书和配置需要另行迁移。

## 手工接入 Agent

1. 在 Agent 的 root 专用目录 `/etc/netwatch`（`0700`）生成专用 SSH 密钥。

   ```sh
   ssh-keygen -t ed25519 -N '' -f /etc/netwatch/tunnel_key
   ```

2. 通过主控控制台核对 SSH 主机密钥，将其写入 Agent 的 `/etc/netwatch/known_hosts`。主控在 `netwatch-tunnel` 的 `authorized_keys` 中添加 Agent 公钥，每行使用如下前缀。

   ```text
   restrict,port-forwarding,permitopen="127.0.0.1:8787",command="/bin/false" ssh-ed25519 <Agent 公钥>
   ```

   在主控的 SSH 配置末尾对该专用账户限制为本地转发，阻止远程转发，并只接受公钥认证。先用 `sshd -t` 验证，再重载 SSH 服务。

   ```text
   Match User netwatch-tunnel
       AllowTcpForwarding local
       PermitOpen 127.0.0.1:8787
       AuthenticationMethods publickey
   ```

3. 将程序安装到 `/opt/netwatch/netwatch.py`，把 Agent 和隧道服务模板装到 `/etc/systemd/system/`。创建 `/etc/netwatch/agent.env`（`0600`）。节点 ID、令牌、SSH 地址和网卡均替换为实际值。下载限速暂不启用时，省略最后一行。

   ```ini
   NETWATCH_NODE_ID=agent-01
   NETWATCH_AGENT_TOKEN=replace-with-generated-agent-token
   NETWATCH_SSH_HOST=monitor.example.com
   NETWATCH_SSH_PORT=22
   NETWATCH_XRAY_CONFIG=/usr/local/x-ui/bin/config.json
   NETWATCH_DOWNLOAD_INTERFACE=ens17
   ```

   SSH 地址须直接可达主控 SSH 端口。若网页域名经过 HTTP CDN 代理，在此填直连 SSH 的主机名或 IP。

4. 运行 `systemctl daemon-reload` 及 `systemctl enable --now netwatch-tunnel netwatch-agent`。先接一台试点，检查约一分钟的采样间隔、备注和来源历史。使用测试入站验证封禁、限速、解除和 Agent 重启。规则随上报拉取，面板确认可能要等随后的一次上报。

## 备份和回滚

- 定期用 SQLite `.backup` 创建一致副本，并把副本保存到另一台机器的受保护位置。另行备份凭据和服务配置。先在隔离环境试恢复再上线。
- 升级前保存上一版程序和页面、环境配置以及数据库一致副本。发生故障时先切回上一版程序和页面。若必须还原数据库，先停主控，保留当前数据库及其 WAL 文件以备排查，在隔离目录验证备份后再用它替换生产数据库并重启。
- 主控断线期间当前版本会跳过当轮上报。Agent 启动时需从主控重新取得规则。上线验收时检查重连与规则恢复。
