#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $EUID != 0 || $# != 2 ]]; then
    echo '需要 root、主控 HTTPS 地址和部署凭据。' >&2
    exit 2
fi
origin=$1
credential=$2
[[ $origin =~ ^https://[A-Za-z0-9.-]+$ ]] || exit 2
if [[ -e /etc/systemd/system/netwatch-agent.service && ! -e /etc/netwatch/panel-managed ]]; then
    echo '已发现手工部署的 Netwatch Agent，请先迁移该服务。' >&2
    exit 1
fi
for tool in curl python3 ssh ss nft systemctl timeout; do
    command -v "$tool" >/dev/null || { echo "缺少命令 $tool" >&2; exit 1; }
done

work=$(mktemp -d)
trap 'python3 -c "import shutil,sys; shutil.rmtree(sys.argv[1])" "$work"' EXIT
printf '%s' "$credential" | python3 -c '
import base64, json, os, re, sys
from pathlib import Path
p = json.loads(base64.urlsafe_b64decode(sys.stdin.read()))
out = Path(sys.argv[1])
assert re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", p["node"])
assert re.fullmatch(r"[a-f0-9]{64}", p["token"])
assert re.fullmatch(r"[A-Za-z0-9.-]+", p["host"])
assert type(p["ssh_port"]) is int and 1 <= p["ssh_port"] <= 65535
assert re.fullmatch(r"/[A-Za-z0-9_./-]+", p["config"])
assert re.fullmatch(r"[A-Za-z0-9_.-]{0,15}", p["interface"])
assert Path(p["config"]).is_file(), "Xray 配置不存在"
if p["interface"]:
    assert Path("/sys/class/net", p["interface"]).exists(), "出口网卡不存在"
env = {
    "NETWATCH_NODE_ID": p["node"], "NETWATCH_AGENT_TOKEN": p["token"],
    "NETWATCH_SSH_HOST": p["host"], "NETWATCH_SSH_PORT": p["ssh_port"],
    "NETWATCH_XRAY_CONFIG": p["config"], "NETWATCH_DOWNLOAD_INTERFACE": p["interface"],
}
(out/"agent.env").write_text("".join(f"{k}={v}\n" for k,v in env.items()))
(out/"tunnel_key").write_text(p["private_key"])
(out/"known_hosts").write_text(p["known_hosts"]+"\n")
' "$work"

for file in netwatch.py netwatch-agent.service netwatch-tunnel.service; do
    curl --proto '=https' -fsS --max-time 30 "$origin/deploy/$file" -o "$work/$file"
done
python3 -m py_compile "$work/netwatch.py"
(
    set -a
    source "$work/agent.env"
    set +a
    timeout 8 ssh -p "$NETWATCH_SSH_PORT" -i "$work/tunnel_key" \
        -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="$work/known_hosts" -o ConnectTimeout=5 \
        -W 127.0.0.1:8787 "netwatch-tunnel@$NETWATCH_SSH_HOST" <<'REQUEST' |
GET /health HTTP/1.0

REQUEST
        grep '200 OK' >/dev/null
)
install -d -m 0700 /etc/netwatch
install -d -m 0755 /opt/netwatch
install -m 0600 "$work/agent.env" "$work/tunnel_key" "$work/known_hosts" /etc/netwatch/
install -m 0644 "$work/netwatch.py" /opt/netwatch/
install -m 0644 "$work/"*.service /etc/systemd/system/
touch /etc/netwatch/panel-managed
systemctl daemon-reload
systemctl enable netwatch-tunnel netwatch-agent
systemctl restart netwatch-tunnel netwatch-agent
systemctl is-active netwatch-tunnel netwatch-agent
echo 'Agent 安装完成，请回到主控查看上报状态。'
