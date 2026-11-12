#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo '用法：sudo bash deploy/install-server.sh 域名 SSH入口 端口 邮箱' >&2
    exit 2
}

[[ $EUID == 0 && $# == 4 ]] || usage
domain=$1
ssh_host=$2
ssh_port=$3
email=$4
[[ $domain =~ ^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ &&
   $ssh_host =~ ^[A-Za-z0-9.-]+$ &&
   $ssh_port =~ ^[1-9][0-9]{0,4}$ && $ssh_port -le 65535 &&
   $email == *@* ]] || usage
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
test -f netwatch.py && test -f index.html && test -f deploy/netwatch-server.service
command -v apt-get >/dev/null && command -v systemctl >/dev/null || {
    echo '此安装器需要 Debian 或 Ubuntu 和 systemd。' >&2
    exit 1
}

config=/etc/netwatch/server.env
site=/etc/nginx/sites-available/netwatch
unit=/etc/systemd/system/netwatch-server.service
marker=/etc/netwatch/server-install-pending
settings=$(printf '%s\n' "$domain" "$ssh_host" "$ssh_port")
if [[ -f $marker ]]; then
    [[ $(cat "$marker") == "$settings" ]] || {
        echo '上次安装未完成，请用相同的域名和 SSH 参数重试。' >&2
        exit 1
    }
elif [[ -e $config || -e $site || -e $unit || -e /opt/netwatch/netwatch.py ]]; then
    echo '检测到已有 Netwatch 部署，请使用升级或迁移流程。' >&2
    exit 1
fi
install -d -m 0700 /etc/netwatch
printf '%s\n' "$settings" > "$marker"

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 nginx certbot openssl curl openssh-server sqlite3

id netwatch >/dev/null 2>&1 ||
    adduser --system --group --home /var/lib/netwatch --no-create-home netwatch
id netwatch-tunnel >/dev/null 2>&1 ||
    adduser --disabled-password --gecos '' netwatch-tunnel

install -d -m 0755 /opt/netwatch /var/www/netwatch-install /var/www/netwatch-acme
install -m 0644 netwatch.py index.html /opt/netwatch/
install -m 0644 deploy/netwatch-server.service "$unit"
install -D -o root -g root -m 0755 deploy/netwatch-authorized-keys /usr/local/libexec/netwatch-authorized-keys
install -m 0644 netwatch.py deploy/agent-install.sh \
    deploy/netwatch-agent.service deploy/netwatch-tunnel.service /var/www/netwatch-install/

if [[ ! -e $config ]]; then
    (
        umask 077
        printf 'NETWATCH_ADMIN_PASSWORD=%s\n' "$(openssl rand -hex 24)"
        printf 'NETWATCH_ENROLL_ORIGIN=https://%s\n' "$domain"
        printf 'NETWATCH_ENROLL_SSH_HOST=%s\n' "$ssh_host"
        printf 'NETWATCH_ENROLL_SSH_PORT=%s\n' "$ssh_port"
    ) > "$config"
fi

ssh-keygen -A
runuser -u netwatch -- test -r /etc/ssh/ssh_host_ed25519_key.pub
sshd_config=/etc/ssh/sshd_config
if ! grep -q '^Match User netwatch-tunnel$' "$sshd_config"; then
    cp -p "$sshd_config" "$sshd_config.pre-netwatch"
    { printf '\n'; cat deploy/netwatch-sshd.conf; } >> "$sshd_config"
    if ! /usr/sbin/sshd -t; then
        cp -p "$sshd_config.pre-netwatch" "$sshd_config"
        exit 1
    fi
fi
/usr/sbin/sshd -t
effective=$(/usr/sbin/sshd -T -C user=netwatch-tunnel,host=localhost,addr=127.0.0.1)
grep -Fxq 'allowtcpforwarding local' <<< "$effective"
grep -Fxq 'permitopen 127.0.0.1:8787' <<< "$effective"
grep -Fxq 'maxsessions 0' <<< "$effective"
grep -Fxq 'authorizedkeyscommand /usr/local/libexec/netwatch-authorized-keys %f' <<< "$effective"
systemctl reload ssh

systemctl daemon-reload
systemctl enable netwatch-server
systemctl restart netwatch-server
curl -fsS --retry 4 --retry-connrefused http://127.0.0.1:8787/health
printf '\n'

full_site=$(mktemp)
trap 'rm -f -- "$full_site"' EXIT
sed "s/monitor\\.example\\.com/$domain/g" deploy/netwatch.nginx.conf > "$full_site"
if [[ ! -s /etc/letsencrypt/live/$domain/fullchain.pem ]]; then
    awk '/^server \{/ { if (++n == 2) exit } { print }' "$full_site" > "$site"
else
    install -m 0644 "$full_site" "$site"
fi
ln -sfn "$site" /etc/nginx/sites-enabled/netwatch
nginx -t
systemctl enable --now nginx
systemctl reload nginx

certbot certonly --webroot -w /var/www/netwatch-acme -d "$domain" --cert-name "$domain" \
    --non-interactive --agree-tos --email "$email" --keep-until-expiring
install -m 0644 "$full_site" "$site"
nginx -t
systemctl reload nginx

install -d /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/netwatch-nginx <<'HOOK'
#!/bin/sh
systemctl reload nginx
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/netwatch-nginx
systemctl enable --now certbot.timer
curl -fsS --resolve "$domain:443:127.0.0.1" "https://$domain/health"
printf '\n'
rm -f -- "$marker"
printf '面板：https://%s/\n用户名：admin\n查看密码：sudo sed -n '\''s/^NETWATCH_ADMIN_PASSWORD=//p'\'' %s\n' "$domain" "$config"
