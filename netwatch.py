#!/usr/bin/env python3
import argparse
import base64
import hmac
import ipaddress
import json
import os
import re
import secrets
import shlex
import sqlite3
import subprocess
import tempfile
import time
from contextlib import closing
from datetime import date, datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

CHINA = timezone(timedelta(hours=8))
PAGE = Path(__file__).with_name("index.html")
DEPLOY_FILES = {
    "agent-install.sh": PAGE.parent / "deploy" / "agent-install.sh",
    "netwatch.py": Path(__file__),
    "netwatch-agent.service": PAGE.parent / "deploy" / "netwatch-agent.service",
    "netwatch-tunnel.service": PAGE.parent / "deploy" / "netwatch-tunnel.service",
}
SAMPLE_INTERVAL = 60


def address(value):
    ip = ipaddress.ip_address(value.strip("[]").split("%", 1)[0])
    return str(getattr(ip, "ipv4_mapped", None) or ip)


def collect(config, sockets, remarks=None):
    remarks = remarks or {}
    ports = {}
    for inbound in config["inbounds"]:
        stream = inbound.get("streamSettings", {})
        if inbound.get("protocol") != "vless" or stream.get("security") != "reality":
            continue
        if stream.get("network", "tcp") not in ("tcp", "raw"):
            continue
        port = int(inbound["port"])
        listen = inbound.get("listen") or "::"
        clients = inbound.get("settings", {}).get("clients", [])
        row = {
            "port": port,
            "listen": listen,
            "tag": inbound.get("tag", ""),
            "remark": remarks.get((port, inbound.get("tag", "")), ""),
            "users": [client["email"] for client in clients if client.get("email")],
            "sources": {},
        }
        ports.setdefault(port, []).append(row)

    for line in sockets.splitlines():
        recvq, sendq, local, peer, *_ = line.split()
        local_ip, local_port = local.rsplit(":", 1)
        candidates = ports.get(int(local_port), [])
        if not candidates:
            continue
        peer_ip = address(peer.rsplit(":", 1)[0])
        for row in candidates:
            listen = address(row["listen"])
            if listen == address(local_ip) or listen == "::" or (
                listen == "0.0.0.0" and ":" not in address(local_ip)
            ):
                sources = row["sources"]
                sources[peer_ip] = sources.get(peer_ip, 0) + 1
    return [row for rows in ports.values() for row in rows]


def authorized(actual, expected):
    return hmac.compare_digest(actual.encode(), expected.encode())


def sync_firewall(rules):
    tables = subprocess.check_output(["/usr/sbin/nft", "list", "tables"], text=True, timeout=4)
    script = []
    if "table inet netwatch" in tables.splitlines():
        script.append("delete table inet netwatch")
    if rules:
        script.extend([
            "add table inet netwatch",
            "add chain inet netwatch input { type filter hook input priority -10; policy accept; }",
        ])
        for port, ip in rules:
            family = "ip" if ipaddress.ip_address(ip).version == 4 else "ip6"
            script.append(f"add rule inet netwatch input {family} saddr {ip} tcp dport {port} drop")
    if script:
        subprocess.run(["/usr/sbin/nft", "-f", "-"], input="\n".join(script) + "\n",
                       text=True, check=True, timeout=4)


def sync_downloads(limits, interface):
    def command(*args):
        return subprocess.check_output(args, text=True, timeout=4, stderr=subprocess.STDOUT)

    links = json.loads(command("ip", "-j", "-d", "link", "show"))
    prefix = "netwatch-download:"
    owned = {}
    for link in links:
        name = link["ifname"]
        alias = link.get("ifalias", "")
        if (name.startswith("nw-dl-") and name[6:].isdigit() and alias.startswith(prefix)
                and link.get("linkinfo", {}).get("info_kind") == "ifb"):
            owned[int(name[6:])] = alias[len(prefix):]

    priorities = {"ip": "45100", "ipv6": "45101"}

    # Dedicated priorities and per-port handles isolate Netwatch's filters.
    def filter_args(device, protocol, port):
        return ("dev", device, "egress", "protocol", protocol, "pref", priorities[protocol],
                "handle", hex(port), "flower")

    def owned_filter(device, protocol, port):
        filters = json.loads(command("tc", "-j", "filter", "show", "dev",
                                     device, "egress", "protocol", protocol,
                                     "pref", priorities[protocol]))
        for rule in filters:
            options = rule.get("options", {})
            if options.get("handle") == port:
                actions = options.get("actions", [])
                if len(actions) != 1 or actions[0].get("to_dev") != f"nw-dl-{port}":
                    raise ValueError("下载限速的 tc 过滤器位置已被占用")
                return True
        return False

    devices = {link["ifname"] for link in links}
    for port, old_interface in owned.items():
        if port in limits and old_interface == interface:
            continue
        if old_interface in devices:
            for protocol in ("ip", "ipv6"):
                if owned_filter(old_interface, protocol, port):
                    command("tc", "filter", "del", *filter_args(old_interface, protocol, port))
        command("ip", "link", "del", f"nw-dl-{port}")
    if not limits:
        return
    if not interface or interface not in devices:
        raise ValueError("未配置可用的下载出口网卡")
    qdiscs = json.loads(command("tc", "-j", "qdisc", "show", "dev", interface))
    if not any(qdisc["kind"] == "clsact" for qdisc in qdiscs):
        command("tc", "qdisc", "add", "dev", interface, "clsact")
    for port, mbps in limits.items():
        device = f"nw-dl-{port}"
        if owned.get(port) != interface:
            command("ip", "link", "add", device, "type", "ifb")
            try:
                command("ip", "link", "set", device, "alias", prefix + interface)
            except (OSError, subprocess.SubprocessError):
                command("ip", "link", "del", device)
                raise
        command("ip", "link", "set", device, "up")
        burst = max(131072, mbps * 1250)
        command("tc", "qdisc", "replace", "dev", device, "root", "tbf",
                "rate", f"{mbps}mbit", "burst", str(burst), "latency", "100ms")
        for protocol in ("ip", "ipv6"):
            exists = owned_filter(interface, protocol, port)
            command("tc", "filter", "replace" if exists else "add", *filter_args(interface, protocol, port),
                    "skip_hw", "ip_proto", "tcp", "src_port", str(port),
                    "action", "mirred", "egress", "redirect", "dev", device)


def xui_remarks():
    try:
        with closing(sqlite3.connect("file:/etc/x-ui/x-ui.db?mode=ro", uri=True, timeout=1)) as db:
            return {(port, tag): remark for port, tag, remark in
                    db.execute("SELECT port, tag, remark FROM inbounds")}
    except sqlite3.Error:
        return {}


def run_agent(args):
    if args.url.startswith("http://") and urlsplit(args.url).hostname not in (
        "localhost", "127.0.0.1", "::1"
    ):
        raise SystemExit("远程控制端必须使用 HTTPS")
    token = os.environ["NETWATCH_AGENT_TOKEN"]
    applied = None
    download_applied = None
    download_error = False
    download_interface = os.environ.get("NETWATCH_DOWNLOAD_INTERFACE")
    while True:
        try:
            if args.demo:
                config = {"inbounds": [
                    {"port": port, "tag": "inbound-" + str(port), "protocol": "vless",
                     "streamSettings": {"security": "reality"}}
                    for port in (49763, 43657)
                ]}
                sockets = (
                    "0 0 192.0.2.20:49763 203.0.113.10:53001\n"
                    "0 0 192.0.2.20:49763 203.0.113.10:53002\n"
                    "0 0 192.0.2.20:49763 198.51.100.20:53003\n"
                )
            else:
                config = json.loads(Path(args.config).read_text())
                sockets = subprocess.check_output(
                    ["ss", "-Htn", "state", "established"], text=True, timeout=4
                )
            ports = collect(config, sockets, {} if args.demo else xui_remarks())
            payload = {"node": args.node, "ports": ports, "applied": applied}
            if download_interface and not args.demo:
                payload["download"] = {"applied": download_applied, "error": download_error}
            body = json.dumps(payload).encode()
            request = Request(args.url.rstrip("/") + "/ingest", body, {
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
            })
            with urlopen(request, timeout=5) as response:
                result = json.load(response)
                print("上报成功", response.status, flush=True)
            if not args.demo and "rules" in result:
                allowed = {row["port"] for row in ports} - {22}
                rules = sorted({(port, address(ip)) for port, ip in result["rules"]
                                if type(port) is int and port in allowed})
                if rules != applied:
                    sync_firewall(rules)
                    applied = rules
                if download_interface and "limits" in result:
                    limits = {port: mbps for port, mbps in result["limits"]
                              if type(port) is int and port in allowed
                              and type(mbps) is int and 1 <= mbps <= 10000}
                    if limits != download_applied or download_error:
                        try:
                            sync_downloads(limits, download_interface)
                        except (OSError, ValueError, subprocess.SubprocessError) as exc:
                            download_error = True
                            print("下载限速配置失败", exc, getattr(exc, "output", ""), flush=True)
                        else:
                            download_applied = limits
                            download_error = False
        except (OSError, ValueError, KeyError, subprocess.SubprocessError, HTTPError) as exc:
            print("采集或上报失败", exc, flush=True)
            if args.once:
                raise SystemExit(1)
        if args.once:
            return
        time.sleep(SAMPLE_INTERVAL)


def archive_sample(db, node, received, ports):
    day = datetime.fromtimestamp(received, CHINA).date().isoformat()
    totals = []
    sources = []
    for row in ports:
        if not isinstance(row, dict):
            continue
        port, listen, tag, counts = (row.get(key) for key in ("port", "listen", "tag", "sources"))
        if type(port) is not int or not isinstance(listen, str) or not isinstance(tag, str):
            continue
        if not isinstance(counts, dict) or not all(type(n) is int and 0 < n <= 2**31 for n in counts.values()):
            continue
        key = (node, port, listen, tag, day)
        totals.append((*key, sum(counts.values())))
        sources.extend((*key, ip, received, received, count) for ip, count in counts.items())

    db.executemany("""
        INSERT INTO inbound_days VALUES (?, ?, ?, ?, ?, 1, ?)
        ON CONFLICT(node, port, listen, tag, day) DO UPDATE SET
            samples = samples + 1, peak = MAX(peak, excluded.peak)
    """, totals)
    db.executemany("""
        INSERT INTO source_days VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(node, port, listen, tag, day, ip) DO UPDATE SET
            first = MIN(first, excluded.first), last = MAX(last, excluded.last),
            peak = MAX(peak, excluded.peak)
    """, sources)


def run_server(args):
    tokens = json.loads(os.environ.get("NETWATCH_NODE_TOKENS", "{}"))
    password = os.environ["NETWATCH_ADMIN_PASSWORD"]
    origin = os.environ.get("NETWATCH_ENROLL_ORIGIN", "")
    ssh_host = os.environ.get("NETWATCH_ENROLL_SSH_HOST", "")
    ssh_port = int(os.environ.get("NETWATCH_ENROLL_SSH_PORT", "22"))
    enrollment = bool(re.fullmatch(r"https://[A-Za-z0-9.-]+", origin)
                      and re.fullmatch(r"[A-Za-z0-9.-]+", ssh_host) and 1 <= ssh_port <= 65535)
    if not password or (not tokens and not enrollment) or any(not token for token in tokens.values()):
        raise SystemExit("需要设置管理密码和各服务器的独立令牌")
    os.umask(0o077)
    with closing(sqlite3.connect(args.db)) as db:
        db.executescript("""
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS samples (
                id INTEGER PRIMARY KEY, node TEXT NOT NULL,
                received INTEGER NOT NULL, ports TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS node_received ON samples (node, received);
            CREATE TABLE IF NOT EXISTS inbound_days (
                node TEXT NOT NULL, port INTEGER NOT NULL, listen TEXT NOT NULL, tag TEXT NOT NULL,
                day TEXT NOT NULL, samples INTEGER NOT NULL, peak INTEGER NOT NULL,
                PRIMARY KEY (node, port, listen, tag, day)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS source_days (
                node TEXT NOT NULL, port INTEGER NOT NULL, listen TEXT NOT NULL, tag TEXT NOT NULL,
                day TEXT NOT NULL, ip TEXT NOT NULL, first INTEGER NOT NULL,
                last INTEGER NOT NULL, peak INTEGER NOT NULL,
                PRIMARY KEY (node, port, listen, tag, day, ip)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS agent_credentials (
                node TEXT PRIMARY KEY, token TEXT NOT NULL,
                public_key TEXT NOT NULL, fingerprint TEXT NOT NULL UNIQUE,
                sample_floor INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS node_settings (
                node TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', applied TEXT
            );
            CREATE TABLE IF NOT EXISTS download_limits (
                node TEXT NOT NULL, port INTEGER NOT NULL, mbps INTEGER NOT NULL,
                PRIMARY KEY (node, port)
            );
            CREATE TABLE IF NOT EXISTS download_status (
                node TEXT PRIMARY KEY, state TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS blocks (
                node TEXT NOT NULL, port INTEGER NOT NULL, ip TEXT NOT NULL,
                PRIMARY KEY (node, port, ip)
            );
        """)

        db.execute("BEGIN IMMEDIATE")
        with db:
            if db.execute("PRAGMA user_version").fetchone()[0] == 0:
                for node, received, ports in db.execute("SELECT node, received, ports FROM samples"):
                    archive_sample(db, node, received, json.loads(ports))
                db.execute("PRAGMA user_version = 1")

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, value, kind="application/json"):
            body = value if isinstance(value, bytes) else json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if status == 401:
                self.send_header("WWW-Authenticate", 'Basic realm="Netwatch"')
            self.end_headers()
            self.wfile.write(body)

        def admin(self):
            expected = "Basic " + base64.b64encode(("admin:" + password).encode()).decode()
            return authorized(self.headers.get("Authorization", ""), expected)

        def enroll(self, payload):
            if not enrollment:
                return self.reply(503, {"error": "主控尚未配置 SSH 注册"})
            node = payload.get("node")
            name = payload.get("name")
            config = payload.get("config")
            interface = payload.get("interface")
            replace = payload.get("action") == "replace_agent"
            if (not isinstance(node, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", node)
                    or not isinstance(name, str) or not 1 <= len(name.strip()) <= 80
                    or not isinstance(config, str) or not re.fullmatch(r"/[A-Za-z0-9_./-]+", config)
                    or not isinstance(interface, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{0,15}", interface)):
                return self.reply(400, {"error": "请检查节点 ID、名称、配置路径或网卡"})
            try:
                host_key = Path("/etc/ssh/ssh_host_ed25519_key.pub").read_text().split()
                if host_key[0] != "ssh-ed25519":
                    raise ValueError("无 ED25519 主机密钥")
                with tempfile.TemporaryDirectory() as work:
                    path = Path(work) / "agent"
                    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)],
                                   check=True, timeout=5, capture_output=True)
                    public = path.with_suffix(".pub").read_text().strip()
                    fingerprint = subprocess.check_output(["ssh-keygen", "-lf", str(path.with_suffix(".pub"))],
                                                          text=True, timeout=5).split()[1]
                    private = path.read_text()
            except (OSError, ValueError, IndexError, subprocess.SubprocessError):
                return self.reply(503, {"error": "无法生成或固定 SSH 密钥"})
            token = secrets.token_hex(32)
            with closing(sqlite3.connect(args.db)) as db, db:
                db.execute("BEGIN IMMEDIATE")
                exists = node in tokens or db.execute(
                    "SELECT 1 FROM node_settings WHERE node = ?", (node,)
                ).fetchone() is not None
                if exists != replace:
                    return self.reply(409, {"error": "节点已存在，请使用换机" if exists else "节点不存在"})
                db.execute("INSERT OR REPLACE INTO agent_credentials VALUES (?, ?, ?, ?, ?)",
                           (node, token, public, fingerprint, db.execute("SELECT COALESCE(MAX(id), 0) FROM samples").fetchone()[0]))
                db.execute("""
                    INSERT INTO node_settings(node, name, applied) VALUES (?, ?, NULL)
                    ON CONFLICT(node) DO UPDATE SET name = excluded.name, applied = NULL
                """, (node, name.strip()))
                db.execute("DELETE FROM download_status WHERE node = ?", (node,))
            known_host = ssh_host if ssh_port == 22 else f"[{ssh_host}]:{ssh_port}"
            data = {"node": node, "token": token, "private_key": private, "host": ssh_host,
                    "ssh_port": ssh_port, "config": config, "interface": interface,
                    "known_hosts": " ".join([known_host, *host_key[:2]])}
            encoded = base64.urlsafe_b64encode(json.dumps(data).encode()).decode()
            installer = shlex.quote(origin + "/deploy/agent-install.sh")
            self.reply(200, {"command": f"curl -fsS {installer} | sudo bash -s -- {shlex.quote(origin)} {shlex.quote(encoded)}"})

        def manage(self, payload):
            if not isinstance(payload, dict):
                return self.reply(400, {})
            if payload.get("action") in ("add_agent", "replace_agent"):
                return self.enroll(payload)
            node = payload.get("node")
            if not isinstance(node, str):
                return self.reply(400, {})
            with closing(sqlite3.connect(args.db)) as db, db:
                sample = db.execute(
                    "SELECT ports FROM samples WHERE node = ? ORDER BY id DESC LIMIT 1",
                    (node,),
                ).fetchone()
                if sample is None:
                    return self.reply(404, {})
                if payload.get("action") == "rename":
                    name = payload.get("name")
                    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
                        return self.reply(400, {})
                    db.execute("""
                        INSERT INTO node_settings(node, name) VALUES (?, ?)
                        ON CONFLICT(node) DO UPDATE SET name = excluded.name
                    """, (node, name.strip()))
                elif payload.get("action") == "download_limit":
                    port, mbps = payload.get("port"), payload.get("mbps")
                    if (type(port) is not int or not 1 <= port <= 65535 or port == 22
                            or type(mbps) is not int or not 0 <= mbps <= 10000):
                        return self.reply(400, {})
                    if mbps:
                        if not any(row["port"] == port for row in json.loads(sample[0])):
                            return self.reply(400, {})
                        if not db.execute("SELECT 1 FROM download_status WHERE node = ?",
                                          (node,)).fetchone():
                            return self.reply(409, {})
                        db.execute("""
                            INSERT INTO download_limits VALUES (?, ?, ?)
                            ON CONFLICT(node, port) DO UPDATE SET mbps = excluded.mbps
                        """, (node, port, mbps))
                    else:
                        db.execute("DELETE FROM download_limits WHERE node = ? AND port = ?",
                                   (node, port))
                else:
                    port, ip, action = payload.get("port"), payload.get("ip"), payload.get("action")
                    if type(port) is not int or not 1 <= port <= 65535 or not isinstance(ip, str):
                        return self.reply(400, {})
                    try:
                        ip = address(ip)
                    except ValueError:
                        return self.reply(400, {})
                    if action == "block":
                        if port == 22 or not any(row["port"] == port for row in json.loads(sample[0])):
                            return self.reply(400, {})
                        db.execute("INSERT OR IGNORE INTO blocks VALUES (?, ?, ?)", (node, port, ip))
                    elif action == "unblock":
                        db.execute("DELETE FROM blocks WHERE node = ? AND port = ? AND ip = ?",
                                   (node, port, ip))
                    else:
                        return self.reply(400, {})
            self.reply(200, {})

        def restore_agent(self, payload):
            if not isinstance(payload, dict):
                return self.reply(400, {"error": "备份格式无效"})
            node, backup, apply = (payload.get(key) for key in ("node", "backup", "apply"))
            if (not isinstance(node, str) or not isinstance(backup, dict)
                    or backup.get("version") != 1 or type(apply) is not bool):
                return self.reply(400, {"error": "只支持 Netwatch 单 Agent JSON 备份"})
            try:
                inbound, sources, blocks, limits = (
                    backup[key] for key in ("inbound_days", "source_days", "blocks", "download_limits")
                )
                if not all(isinstance(rows, list) for rows in (inbound, sources, blocks, limits)):
                    raise ValueError
                def integer(value, minimum=0, maximum=2**53 - 1):
                    if type(value) is not int or not minimum <= value <= maximum:
                        raise ValueError
                    return value
                def identity(row):
                    listen, tag = row["listen"], row["tag"]
                    if not isinstance(listen, str) or not isinstance(tag, str):
                        raise ValueError
                    return integer(row["port"], 1, 65535), listen, tag
                def day(row):
                    return date.fromisoformat(row["day"]).isoformat()
                inbound = [(identity(row), day(row), integer(row["samples"], 1), integer(row["peak"]))
                           for row in inbound]
                sources = [(identity(row), day(row), address(row["ip"]), integer(row["first"]),
                            integer(row["last"]), integer(row["peak"], 1)) for row in sources]
                for _, day_key, _, first, last, _ in sources:
                    if not 0 <= first <= last <= 253402214400:
                        raise ValueError
                    if any(datetime.fromtimestamp(stamp, CHINA).date().isoformat() != day_key
                           for stamp in (first, last)):
                        raise ValueError
                blocks = {(integer(row["port"], 1, 65535), address(row["ip"])) for row in blocks}
                limit_rows = [(integer(row["port"], 1, 65535), integer(row["mbps"], 1, 10000))
                              for row in limits]
                limits = dict(limit_rows)
                if len(limits) != len(limit_rows):
                    raise ValueError
            except (KeyError, TypeError, ValueError, AttributeError, OverflowError, OSError):
                return self.reply(400, {"error": "备份记录无效或文件类型不受支持"})
            with closing(sqlite3.connect(args.db)) as db, db:
                db.execute("BEGIN IMMEDIATE" if apply else "BEGIN")
                sample = db.execute("""
                    SELECT s.ports FROM samples s LEFT JOIN agent_credentials c ON c.node = s.node
                    WHERE s.node = ? AND (c.node IS NULL OR s.id > c.sample_floor)
                    ORDER BY s.id DESC LIMIT 1
                """, (node,)).fetchone()
                if not sample:
                    return self.reply(409, {"error": "请等待目标 Agent 首次上报"})
                target = {identity(row) for row in json.loads(sample[0])}
                backup_identities = {row[0] for row in inbound + sources}
                matched = target & backup_identities
                rule_ports = {port for port, _, _ in matched} - {22}
                unmatched = sorted({port for port, _, _ in backup_identities - matched}
                                   | ({port for port, _ in blocks} | limits.keys()) - rule_ports)
                inbound_rows = [(node, *key, day_key, n, peak)
                                for key, day_key, n, peak in inbound if key in matched]
                source_rows = [(node, *key, day_key, ip, first, last, peak)
                               for key, day_key, ip, first, last, peak in sources if key in matched]
                current_blocks = set(db.execute("SELECT port, ip FROM blocks WHERE node = ?", (node,)))
                new_blocks = sorted({rule for rule in blocks if rule[0] in rule_ports} - current_blocks)
                current_limits = dict(db.execute("SELECT port, mbps FROM download_limits WHERE node = ?", (node,)))
                new_limits = [(port, mbps) for port, mbps in sorted(limits.items())
                              if port in rule_ports and port not in current_limits]
                conflicts = [{"port": port, "current": current_limits[port], "backup": mbps}
                             for port, mbps in sorted(limits.items())
                             if port in rule_ports and port in current_limits and current_limits[port] != mbps]
                if apply:
                    db.executemany("""
                        INSERT INTO inbound_days VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(node, port, listen, tag, day) DO UPDATE SET
                            samples = MAX(samples, excluded.samples), peak = MAX(peak, excluded.peak)
                    """, inbound_rows)
                    db.executemany("""
                        INSERT INTO source_days VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(node, port, listen, tag, day, ip) DO UPDATE SET
                            first = MIN(first, excluded.first), last = MAX(last, excluded.last),
                            peak = MAX(peak, excluded.peak)
                    """, source_rows)
                    db.executemany("INSERT OR IGNORE INTO blocks VALUES (?, ?, ?)",
                                   [(node, port, ip) for port, ip in new_blocks])
                    db.executemany("INSERT OR IGNORE INTO download_limits VALUES (?, ?, ?)",
                                   [(node, port, mbps) for port, mbps in new_limits])
            self.reply(200, {"matched": len(matched), "source_rows": len(source_rows),
                             "blocks": len(new_blocks), "limits": len(new_limits),
                             "conflicts": conflicts, "unmatched": unmatched})

        def do_POST(self):
            if self.path in ("/manage", "/agent-restore"):
                if not self.admin():
                    return self.reply(401, {})
                if (self.headers.get("X-Netwatch-Action") != "1" or
                        self.headers.get_content_type() != "application/json"):
                    return self.reply(403, {})
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    maximum = 8 * 1024 * 1024 if self.path == "/agent-restore" else 4096
                    if not 0 < size <= maximum:
                        return self.reply(413, {"error": "请求大小超出限制"})
                    payload = json.loads(self.rfile.read(size))
                except (ValueError, UnicodeError):
                    return self.reply(400, {})
                return self.restore_agent(payload) if self.path == "/agent-restore" else self.manage(payload)
            if self.path != "/ingest":
                return self.reply(404, {})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 2_000_000:
                    return self.reply(413, {})
                payload = json.loads(self.rfile.read(length))
                node = payload["node"]
                ports = payload["ports"]
                if not isinstance(node, str) or not isinstance(ports, list):
                    return self.reply(400, {})
            except (ValueError, KeyError, TypeError):
                return self.reply(400, {})
            now = int(time.time())
            with closing(sqlite3.connect(args.db)) as db, db:
                db.execute("BEGIN IMMEDIATE")
                credential = db.execute("SELECT token FROM agent_credentials WHERE node = ?", (node,)).fetchone()
                token = credential[0] if credential else tokens.get(node)
                if not token or not authorized(self.headers.get("Authorization", ""), "Bearer " + token):
                    return self.reply(403, {})
                db.execute("INSERT INTO samples(node, received, ports) VALUES (?, ?, ?)",
                           (node, now, json.dumps(ports)))
                archive_sample(db, node, now, ports)
                db.execute("DELETE FROM samples WHERE received < ?", (now - 7 * 86400,))
                db.execute("""
                    INSERT INTO node_settings(node, applied) VALUES (?, ?)
                    ON CONFLICT(node) DO UPDATE SET applied = excluded.applied
                """, (node, json.dumps(payload.get("applied"))))
                rules = db.execute("SELECT port, ip FROM blocks WHERE node = ?", (node,)).fetchall()
                limits = db.execute("SELECT port, mbps FROM download_limits WHERE node = ?",
                                    (node,)).fetchall()
                download = payload.get("download")
                if isinstance(download, dict):
                    db.execute("""
                        INSERT INTO download_status VALUES (?, ?)
                        ON CONFLICT(node) DO UPDATE SET state = excluded.state
                    """, (node, json.dumps(download)))
                else:
                    db.execute("DELETE FROM download_status WHERE node = ?", (node,))
            self.reply(200, {"rules": rules, "limits": limits})

        def do_GET(self):
            url = urlsplit(self.path)
            if url.path == "/health":
                return self.reply(200, {"ok": True})
            if enrollment and url.path.startswith("/deploy/"):
                file = DEPLOY_FILES.get(url.path.removeprefix("/deploy/"))
                if file is None or not file.is_file():
                    return self.reply(404, {})
                return self.reply(200, file.read_bytes(), "application/octet-stream")
            if not self.admin():
                return self.reply(401, {})
            if url.path == "/":
                return self.reply(200, PAGE.read_bytes(), "text/html; charset=utf-8")
            if url.path not in ("/live", "/today", "/yesterday", "/history", "/agent-backup"):
                return self.reply(404, {})
            with closing(sqlite3.connect(args.db)) as db:
                if url.path == "/agent-backup":
                    node = parse_qs(url.query).get("node", [""])[0]
                    db.execute("BEGIN")
                    db.row_factory = sqlite3.Row
                    settings = db.execute("SELECT name FROM node_settings WHERE node = ?", (node,)).fetchone()
                    if not settings:
                        return self.reply(404, {})
                    result = {"version": 1, "node": node, "name": settings["name"] or node,
                              "exported": int(time.time())}
                    for table in ("inbound_days", "source_days", "blocks", "download_limits"):
                        result[table] = [dict(row) for row in db.execute(
                            f"SELECT * FROM {table} WHERE node = ?", (node,)
                        )]
                    return self.reply(200, result)
                if url.path == "/live":
                    rows = db.execute("""
                        WITH latest AS (
                            SELECT id, node, received, ports FROM samples
                            WHERE id IN (SELECT MAX(id) FROM samples GROUP BY node)
                        )
                        SELECT latest.node, latest.received, latest.ports FROM latest
                        LEFT JOIN agent_credentials c ON c.node = latest.node
                        WHERE c.node IS NULL OR latest.id > c.sample_floor
                        UNION ALL
                        SELECT n.node, 0, '[]' FROM node_settings n
                        LEFT JOIN agent_credentials c ON c.node = n.node
                        WHERE NOT EXISTS (SELECT 1 FROM latest WHERE node = n.node
                                          AND (c.node IS NULL OR id > c.sample_floor))
                        ORDER BY 1
                    """)
                    names = {node: (name, json.loads(applied or "null")) for node, name, applied in
                             db.execute("SELECT node, name, applied FROM node_settings")}
                    downloads = {node: json.loads(state) for node, state in
                                 db.execute("SELECT node, state FROM download_status")}
                    limits = {}
                    for node, port, mbps in db.execute("SELECT node, port, mbps FROM download_limits"):
                        limits.setdefault(node, {})[port] = mbps
                    blocks = {}
                    for node, port, ip in db.execute("SELECT node, port, ip FROM blocks"):
                        blocks.setdefault(node, []).append([port, ip])
                    return self.reply(200, [
                        {"node": node, "received": stamp, "ports": json.loads(ports),
                         "name": names.get(node, ("", None))[0] or node,
                         "applied": names.get(node, ("", None))[1],
                         "blocks": blocks.get(node, []),
                         "download": downloads.get(node),
                         "limits": limits.get(node, {})}
                        for node, stamp, ports in rows
                    ])
                params = parse_qs(url.query, keep_blank_values=True)
                try:
                    node = params["node"][0]
                    port = int(params["port"][0])
                    listen = params["listen"][0]
                    tag = params["tag"][0]
                except (KeyError, ValueError):
                    return self.reply(400, {})
                today = datetime.now(CHINA).date()
                if url.path == "/history":
                    try:
                        start = date.fromisoformat(params.get("from", ["0001-01-01"])[0])
                        end = date.fromisoformat(params.get("to", [today.isoformat()])[0])
                    except ValueError:
                        return self.reply(400, {})
                    if start > end:
                        return self.reply(400, {})
                else:
                    start = end = today - timedelta(days=url.path == "/yesterday")
                key = (node, port, listen, tag, start.isoformat(), end.isoformat())
                db.execute("BEGIN")
                samples, peak = db.execute("""
                    SELECT COALESCE(SUM(samples), 0), COALESCE(MAX(peak), 0)
                    FROM inbound_days WHERE node = ? AND port = ? AND listen = ? AND tag = ?
                    AND day BETWEEN ? AND ?
                """, key).fetchone()
                sources = {ip: {"first": first, "last": last, "peak": maximum}
                           for ip, first, last, maximum in db.execute("""
                    SELECT ip, MIN(first), MAX(last), MAX(peak)
                    FROM source_days WHERE node = ? AND port = ? AND listen = ? AND tag = ?
                    AND day BETWEEN ? AND ? GROUP BY ip ORDER BY MAX(last) DESC, ip
                """, key)}
                self.reply(200, {"samples": samples, "peak": peak, "sources": sources})

    ThreadingHTTPServer((args.bind, args.port), Handler).serve_forever()


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    server = commands.add_parser("server")
    server.add_argument("--db", default="netwatch.db")
    server.add_argument("--port", type=int, default=8787)
    server.add_argument("--bind", default="127.0.0.1")
    agent = commands.add_parser("agent")
    agent.add_argument("--url", default="http://127.0.0.1:8787")
    agent.add_argument("--node", required=True)
    agent.add_argument("--config", default="/usr/local/x-ui/bin/config.json")
    agent.add_argument("--once", action="store_true")
    agent.add_argument("--demo", action="store_true")
    args = parser.parse_args()
    if args.command == "server":
        run_server(args)
    else:
        run_agent(args)


if __name__ == "__main__":
    main()
