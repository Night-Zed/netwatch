FROM python:3.11-slim-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*
ARG NETWATCH_UID
ARG NETWATCH_GID
RUN test "$NETWATCH_UID" -gt 0 && test "$NETWATCH_GID" -gt 0 \
    && (getent group "$NETWATCH_GID" >/dev/null || groupadd -g "$NETWATCH_GID" netwatch) \
    && (getent passwd "$NETWATCH_UID" >/dev/null || useradd -M -u "$NETWATCH_UID" -g "$NETWATCH_GID" -s /usr/sbin/nologin netwatch)
WORKDIR /app
COPY netwatch.py index.html ./
COPY deploy/agent-install.sh deploy/netwatch-agent.service deploy/netwatch-tunnel.service ./deploy/
CMD ["python3", "netwatch.py", "server", "--bind", "0.0.0.0", "--db", "/var/lib/netwatch/netwatch.db"]
