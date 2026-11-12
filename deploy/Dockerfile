FROM python:3.11-slim-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY netwatch.py index.html ./
COPY deploy/agent-install.sh deploy/netwatch-agent.service deploy/netwatch-tunnel.service ./deploy/
CMD ["python3", "netwatch.py", "server", "--bind", "0.0.0.0", "--db", "/var/lib/netwatch/netwatch.db"]
