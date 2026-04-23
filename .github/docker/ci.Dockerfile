FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /opt/nasfs

COPY .github/scripts/install-ubuntu-deps.sh /tmp/install-ubuntu-deps.sh

RUN chmod +x /tmp/install-ubuntu-deps.sh \
    && /tmp/install-ubuntu-deps.sh \
    && rm -f /tmp/install-ubuntu-deps.sh \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
