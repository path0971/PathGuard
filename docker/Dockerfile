# Build/test image. fanotify permission events are not exercised here
# (see tests/vm for the real-kernel tests); this only compiles and runs unit tests.
ARG UBUNTU=24.04
FROM ubuntu:${UBUNTU}
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential cmake pkg-config libyara-dev libssl-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
