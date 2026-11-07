# CI image for ret-client: Zephyr build tooling, the SDK toolchain native_sim
# needs, and uv for the Python test peer / rnsd used by the e2e test.
#
# Build it on the runner host (not in a workflow):
#   docker build -t ret-client-ci:latest ci/
#
# Rebuild when a pinned version below changes. The west workspace and the
# compiler cache live in named volumes mounted by the workflow; see
# docs/ci-forgejo.md. Same base and SDK as lion-client's image.
FROM docker.io/zephyrprojectrtos/ci-base:v0.29.3

ENV DEBIAN_FRONTEND=noninteractive

# pipefail: a failed `curl | sh` must fail the build, not silently fall back
# (e.g. to the distro's older Node).
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# gcc-multilib: native_sim builds 32-bit and links against the host libc.
# Node: the runner executes JavaScript actions (actions/checkout) with the
# job container's node. jq: scripts/forgejo.sh.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc-multilib g++-multilib \
        ccache curl ca-certificates xz-utils jq \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && node --version

# uv runs tools/rns_peer (rns pinned in its uv.lock): the e2e peer, rnsd,
# the golden-vector check and ruff.
ARG UV_VERSION=0.13.0
RUN curl -LsSf "https://astral.sh/uv/${UV_VERSION}/install.sh" \
        | env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh \
    && uv --version

# Pinned to zephyr/SDK_VERSION on the revision west-vanilla.yml tracks
# (v4.2.2 wants 0.17.4). Only x86_64-zephyr-elf for now: native_sim. Add
# arm-zephyr-eabi with the nRF9151 job.
ARG ZSDK_VERSION=0.17.4
RUN cd /opt \
    && curl -fsSL -O "https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v${ZSDK_VERSION}/zephyr-sdk-${ZSDK_VERSION}_linux-x86_64_minimal.tar.xz" \
    && tar xf "zephyr-sdk-${ZSDK_VERSION}_linux-x86_64_minimal.tar.xz" \
    && rm "zephyr-sdk-${ZSDK_VERSION}_linux-x86_64_minimal.tar.xz" \
    && cd "zephyr-sdk-${ZSDK_VERSION}" \
    && ./setup.sh -t x86_64-zephyr-elf -c

# The west workspace is bind-mounted from a host volume owned by another
# user; without this every git call west makes refuses ("dubious ownership").
RUN git config --system --add safe.directory '*'

ENV ZEPHYR_TOOLCHAIN_VARIANT=zephyr \
    ZEPHYR_SDK_INSTALL_DIR=/opt/zephyr-sdk-${ZSDK_VERSION} \
    CCACHE_DIR=/ccache \
    UV_CACHE_DIR=/ccache/uv

RUN mkdir -p /west-workspace /ccache
