# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.224.3/containers/rust/.devcontainer/base.Dockerfile

# [Choice] Debian OS version (use bullseye on local arm64/Apple Silicon): buster, bullseye
ARG VARIANT="buster"
FROM mcr.microsoft.com/vscode/devcontainers/rust:0-${VARIANT}

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends  build-essential git libftdi-dev libftdi1 doxygen python3-pip libsdl2-dev curl cmake libusb-1.0-0-dev scons gtkwave libsndfile1-dev rsync autoconf automake texinfo libtool pkg-config libsdl2-ttf-dev



ADD "https://github.com/pulp-platform/pulp-riscv-gnu-toolchain/releases/download/v1.0.16/v1.0.16-pulp-riscv-gcc-ubuntu-18.tar.bz2" /tmp/pulp-riscv-gnu
WORKDIR /tmp/
RUN tar -xvf /tmp/pulp-riscv-gnu && mv /tmp/v1.0.16-pulp-riscv-gcc-ubuntu-18 /opt/riscv
RUN pip install argcomplete pyelftools

ENV PATH "$PATH:/opt/riscv/bin"
ENV PULP_RISCV_GCC_TOOLCHAIN "/opt/riscv"

WORKDIR /opt/
RUN bash -c "git clone https://github.com/pulp-platform/pulp-sdk && cd pulp-sdk && source configs/pulp-open.sh && make build"
RUN echo "source /opt/pulp-sdk/configs/pulp-open.sh" >> /home/vscode/.bashrc
    
