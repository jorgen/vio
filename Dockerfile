FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    gcc-14 g++-14 \
    clang-18 libc++-18-dev libc++abi-18-dev \
    ninja-build python3 python3-pip git ca-certificates ccache \
    golang-go \
    pkg-config libx11-dev libxkbcommon-dev libwayland-dev libwayland-bin wayland-protocols \
    xvfb weston libegl1 libegl-mesa0 libwayland-egl1 libgl1-mesa-dri \
    libvulkan-dev mesa-vulkan-drivers \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --break-system-packages cmake

ENV CC=gcc-14
ENV CXX=g++-14
