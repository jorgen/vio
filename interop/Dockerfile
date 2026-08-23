# The image the QUIC Interop Runner starts, as both client and server.
#
# Build from the repository root:
#   docker build -f interop/Dockerfile -t vio-interop .
#
# The dependencies are fetched at configure time, so the build stage needs
# network access.

FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        g++-14 \
        git \
        ninja-build \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# 24.04 ships 3.28 and this tree asks for 3.30. The runtime image below is the
# same Ubuntu release, so what is built here runs there unchanged.
RUN curl -fsSL https://github.com/Kitware/CMake/releases/download/v3.31.6/cmake-3.31.6-linux-x86_64.tar.gz \
    | tar -xz --strip-components=1 -C /usr/local

WORKDIR /src
COPY . /src

# Statically linked against libstdc++ and libgcc so the binary does not depend
# on the runtime image having the same toolchain as the one that built it.
RUN cmake -S . -B build-interop -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DVIO_BUILD_SHARED=OFF \
        -DCMAKE_C_COMPILER=gcc-14 \
        -DCMAKE_CXX_COMPILER=g++-14 \
        -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc" \
    && cmake --build build-interop --target vio_interop_endpoint -j "$(nproc)"

FROM martenseemann/quic-network-simulator-endpoint:latest

WORKDIR /vio
COPY --from=builder /src/build-interop/test/vio_interop_endpoint ./vio_interop_endpoint
COPY interop/run_endpoint.sh ./
RUN chmod +x run_endpoint.sh

ENTRYPOINT [ "./run_endpoint.sh" ]
