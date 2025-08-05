# --------- Base Image ----------
FROM ubuntu:22.04 as base

ENV LANG en_US.utf8
ENV TZ="Asia/Singapore"

# Fix timezone for tzdata
RUN ln -snf /usr/share/zoneinfo/$CONTAINER_TIMEZONE /etc/localtime && echo $CONTAINER_TIMEZONE > /etc/timezone

RUN apt-get update && DEBIAN_FRONTEND=noninteractive \
    apt-get install -yq \
    locales sudo tzdata git wget curl software-properties-common net-tools iproute2 \
    && rm -rf /var/lib/apt/lists/* \
	&& localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8 && \
    dpkg-reconfigure -f noninteractive tzdata

# Workaround for CVE-2022-24765
RUN git config --system --add safe.directory '*'


# --------- OAI Dev Image ----------
# Base Image
FROM base as oai-cu-du-base
ARG OAI_TARGET=SIMU
ENV BUILD_UHD_FROM_SOURCE=True
ENV UHD_VERSION=4.4.0.0
ENV DEBIAN_FRONTEND=noninteractive
RUN git clone https://gitlab.eurecom.fr/oai/openairinterface5g --recursive --depth=1 oai && \
    cd oai/cmake_targets && ./build_oai -I --install-optional-packages -w ${OAI_TARGET} --gNB --nrUE --build-e2 --noavx512 --ninja \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /oai
# Main Image (Fast git pull & build)
FROM oai-cu-du-base as oai-cu-du
ARG CACHEBUST=1
RUN git fetch --depth 1 && git reset --hard \
    && git submodule init && git submodule update \
    && cd cmake_targets \
    && ./build_oai -w ${OAI_TARGET} --gNB --nrUE --build-e2 --noavx512 --ninja
ARG CACHEBUST=0
WORKDIR /oai/cmake_targets/ran_build/build

# --------- Flexric Dev Image ----------
# Base Image
FROM base as flexric-base
RUN apt-get update && DEBIAN_FRONTEND=noninteractive \
    apt-get install -yq \
    libsctp-dev python3 cmake-curses-gui libpcre2-dev python3-dev python3-pip \
    gcc-10 automake autotools-dev bison flex pkg-config \
    libconfig-dev libconfig++-dev default-libmysqlclient-dev && \
    rm -rf /var/lib/apt/lists/* && python3 -m pip install -U ninja cmake

RUN git clone https://github.com/swig/swig.git && cd swig \
    git checkout release-4.1  && ./autogen.sh && ./configure --prefix=/usr/ && \
    make -j$(($(nproc) /2)) && make install && cd .. && rm swig -rdf
# Main Image
FROM flexric-base as flexric
ARG KPM_VERSION=KPM_V2_03
ARG FLEXRIC_COMMIT=dev
RUN gcc --version && git clone https://gitlab.eurecom.fr/mosaic5g/flexric.git && cd flexric && \
    git checkout ${FLEXRIC_COMMIT} && \
    mkdir build && cd build && cmake -DCMAKE_C_COMPILER=gcc-10 -DKPM_VERSION=${KPM_VERSION} -GNinja .. && ninja && \
    ninja install
WORKDIR /flexric

