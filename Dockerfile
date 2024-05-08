FROM debian:bookworm-slim

ARG VERSION=1.20.0

ENV BUILD_PKGS \
    build-essential \
    autoconf \
    libevent-dev \
    libssl-dev \
    bison \
    flex \
    curl \
    libprotobuf-c-dev \
    protobuf-c-compiler \
    libhiredis-dev \
    libnghttp2-dev \
    libexpat-dev \
    libmnl-dev

ENV CONFIGURE_ARGS \
    --sysconfdir=/config \
    --localstatedir=/storage \
    --with-conf-file=/config/unbound.conf \
    --with-libnghttp2 \
    --with-libhiredis \
    --with-libmnl \
    --enable-cachedb \
    --enable-subnet \
    --enable-tfo-client \
    --enable-tfo-server \
    --enable-dnstap \
    --enable-ipset

# Install dependencies
RUN apt-get update && \
    apt-get install -yqq ${BUILD_PKGS}

# Fetch source
WORKDIR /unbound-src
RUN curl -L https://github.com/NLnetLabs/unbound/archive/refs/tags/release-${VERSION}.tar.gz | tar --strip-components 1 -xzf -

# Build the project
RUN ./configure ${CONFIGURE_ARGS} && \
    make && \
    make DESTDIR=/tmp/unbound-install install

# Save result
RUN tar cvzfC /unbound.tar.gz /tmp/unbound-install usr/local config



FROM debian:bookworm-slim

# Environment
ENV RUNTIME_PKGS \
    procps \
    openssl \
    bind9-dnsutils \
    libssl3 \
    libevent-2.1 \
    libhiredis0.14 \
    libprotobuf-c1 \
    libnghttp2-14 \
    libexpat1 \
    libmnl0

# Copy artifacts
COPY --from=0 /unbound.tar.gz /tmp
RUN tar xvzpf /tmp/unbound.tar.gz
RUN rm -f /tmp/unbound.tar.gz

# Install dependencies and create unbound user and group
ARG UID=53
RUN apt-get update && \
    apt-get install -yqq ${RUNTIME_PKGS} && \
    rm -rf /var/lib/apt/lists/* && \
    ldconfig && \
    useradd --system --user-group -M --home /storage --uid ${UID} unbound && \
    install -d -o unbound -g unbound /config /storage && \
    chown -R unbound:unbound /config /storage

# Add default config
ADD unbound.conf /config

# Create extra directories
RUN install -d /config/local.d
RUN install -d /config/conf.d
RUN install -d /config/keys.d

# Add entrypoint
ADD entrypoint.sh /
ENTRYPOINT bash /entrypoint.sh

# Expose port
EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 443/tcp
EXPOSE 853/tcp

# Prepare shared directories
VOLUME /config
VOLUME /storage
