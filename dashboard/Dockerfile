FROM node:22-bookworm-slim AS web
WORKDIR /build
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/index.html web/vite.config.js ./
COPY web/src/ ./src/
RUN npm run build

FROM rust:1.94.1-slim-bookworm AS api
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake g++ make \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY api/Cargo.toml api/Cargo.lock ./
COPY api/src/ ./src/
RUN cargo build --release --locked

FROM debian:bookworm-slim
ARG VERSION=0.3.0
LABEL org.opencontainers.image.title="Stow Dashboard" \
      org.opencontainers.image.source="https://github.com/VijinV/stow" \
      org.opencontainers.image.version="${VERSION}"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 0700 -o 10001 -g 10001 /var/lib/stow
COPY --from=api /build/target/release/stow-dashboard /usr/local/bin/stow-dashboard
COPY --from=web /build/dist /opt/stow/web
ENV STOW_LISTEN=0.0.0.0:8787 \
    STOW_DB=/var/lib/stow/stow.sqlite3 \
    STOW_WEB_DIR=/opt/stow/web
USER 10001:10001
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/stow-dashboard"]
