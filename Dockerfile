FROM rust:alpine

RUN apk add --no-cache \
    bash \
    curl \
    gcc \
    musl-dev \
    openssl-dev \
    pkgconfig \
    git \
    pcsc-lite-dev \
    pcsc-lite-static

WORKDIR /project