#!/bin/bash

set -e

IMAGE_NAME="rust-musl"
CARGO_CACHE_DIR="${HOME}/.cargo"

# Create cargo cache directories if they don't exist
mkdir -p "${CARGO_CACHE_DIR}/registry"
mkdir -p "${CARGO_CACHE_DIR}/git"

# Check if the Docker image exists
if ! docker image inspect "$IMAGE_NAME" &> /dev/null; then
    echo "Docker image '$IMAGE_NAME' not found. Building it..."

    # Check if Dockerfile exists
    if [ ! -f "Dockerfile" ]; then
        echo "Error: Dockerfile not found in current directory"
        exit 1
    fi

    docker build -t "$IMAGE_NAME" .
    echo "Image built successfully!"
else
    echo "Using existing '$IMAGE_NAME' image"
fi

echo "Building project..."
docker run --rm \
  --security-opt apparmor=unconfined \
  -v "$PWD":/project \
  -v "${CARGO_CACHE_DIR}/registry:/usr/local/cargo/registry" \
  -v "${CARGO_CACHE_DIR}/git:/usr/local/cargo/git" \
  -w /project \
  -e RUSTFLAGS="-C target-feature=+crt-static" \
  "$IMAGE_NAME" \
  cargo build --release --target x86_64-unknown-linux-musl

echo "Build complete! Binary is in target/x86_64-unknown-linux-musl/release/"