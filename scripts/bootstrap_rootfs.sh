#!/usr/bin/env bash
set -euo pipefail

ROOTFS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/rootfs"
ALPINE_VERSION="3.20.0"
ALPINE_TAR="alpine-minirootfs-${ALPINE_VERSION}-x86_64.tar.gz"
ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/${ALPINE_TAR}"

echo "[*] Preparing sandbox rootfs at: ${ROOTFS_DIR}"

if [ -d "${ROOTFS_DIR}" ]; then
    echo "[!] Directory ${ROOTFS_DIR} already exists. Skipping download."
else
    mkdir -p "${ROOTFS_DIR}"
    echo "[*] Downloading Alpine Linux minirootfs..."
    curl -fsSL -o "/tmp/${ALPINE_TAR}" "${ALPINE_URL}"
    
    echo "[*] Extracting rootfs..."
    sudo tar -xzf "/tmp/${ALPINE_TAR}" -C "${ROOTFS_DIR}"
    rm "/tmp/${ALPINE_TAR}"
fi

echo "[*] Installing runtimes (Python 3, GCC/G++, musl-dev)..."
sudo cp /etc/resolv.conf "${ROOTFS_DIR}/etc/resolv.conf"
sudo chroot "${ROOTFS_DIR}" /sbin/apk update
sudo chroot "${ROOTFS_DIR}" /sbin/apk add --no-cache python3 gcc g++ musl-dev
sudo rm -f "${ROOTFS_DIR}/etc/resolv.conf"

echo "[*] Setting up workspace..."
sudo mkdir -p "${ROOTFS_DIR}/workspace" "${ROOTFS_DIR}/tmp"
sudo chmod 777 "${ROOTFS_DIR}/workspace" "${ROOTFS_DIR}/tmp"

echo "[+] Sandbox rootfs setup complete!"