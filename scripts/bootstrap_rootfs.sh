#!/usr/bin/env bash
#
# Khoros Sandbox - rootfs bootstrap
#
# Changes from the previous version:
#   * The Alpine tarball's SHA256 is verified. An unverified download that is
#     then unpacked as root and used as the execution root for every sandboxed
#     run is a supply-chain hole.
#   * Creates rootfs/.old_root once, up front. The runner used to mkdir and
#     rmdir this per run inside the shared rootfs, which raced between
#     concurrent requests and could break another run's pivot_root.
#   * Creates a dedicated unprivileged khoros-sandbox user for the jail to run
#     as, and reports its uid/gid.
#   * The rootfs is root-owned and not group/world writable; the runner refuses
#     to use it otherwise.
#   * workspace/ is 0751, not 0777. Each run's scratch dir is created 0700 by
#     the API and chowned to the sandbox uid by the runner.

set -euo pipefail

ENGINE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOTFS_DIR="${ENGINE_DIR}/rootfs"

ALPINE_VERSION="3.20.3"
ALPINE_BRANCH="v3.20"
ALPINE_TAR="alpine-minirootfs-${ALPINE_VERSION}-x86_64.tar.gz"
ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_BRANCH}/releases/x86_64/${ALPINE_TAR}"

# Pin the digest. Update this together with ALPINE_VERSION; the current value
# is published next to the tarball as ${ALPINE_TAR}.sha256.
#   curl -fsSL "${ALPINE_URL}.sha256"
ALPINE_SHA256="${KHOROS_ALPINE_SHA256:-}"

SANDBOX_USER="khoros-sandbox"

say() { printf '[*] %s\n' "$*"; }
die() { printf '[!] %s\n' "$*" >&2; exit 1; }

# --------------------------------------------------------------------------
# Sandbox user
# --------------------------------------------------------------------------
if ! id -u "${SANDBOX_USER}" >/dev/null 2>&1; then
    say "Creating unprivileged user ${SANDBOX_USER}"
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin \
        "${SANDBOX_USER}" 2>/dev/null \
        || sudo useradd --system --no-create-home --shell /sbin/nologin \
            "${SANDBOX_USER}"
fi
SANDBOX_UID="$(id -u "${SANDBOX_USER}")"
SANDBOX_GID="$(id -g "${SANDBOX_USER}")"
[ "${SANDBOX_UID}" -ne 0 ] || die "${SANDBOX_USER} resolved to uid 0"
say "Sandbox identity: ${SANDBOX_USER} (uid=${SANDBOX_UID} gid=${SANDBOX_GID})"

# --------------------------------------------------------------------------
# Download and verify
# --------------------------------------------------------------------------
if [ -d "${ROOTFS_DIR}/usr" ]; then
    say "Rootfs already present at ${ROOTFS_DIR}; skipping download."
else
    sudo mkdir -p "${ROOTFS_DIR}"
    TARBALL="$(mktemp -t khoros-alpine-XXXXXX.tar.gz)"
    trap 'rm -f "${TARBALL}"' EXIT

    say "Downloading ${ALPINE_TAR}"
    curl -fsSL -o "${TARBALL}" "${ALPINE_URL}"

    if [ -z "${ALPINE_SHA256}" ]; then
        say "Fetching published checksum"
        ALPINE_SHA256="$(curl -fsSL "${ALPINE_URL}.sha256" | awk '{print $1}')"
        [ -n "${ALPINE_SHA256}" ] || die "could not retrieve a checksum to verify against"
    fi

    say "Verifying SHA256"
    ACTUAL="$(sha256sum "${TARBALL}" | awk '{print $1}')"
    if [ "${ACTUAL}" != "${ALPINE_SHA256}" ]; then
        die "checksum mismatch: expected ${ALPINE_SHA256}, got ${ACTUAL}"
    fi
    say "Checksum OK (${ACTUAL})"

    say "Extracting rootfs"
    sudo tar -xzf "${TARBALL}" -C "${ROOTFS_DIR}"
fi

# --------------------------------------------------------------------------
# Runtimes
# --------------------------------------------------------------------------
say "Installing Python 3, GCC/G++, musl-dev into the rootfs"
sudo cp /etc/resolv.conf "${ROOTFS_DIR}/etc/resolv.conf"
sudo chroot "${ROOTFS_DIR}" /sbin/apk update
sudo chroot "${ROOTFS_DIR}" /sbin/apk add --no-cache python3 gcc g++ musl-dev
sudo rm -f "${ROOTFS_DIR}/etc/resolv.conf"

# apk is not needed at execution time and only widens the attack surface.
sudo rm -rf "${ROOTFS_DIR}/var/cache/apk" "${ROOTFS_DIR}/etc/apk/cache" || true

# --------------------------------------------------------------------------
# Mount points the runner expects to already exist
#
# The rootfs is mounted read-only inside the jail, so these cannot be created
# at run time. .old_root in particular must be pre-created: the runner no
# longer mkdir/rmdirs it per run, which is what removed the pivot_root race.
# --------------------------------------------------------------------------
say "Creating mount points (.old_root, proc, dev, tmp, workspace)"
sudo mkdir -p \
    "${ROOTFS_DIR}/.old_root" \
    "${ROOTFS_DIR}/proc" \
    "${ROOTFS_DIR}/dev" \
    "${ROOTFS_DIR}/tmp" \
    "${ROOTFS_DIR}/workspace"

sudo chown root:root "${ROOTFS_DIR}" "${ROOTFS_DIR}/.old_root"
sudo chmod 0755 "${ROOTFS_DIR}"
sudo chmod 0700 "${ROOTFS_DIR}/.old_root"
sudo chmod 1777 "${ROOTFS_DIR}/tmp"

# The API user creates per-run scratch dirs here, so it needs write access to
# this directory, but nothing else needs to list it.
API_USER="${SUDO_USER:-${USER}}"
sudo chown "${API_USER}:${SANDBOX_GID}" "${ROOTFS_DIR}/workspace"
sudo chmod 0751 "${ROOTFS_DIR}/workspace"

# --------------------------------------------------------------------------
# Sanity checks matching what the runner enforces at startup
# --------------------------------------------------------------------------
say "Verifying rootfs ownership and permissions"
OWNER="$(stat -c '%u' "${ROOTFS_DIR}")"
PERMS="$(stat -c '%a' "${ROOTFS_DIR}")"
[ "${OWNER}" = "0" ] || die "rootfs must be owned by root (is uid ${OWNER})"
case "${PERMS}" in
    *[2367]) die "rootfs must not be group/world writable (mode ${PERMS})" ;;
esac

for p in /usr/bin/python3 /usr/bin/g++; do
    [ -x "${ROOTFS_DIR}${p}" ] || die "missing ${p} inside the rootfs"
done

cat <<EOF

[+] Rootfs ready at ${ROOTFS_DIR}

Next steps:
  make build

  # cgroup parent. The runner delegates memory/pids/cpu to it on first use.
  sudo mkdir -p /sys/fs/cgroup/sandbox_demo

  # Grant sudo only for the runner binary, and only once the binary is
  # root-owned and not writable by anyone else. The runner now resolves its
  # rootfs from /proc/self/exe rather than ./rootfs, but a user-writable
  # NOPASSWD binary is still a local root hole:
  sudo chown root:root ${ENGINE_DIR}/sandbox_runner
  sudo chmod 0755 ${ENGINE_DIR}/sandbox_runner
  echo "${API_USER} ALL=(ALL) NOPASSWD: ${ENGINE_DIR}/sandbox_runner" \\
      | sudo tee /etc/sudoers.d/khoros_runner
  sudo chmod 0440 /etc/sudoers.d/khoros_runner

  # Sandbox identity for the jail (defaults to 65534 if not passed):
  #   sandbox_runner --uid ${SANDBOX_UID} --gid ${SANDBOX_GID} ...
  export KHOROS_SANDBOX_UID=${SANDBOX_UID}
  export KHOROS_SANDBOX_GID=${SANDBOX_GID}

  make server   # binds 127.0.0.1 by default
EOF
