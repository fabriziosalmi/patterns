#!/usr/bin/env bash
# Provision a Linux box (Ubuntu 24.04) so `scripts/ci-local.sh` can reproduce this
# repository's GitHub Actions workflows locally, before pushing.
#
# Run once as root, on the box (the `ci-patterns` LXC). Idempotent: re-running only fills
# in what is missing. Everything CI-related runs as an unprivileged user (default `ci`),
# like the GitHub runner.
#
# What the workflows need, and where this installs it:
#
#   Python 3.11, 3.13   test_ir.yml (matrix), the conformance and nightly jobs (3.11):
#                       `uv` virtual environments, one for each version. The system
#                       Python is 3.12, which no workflow uses.
#   nginx               test_nginx.yml and tests/test_nginx_blocking.py run the binary.
#                       The distribution's service is disabled: the tests start their own.
#   Docker              test_conformance.yml: Apache with ModSecurity, HAProxy, Traefik and
#                       Envoy are run as containers, from images pulled here once.
#   Node 20             docs.yml (VitePress).
#   actionlint          the workflows themselves (an extra stage, not a CI job).
#
# LXC note: Docker inside a Proxmox LXC needs `nesting=1,keyctl=1,mknod=1` and, on the
# hosts here, the `lxc.apparmor.profile: unconfined` / `lxc.cap.drop:` / device lines the
# other CI containers use. See ci-linuxslm (CT 405) or ci-zion (CT 406) for the exact conf.
set -euo pipefail

CI_USER="${CI_USER:-ci}"
NODE_MAJOR="${NODE_MAJOR:-20}"
PYTHONS="${PYTHONS:-3.11 3.13}"
# The images the conformance tests start. Keep in step with IMAGE in tests/test_*_blocking.py.
IMAGES="${IMAGES:-owasp/modsecurity:apache haproxy:latest traefik:3.7 envoyproxy/envoy:v1.32.13}"

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
export DEBIAN_FRONTEND=noninteractive

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

say "apt packages"
apt-get update -y
apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg git jq rsync sudo unzip xz-utils lsb-release \
  build-essential python3 python3-pip python3-venv python3-yaml \
  nginx iproute2 procps openssl
# The tests start their own nginx on their own ports; the packaged service would hold port 80.
systemctl disable --now nginx >/dev/null 2>&1 || true

say "AppArmor user space off"
# Docker in an LXC: with the `apparmor` package installed, which the Ubuntu template has, Docker
# tries to load its `docker-default` profile and the container's AppArmor namespace refuses
# ("Could not check if docker-default AppArmor profile was loaded: ... permission denied"), and
# no container starts. ci-zion (CT 406) works because it does not have the package. The LXC is
# `lxc.apparmor.profile: unconfined` anyway, so there is nothing to confine with.
apt-get purge -y apparmor >/dev/null 2>&1 || true

say "Docker"
if ! command -v docker >/dev/null; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker || true

say "user '$CI_USER'"
id "$CI_USER" >/dev/null 2>&1 || useradd -m -s /bin/bash "$CI_USER"
usermod -aG docker "$CI_USER"
# GitHub runners have passwordless sudo; the workflows call `sudo apt-get`.
echo "$CI_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/90-ci-user
chmod 0440 /etc/sudoers.d/90-ci-user
# The same keys that open root open the CI user, so `scripts/ci-remote.sh` can rsync as it.
if [ -f /root/.ssh/authorized_keys ]; then
  install -d -m 0700 -o "$CI_USER" -g "$CI_USER" "/home/$CI_USER/.ssh"
  install -m 0600 -o "$CI_USER" -g "$CI_USER" /root/.ssh/authorized_keys "/home/$CI_USER/.ssh/authorized_keys"
fi

say "Node $NODE_MAJOR"
if ! command -v node >/dev/null || [ "$(node -p 'process.versions.node.split(".")[0]')" != "$NODE_MAJOR" ]; then
  base="https://nodejs.org/dist/latest-v${NODE_MAJOR}.x"
  tarball="$(curl -fsSL "$base/SHASUMS256.txt" | awk '/linux-x64.tar.xz/ {print $2}')"
  curl -fsSL "$base/$tarball" -o "/tmp/$tarball"
  # verify against the published checksum before unpacking
  (cd /tmp && curl -fsSL "$base/SHASUMS256.txt" | grep " $tarball\$" | sha256sum -c -)
  tar -xJf "/tmp/$tarball" -C /usr/local --strip-components=1
  rm -f "/tmp/$tarball"
fi

say "uv, and Python $PYTHONS (as $CI_USER)"
# `uv` from PyPI into a venv of its own, so nothing touches the system Python (PEP 668).
python3 -m venv /opt/ci-tools
/opt/ci-tools/bin/pip install --quiet --upgrade pip uv
ln -sf /opt/ci-tools/bin/uv /usr/local/bin/uv
sudo -u "$CI_USER" -H bash -s "$PYTHONS" <<'EOS'
set -euo pipefail
# from the home directory: `uv` looks for a project file in the current one, and this script
# was started from /root, which `$CI_USER` cannot read
cd "$HOME"
for version in $1; do
  uv python install "$version"
  # the environment scripts/ci-local-wf.py would make on first use, so the first run is not slow
  [ -x "$HOME/.cache/ci-local/venv-$version/bin/python" ] \
    || uv venv --seed --python "$version" "$HOME/.cache/ci-local/venv-$version"
done
EOS

say "actionlint"
if ! command -v actionlint >/dev/null; then
  curl -fsSL https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash | bash -s -- latest /usr/local/bin
fi

say "images the conformance tests run (as $CI_USER)"
for image in $IMAGES; do
  sudo -u "$CI_USER" -H docker pull --quiet "$image" >/dev/null && echo "  $image"
done

say "done"
echo "as $CI_USER:  cd <repo> && scripts/ci-local.sh --list"
echo "from a laptop: CI_HOST=$CI_USER@<this box> scripts/ci-remote.sh fast"
