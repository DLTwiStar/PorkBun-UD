#!/bin/sh
# Install or upgrade porkbun-ud on this machine. Run as root from the project
# directory. Safe to re-run: config, API keys and timer settings are kept.
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root." >&2
    exit 1
fi

src=$(cd "$(dirname "$0")" && pwd)

if ! python3 -c 'import tomllib' 2>/dev/null; then
    echo "python3 3.11 or newer is required (apt install python3)." >&2
    exit 1
fi

install -m 755 "$src/porkbun_ud.py" /usr/local/bin/porkud
rm -f /usr/local/bin/porkbun-ud  # name used before the porkud command existed
install -m 644 "$src/systemd/porkbun-ud.service" /etc/systemd/system/porkbun-ud.service
install -m 644 "$src/systemd/porkbun-ud.timer" /etc/systemd/system/porkbun-ud.timer
install -d -m 755 /etc/porkbun-ud
systemctl daemon-reload

cat <<EOF
Installed. To set up:
  porkud auth                    enter your Porkbun API keys
  porkud add home.example.com    add each name to keep updated
  porkud update --dry-run        preview, then run without --dry-run
  porkud enable                  turn on automatic updates
See everything with: porkud --help
EOF
