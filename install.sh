#!/bin/sh
# Install porkbun-ud on this machine. Run as root from the project directory.
# Safe to re-run: existing config and credentials are never overwritten.
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root." >&2
    exit 1
fi

src=$(cd "$(dirname "$0")" && pwd)
etc=/etc/porkbun-ud

if ! python3 -c 'import tomllib' 2>/dev/null; then
    echo "python3 3.11 or newer is required (apt install python3)." >&2
    exit 1
fi

install -m 755 "$src/porkbun_ud.py" /usr/local/bin/porkbun-ud
install -m 644 "$src/systemd/porkbun-ud.service" /etc/systemd/system/porkbun-ud.service
install -m 644 "$src/systemd/porkbun-ud.timer" /etc/systemd/system/porkbun-ud.timer

install -d -m 755 "$etc"
fresh=0
if [ ! -e "$etc/config.toml" ]; then
    install -m 644 "$src/config.example.toml" "$etc/config.toml"
    fresh=1
fi
if [ ! -e "$etc/credentials.env" ]; then
    (umask 077 && printf 'PORKBUN_API_KEY=\nPORKBUN_SECRET_API_KEY=\n' > "$etc/credentials.env")
    fresh=1
fi

systemctl daemon-reload

if [ "$fresh" -eq 1 ]; then
    cat <<EOF
Installed. Next:
  1. Put your API keys in  $etc/credentials.env
  2. List your domains in  $etc/config.toml
  3. Test:    systemctl start porkbun-ud.service && journalctl -u porkbun-ud -n 20
  4. Enable:  systemctl enable --now porkbun-ud.timer
EOF
else
    systemctl enable --now porkbun-ud.timer
    echo "Updated. Timer is enabled; logs: journalctl -u porkbun-ud"
fi
