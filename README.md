# porkbun-ud

Dynamic DNS updater for Porkbun. It finds this network's public IP and points
the A/AAAA records you list at it. One Python file, standard library only,
run every 5 minutes by a systemd timer.

## How it finds the WAN IP

It asks an outside server which address the request came from (Porkbun's `/ip`
endpoint, with ipify as a fallback). Behind NAT that is the gateway's WAN
address. Private and CGNAT addresses are rejected and never written to DNS.

IPv6 is different: the address detected is this machine's own, not the
router's. Set `ipv6 = false` for domains whose services are not on this host.
With no public IPv6 at all, AAAA records are simply left alone.

## Porkbun setup

1. Create an API key at <https://porkbun.com/account/api> (needs DNS read/write).
2. Turn on **API Access** for each domain in its Porkbun settings.

## Install (Debian/Proxmox LXC, as root)

Needs Python 3.11+ (Debian 12 or newer).

```sh
./install.sh
nano /etc/porkbun-ud/credentials.env   # PORKBUN_API_KEY / PORKBUN_SECRET_API_KEY
nano /etc/porkbun-ud/config.toml       # your domains, see config.example.toml
systemctl start porkbun-ud.service && journalctl -u porkbun-ud -n 20
systemctl enable --now porkbun-ud.timer
```

Re-run `./install.sh` to upgrade; it leaves your config and credentials alone.

If the service fails with `status=226/NAMESPACE`, enable nesting on the
container (Proxmox: Options > Features > Nesting).

## Running by hand

```sh
export PORKBUN_API_KEY=pk1_... PORKBUN_SECRET_API_KEY=sk1_...
./porkbun_ud.py -c config.toml --dry-run -v   # show what would change
./porkbun_ud.py -c config.toml                # do it
```

| Flag | Meaning |
|---|---|
| `-c, --config PATH` | config file (default `/etc/porkbun-ud/config.toml`) |
| `-n, --dry-run` | report changes without making them |
| `-f, --force` | check every record even if the IP has not changed |
| `-v, --verbose` | debug logging |

Exit status: 0 on success, 1 if any record failed, 2 for a config or credentials problem.

## Behaviour

- A missing record is created; a record with a different address is updated; a correct one is left alone.
- The last applied IP is remembered, so a normal run makes no Porkbun DNS calls. Records are re-checked in full when the IP or config changes, once a day, or with `--force`.
- A failure on one record does not stop the others, and failed runs are retried on the next tick.

## Tests

```sh
python3 -m unittest discover tests
```
