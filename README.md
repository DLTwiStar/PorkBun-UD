# porkbun-ud

Dynamic DNS updater for Porkbun. It finds this network's public IP and points
the A/AAAA records you choose at it. One Python file, standard library only,
run on a schedule by a systemd timer and managed with the `porkud` command.

## Porkbun setup

1. Create an API key at <https://porkbun.com/account/api> (needs DNS read/write).
2. Turn on **API Access** for each domain in its Porkbun settings.

## Install (Debian/Proxmox LXC, as root)

Needs Python 3.11+ (Debian 12 or newer).

```sh
./install.sh
porkud auth                    # enter and verify your API keys
porkud add home.example.com    # repeat for each name, or list several at once
porkud update --dry-run        # preview
porkud update                  # apply now
porkud enable                  # turn on automatic updates (every 5 minutes)
```

Re-run `./install.sh` to upgrade; it keeps your config, keys and timer settings.

If the service fails with `status=226/NAMESPACE`, enable nesting on the
container (Proxmox: Options > Features > Nesting).

## Commands

| Command | What it does |
|---|---|
| `porkud add [-j JOB] NAME...` | Start updating one or more names (`home.example.com`, `example.com`, `*.example.com`) |
| `porkud remove NAME...` | Stop updating names. The DNS records at Porkbun are left as they are |
| `porkud remove -j JOB` | Remove a whole job |
| `porkud list` | Show each job, its names, where they point and the TTL |
| `porkud set [-j JOB] ip VALUE...` | Choose where a job points: `auto`, one or more addresses, or both |
| `porkud update [-n] [-f]` | Check the public IP and update DNS now. `-n` previews, `-f` re-checks every record |
| `porkud status` | Public IP, last applied IP, API key and timer state |
| `porkud interval [TIME]` | Show or set how often the timer runs (`5m`, `30m`, `1h`; minimum `1m`) |
| `porkud enable` / `disable` | Turn automatic updates on or off |
| `porkud auth` | Set the API keys; they are verified with Porkbun before being saved |
| `porkud set [-j JOB] ttl\|ipv4\|ipv6 VALUE` | Change the TTL, or switch IPv4/IPv6 auto-detection on or off, for everything or one job |
| `porkud logs [-n N] [-f]` | Show log output from the timer runs |

`porkud add` works out which part of a name is the domain from the domains
already in the config, then from the domains in your Porkbun account. If
neither knows it, say so: `porkud add --domain example.co.uk home.example.co.uk`.

## Jobs

A job is a group of names that all point at the same place. Names go into the
job called `default` unless you pass `-j JOB`; a job is created the first time
you use its name, and a name can be in only one job.

```sh
porkud add home.example.com                        # default job, follows the WAN IP
porkud add -j JOB02 nas.example.com                # new job, also "auto" to start with
porkud set -j JOB02 ip 203.0.113.7                 # fixed address instead (manual WAN)
porkud set -j JOB02 ip 203.0.113.7 203.0.113.8     # several addresses, one record each
porkud set -j JOB02 ip auto 203.0.113.8            # the WAN IP plus a fixed one
porkud set -j JOB02 ip auto                        # back to following the WAN IP
```

IPv4 addresses become A records and IPv6 addresses AAAA records. For every
name and record type it manages, `porkud` makes the records match the job
exactly, so other A/AAAA records on that same name are changed or deleted.
Other names and other record types are never touched.

The update interval applies to everything. There is one public IP, so one
lookup covers every name, and when it changes they all need updating.

Use `-c PATH` before the command to work on a different config file, and `-v`
for debug output. Exit status: 0 on success, 1 if an update failed, 2 for a
usage, config or key problem.

## How it finds the WAN IP

It asks an outside server which address the request came from (Porkbun's `/ip`
endpoint, with ipify as a fallback). Behind NAT that is the gateway's WAN
address. Private and CGNAT addresses are rejected and never written to DNS.

IPv6 is different: the address detected is this machine's own, not the
router's. Use `porkud set ipv6 off` (optionally with `-j JOB`) when the
services are not on this host. With no public IPv6 at all, AAAA records are
simply left alone.

## Behaviour

- A missing record is created; a record with a wrong address is updated; a correct one is left alone; an extra one is deleted.
- The last applied IP is remembered, so a normal run makes no Porkbun DNS calls. Records are re-checked in full when the IP or config changes, once a day, or with `porkud update --force`.
- A failure on one record does not stop the others, and failed runs are retried on the next tick.

## Files

| Path | Contents |
|---|---|
| `/etc/porkbun-ud/config.toml` | Names and settings (see `config.example.toml`). Comments are not kept when `porkud` rewrites it |
| `/etc/porkbun-ud/credentials.env` | API keys, readable by root only |
| `/etc/systemd/system/porkbun-ud.timer.d/interval.conf` | The interval set with `porkud interval` |
| `/var/lib/porkbun-ud/state.json` | Last applied IP |

## Tests

```sh
python3 -m unittest discover tests
```

## License

MIT, see [LICENSE](LICENSE).
