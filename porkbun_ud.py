#!/usr/bin/env python3
"""Porkbun dynamic DNS updater.

Detects this network's public IPv4/IPv6 address and points the A/AAAA records
listed in the config file at it. Runs once and exits; schedule it with the
systemd timer in systemd/.
"""

import argparse
import hashlib
import http.client
import ipaddress
import json
import logging
import os
import re
import socket
import sys
import time
import tomllib
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

API_BASE = "https://api.porkbun.com/api/json/v3"
DEFAULT_CONFIG = "/etc/porkbun-ud/config.toml"
MIN_TTL = 600
TIMEOUT = 15
MAX_RETRY_WAIT = 30
# Even when the IP has not changed, re-check the records against Porkbun this
# often so a record edited by hand in the web UI gets put back.
FULL_CHECK_INTERVAL = 24 * 60 * 60

# Where to ask "what address did this request come from?". Behind NAT the
# answer is the WAN address of the gateway, which is what DNS should point at.
# Each entry is (url, JSON field holding the address).
IP_SOURCES = {
    "A": [
        ("https://api-ipv4.porkbun.com/api/json/v3/ip", "yourIp"),
        ("https://api.ipify.org/?format=json", "ip"),
    ],
    "AAAA": [
        ("https://api.porkbun.com/api/json/v3/ip", "yourIp"),
        ("https://api6.ipify.org/?format=json", "ip"),
    ],
}
FAMILY = {"A": socket.AF_INET, "AAAA": socket.AF_INET6}
IP_VERSION = {"A": 4, "AAAA": 6}

NETWORK_ERRORS = (OSError, http.client.HTTPException)

DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]{2,}$")
LABEL = r"[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?"
RECORD_RE = re.compile(rf"^(?:\*|(?:\*\.)?{LABEL}(?:\.{LABEL})*)$")

log = logging.getLogger("porkbun-ud")


class ConfigError(Exception):
    pass


class PorkbunError(Exception):
    def __init__(self, code, message, hint=None):
        self.code = code
        super().__init__(f"{message} [{code}]" + (f" - {hint}" if hint else ""))


@dataclass(frozen=True, order=True)
class Target:
    domain: str
    name: str  # subdomain part only; "" is the root of the domain
    rtype: str  # "A" or "AAAA"
    ttl: int

    @property
    def fqdn(self):
        return f"{self.name}.{self.domain}" if self.name else self.domain


# --- HTTP -------------------------------------------------------------------


def _connector(family):
    """A socket factory like socket.create_connection, pinned to one address family."""

    def create(address, timeout=TIMEOUT, source_address=None):
        host, port = address
        last_error = None
        for af, socktype, proto, _, sockaddr in socket.getaddrinfo(
            host, port, family, socket.SOCK_STREAM
        ):
            sock = socket.socket(af, socktype, proto)
            try:
                sock.settimeout(timeout)
                sock.connect(sockaddr)
                return sock
            except OSError as exc:
                last_error = exc
                sock.close()
        raise last_error or OSError(f"no addresses found for {host}")

    return create


def request(method, url, *, headers=None, body=None, family=socket.AF_UNSPEC):
    """Make one HTTPS request. Returns (status, response headers, body bytes)."""
    parts = urllib.parse.urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    conn = http.client.HTTPSConnection(parts.hostname, parts.port, timeout=TIMEOUT)
    conn._create_connection = _connector(family)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        return response.status, response.headers, response.read()
    finally:
        conn.close()


# --- Public IP detection ----------------------------------------------------


def detect_ip(rtype):
    """Return the public address for record type "A" or "AAAA", or None."""
    for url, field in IP_SOURCES[rtype]:
        host = urllib.parse.urlsplit(url).hostname
        try:
            status, _, data = request("GET", url, family=FAMILY[rtype])
            value = json.loads(data)[field]
            address = ipaddress.ip_address(value)
        except NETWORK_ERRORS as exc:
            log.debug("%s lookup via %s failed: %s", rtype, host, exc)
            continue
        except (ValueError, KeyError, TypeError) as exc:
            log.debug("%s lookup via %s gave an unusable answer: %r", rtype, host, exc)
            continue
        if address.version != IP_VERSION[rtype]:
            log.debug("%s lookup via %s returned IPv%d", rtype, host, address.version)
            continue
        if not address.is_global:
            log.warning(
                "%s reported %s, which is not a public address; ignoring it", host, address
            )
            continue
        log.debug("%s address is %s (via %s)", rtype, address, host)
        return str(address)
    return None


# --- Porkbun API ------------------------------------------------------------


class Porkbun:
    def __init__(self, api_key, secret_key):
        self._headers = {
            "X-API-Key": api_key,
            "X-Secret-API-Key": secret_key,
            "Accept": "application/json",
        }

    def _call(self, method, path, body=None):
        headers = dict(self._headers)
        payload = None
        if body is not None:
            payload = json.dumps(body)
            headers["Content-Type"] = "application/json"
        for attempt in (1, 2):
            status, response_headers, data = request(
                method, API_BASE + path, headers=headers, body=payload
            )
            if status == 429 and attempt == 1:
                try:
                    wait = int(response_headers.get("Retry-After", 5))
                except ValueError:
                    wait = 5
                wait = max(1, min(wait, MAX_RETRY_WAIT))
                log.warning("Rate limited by Porkbun; retrying in %ds", wait)
                time.sleep(wait)
                continue
            break
        try:
            result = json.loads(data)
        except ValueError:
            raise PorkbunError(f"HTTP_{status}", "unexpected non-JSON response from Porkbun")
        if not isinstance(result, dict) or result.get("status") != "SUCCESS":
            result = result if isinstance(result, dict) else {}
            next_action = result.get("next_action")
            raise PorkbunError(
                result.get("code") or f"HTTP_{status}",
                result.get("message") or "request failed",
                next_action.get("hint") if isinstance(next_action, dict) else None,
            )
        for warning in result.get("warnings") or []:
            log.warning("Porkbun warning: %s", warning)
        return result

    @staticmethod
    def _name_path(endpoint, domain, rtype, name):
        path = f"/dns/{endpoint}/{domain}/{rtype}"
        if name:
            path += "/" + urllib.parse.quote(name, safe="*")
        return path

    def retrieve(self, domain, rtype, name):
        result = self._call("GET", self._name_path("retrieveByNameType", domain, rtype, name))
        return result.get("records") or []

    def edit(self, domain, rtype, name, content, ttl):
        self._call(
            "POST",
            self._name_path("editByNameType", domain, rtype, name),
            {"content": content, "ttl": str(ttl)},
        )

    def create(self, domain, rtype, name, content, ttl):
        self._call(
            "POST",
            f"/dns/create/{domain}",
            {"name": name, "type": rtype, "content": content, "ttl": str(ttl)},
        )


# --- Config and state -------------------------------------------------------


def _check_keys(table, allowed, where):
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise ConfigError(f"{where}: unknown setting(s): {', '.join(unknown)}")


def _get(table, key, kind, default, where):
    value = table.get(key, default)
    if type(value) is not kind:
        raise ConfigError(f"{where}: '{key}' must be a {kind.__name__}")
    return value


def _ttl(table, default, where):
    ttl = _get(table, "ttl", int, default, where)
    if ttl < MIN_TTL:
        raise ConfigError(f"{where}: ttl must be at least {MIN_TTL}")
    return ttl


def load_config(path):
    """Read the TOML config and return the sorted list of records to manage."""
    try:
        with open(path, "rb") as handle:
            config = tomllib.load(handle)
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc.strerror}")
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}")

    _check_keys(config, {"ttl", "ipv4", "ipv6", "domain"}, "config")
    ttl = _ttl(config, MIN_TTL, "config")
    ipv4 = _get(config, "ipv4", bool, True, "config")
    ipv6 = _get(config, "ipv6", bool, True, "config")
    domains = config.get("domain")
    if not isinstance(domains, list) or not domains:
        raise ConfigError("config: add at least one [[domain]] section")

    targets = set()
    for entry in domains:
        domain = str(entry.get("name", "")).strip().lower().rstrip(".")
        where = f"domain '{domain}'"
        if not DOMAIN_RE.match(domain):
            raise ConfigError(f"[[domain]]: 'name' is missing or not a domain name: {domain!r}")
        _check_keys(entry, {"name", "records", "ttl", "ipv4", "ipv6"}, where)
        records = entry.get("records", ["@"])
        if not isinstance(records, list) or not records:
            raise ConfigError(f"{where}: 'records' must be a non-empty list")
        rtypes = [
            rtype
            for rtype, enabled in (
                ("A", _get(entry, "ipv4", bool, ipv4, where)),
                ("AAAA", _get(entry, "ipv6", bool, ipv6, where)),
            )
            if enabled
        ]
        domain_ttl = _ttl(entry, ttl, where)
        for record in records:
            name = str(record).strip().lower().rstrip(".")
            if name == domain or name.endswith("." + domain):
                raise ConfigError(
                    f"{where}: record {record!r} includes the domain; "
                    f"use only the subdomain part (or \"@\" for the root)"
                )
            if name == "@":
                name = ""
            elif not RECORD_RE.match(name):
                raise ConfigError(f"{where}: invalid record name {record!r}")
            for rtype in rtypes:
                targets.add(Target(domain, name, rtype, domain_ttl))
    if not targets:
        raise ConfigError("config: nothing to update (ipv4 and ipv6 are both disabled)")
    return sorted(targets)


def config_fingerprint(targets):
    text = json.dumps([[t.domain, t.name, t.rtype, t.ttl] for t in targets])
    return hashlib.sha256(text.encode()).hexdigest()


def default_state_path():
    # systemd sets STATE_DIRECTORY from StateDirectory= in the service unit.
    directory = os.environ.get("STATE_DIRECTORY")
    if directory:
        return Path(directory.split(":")[0]) / "state.json"
    base = os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state"
    return Path(base) / "porkbun-ud" / "state.json"


def load_state(path):
    try:
        state = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}
    return state if isinstance(state, dict) else {}


def save_state(path, state):
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(state))
        os.replace(temporary, path)
    except OSError as exc:
        log.warning("Could not save state to %s: %s", path, exc)


# --- Update logic -----------------------------------------------------------


def _same_address(content, ip):
    try:
        return ipaddress.ip_address(str(content).strip()) == ipaddress.ip_address(ip)
    except ValueError:
        return False


def reconcile(client, target, ip, dry_run=False):
    """Make one record point at ip. Returns "unchanged", "updated" or "created"."""
    records = client.retrieve(target.domain, target.rtype, target.name)
    current = [str(record.get("content", "")) for record in records]
    label = f"{target.fqdn} {target.rtype}"
    if records and all(_same_address(content, ip) for content in current):
        log.info("%s: already %s", label, ip)
        return "unchanged"
    if len(records) > 1:
        log.warning("%s: %d records match; all of them will be set to %s", label, len(records), ip)
    prefix = "[dry run] would have " if dry_run else ""
    if records:
        if not dry_run:
            client.edit(target.domain, target.rtype, target.name, ip, target.ttl)
        log.info("%s: %supdated %s -> %s", label, prefix, ", ".join(current), ip)
        return "updated"
    if not dry_run:
        client.create(target.domain, target.rtype, target.name, ip, target.ttl)
    log.info("%s: %screated -> %s", label, prefix, ip)
    return "created"


def run(targets, client, state_path, dry_run=False, force=False):
    ok = True
    ips = {}
    for rtype in sorted({target.rtype for target in targets}):
        ip = detect_ip(rtype)
        if ip:
            ips[rtype] = ip
        elif rtype == "A":
            log.error("Could not determine the public IPv4 address; A records left alone")
            ok = False
        else:
            log.warning("No public IPv6 address detected; AAAA records left alone")
    if not ips:
        return 1

    summary = ", ".join(ips.values())
    fingerprint = config_fingerprint(targets)
    state = load_state(state_path)
    try:
        age = time.time() - float(state.get("checked", 0))
    except (TypeError, ValueError):
        age = FULL_CHECK_INTERVAL
    if (
        ok
        and not dry_run
        and not force
        and state.get("config") == fingerprint
        and state.get("ips") == ips
        and 0 <= age < FULL_CHECK_INTERVAL
    ):
        log.info("Public IP unchanged (%s); nothing to do", summary)
        return 0

    log.info("Public IP is %s; checking %d record(s)", summary, len(targets))
    for target in targets:
        ip = ips.get(target.rtype)
        if ip is None:
            continue
        try:
            reconcile(client, target, ip, dry_run)
        except (PorkbunError, *NETWORK_ERRORS) as exc:
            log.error("%s %s: %s", target.fqdn, target.rtype, exc)
            ok = False

    # Only remember a fully successful run, so anything that failed is retried.
    if ok and not dry_run:
        save_state(state_path, {"config": fingerprint, "ips": ips, "checked": time.time()})
    return 0 if ok else 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Point Porkbun A/AAAA records at this network's public IP."
    )
    parser.add_argument(
        "-c", "--config", default=DEFAULT_CONFIG, help=f"config file (default: {DEFAULT_CONFIG})"
    )
    parser.add_argument(
        "-n", "--dry-run", action="store_true", help="show what would change without changing it"
    )
    parser.add_argument(
        "-f", "--force", action="store_true", help="check every record even if the IP is unchanged"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
        stream=sys.stdout,
    )

    try:
        targets = load_config(args.config)
    except ConfigError as exc:
        log.error("%s", exc)
        return 2
    api_key = os.environ.get("PORKBUN_API_KEY", "").strip()
    secret_key = os.environ.get("PORKBUN_SECRET_API_KEY", "").strip()
    if not api_key or not secret_key:
        log.error("Set PORKBUN_API_KEY and PORKBUN_SECRET_API_KEY in the environment")
        return 2

    return run(
        targets,
        Porkbun(api_key, secret_key),
        default_state_path(),
        dry_run=args.dry_run,
        force=args.force,
    )


if __name__ == "__main__":
    sys.exit(main())
