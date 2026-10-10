#!/usr/bin/env python3
"""Porkbun dynamic DNS updater.

Detects this network's public IPv4/IPv6 address and points the A/AAAA records
listed in the config file at it. "porkud update" does one pass and exits (the
systemd timer in systemd/ runs it on a schedule); the other subcommands manage
the config, API keys and timer.
"""

import argparse
import getpass
import hashlib
import http.client
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import sys
import time
import tomllib
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

API_BASE = "https://api.porkbun.com/api/json/v3"
DEFAULT_CONFIG = "/etc/porkbun-ud/config.toml"
SYSTEM_STATE_DIR = "/var/lib/porkbun-ud"
TIMER_UNIT = "porkbun-ud.timer"
SERVICE_UNIT = "porkbun-ud.service"
TIMER_DROPIN = "/etc/systemd/system/porkbun-ud.timer.d/interval.conf"
DEFAULT_INTERVAL = 300  # matches OnUnitActiveSec in systemd/porkbun-ud.timer
MIN_INTERVAL = 60
CREDENTIAL_VARS = ("PORKBUN_API_KEY", "PORKBUN_SECRET_API_KEY")
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
JOB_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
DEFAULT_JOB = "default"
RECORD_RE = re.compile(rf"^(?:\*|(?:\*\.)?{LABEL}(?:\.{LABEL})*)$")

log = logging.getLogger("porkbun-ud")


class Failure(Exception):
    """A problem to report to the user without a traceback."""


class ConfigError(Failure):
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
    auto: bool = True  # publish the detected public address
    static: tuple = ()  # fixed addresses to publish as well

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

    def ping(self):
        """Raises PorkbunError unless the API keys are valid."""
        return self._call("GET", "/ping")

    def list_domains(self):
        """Names of every domain in the account."""
        names = []
        while True:
            page = self._call("POST", "/domain/listAll", {"start": str(len(names))}).get("domains")
            names += [str(item["domain"]).lower() for item in page or [] if item.get("domain")]
            if not page or len(page) < 1000:
                return names

    def retrieve(self, domain, rtype, name):
        result = self._call("GET", self._name_path("retrieveByNameType", domain, rtype, name))
        return result.get("records") or []

    def edit_record(self, domain, record_id, rtype, name, content, ttl):
        self._call(
            "POST",
            f"/dns/edit/{domain}/{record_id}",
            {"name": name, "type": rtype, "content": content, "ttl": str(ttl)},
        )

    def delete_record(self, domain, record_id):
        self._call("POST", f"/dns/delete/{domain}/{record_id}", {})

    def create(self, domain, rtype, name, content, ttl):
        self._call(
            "POST",
            f"/dns/create/{domain}",
            {"name": name, "type": rtype, "content": content, "ttl": str(ttl)},
        )


# --- Config and state -------------------------------------------------------

CONFIG_HEADER = """\
# porkbun-ud configuration, managed by the porkud command.
# Hand edits are fine, but comments are not kept when porkud rewrites the file.
# API keys do NOT go here; set them with: porkud auth
"""


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


def normalise_domain(value):
    domain = str(value).strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        raise ConfigError(f"not a domain name: {value!r}")
    return domain


def normalise_record(value, domain):
    """Return the subdomain part of a name as stored in the config ("@" is the root)."""
    name = str(value).strip().lower().rstrip(".")
    if name == domain or name.endswith("." + domain):
        raise ConfigError(
            f"domain '{domain}': record {value!r} includes the domain; "
            f"use only the subdomain part (or \"@\" for the root)"
        )
    if name != "@" and not RECORD_RE.match(name):
        raise ConfigError(f"domain '{domain}': invalid record name {value!r}")
    return name


def normalise_ip_directive(values):
    """Validate a job's ip list: "auto" (the detected WAN address) and/or fixed addresses."""
    result = []
    for value in values:
        text = str(value).strip().lower()
        if text in ("auto", "wan"):
            item = "auto"
        else:
            try:
                item = str(ipaddress.ip_address(text))
            except ValueError:
                raise ConfigError(f"{value!r} is neither an IP address nor \"auto\"")
        if item not in result:
            result.append(item)
    if not result:
        raise ConfigError("ip needs \"auto\" or at least one address")
    return result


def _read_domains(entries, where):
    if not isinstance(entries, list):
        raise ConfigError(f"{where}: domains must be written as [[job.domain]] sections")
    domains = []
    for entry in entries:
        if "name" not in entry:
            raise ConfigError(f"{where}: a domain section has no 'name'")
        domain = normalise_domain(entry["name"])
        _check_keys(entry, {"name", "records"}, f"{where}, domain '{domain}'")
        records = entry.get("records", ["@"])
        if not isinstance(records, list) or not records:
            raise ConfigError(f"{where}, domain '{domain}': 'records' must be a non-empty list")
        records = list(dict.fromkeys(normalise_record(r, domain) for r in records))
        domains.append({"name": domain, "records": records})
    return domains


def read_config(path, missing_ok=False):
    """Read and validate the TOML config. Returns it as a normalised dict."""
    try:
        with open(path, "rb") as handle:
            raw = tomllib.load(handle)
    except FileNotFoundError:
        if not missing_ok:
            raise ConfigError(f"cannot read config {path}: no such file")
        raw = {}
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc.strerror}")
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}")

    _check_keys(raw, {"ttl", "ipv4", "ipv6", "job", "domain"}, "config")
    config = {
        "ttl": _ttl(raw, MIN_TTL, "config"),
        "ipv4": _get(raw, "ipv4", bool, True, "config"),
        "ipv6": _get(raw, "ipv6", bool, True, "config"),
        "jobs": [],
    }
    entries = raw.get("job", [])
    if not isinstance(entries, list):
        raise ConfigError("config: jobs must be written as [[job]] sections")
    if "domain" in raw:
        # Files written before jobs existed list their domains at the top level.
        entries = [{"name": DEFAULT_JOB, "domain": raw["domain"]}, *entries]

    owners = {}
    for entry in entries:
        name = str(entry.get("name", ""))
        if not JOB_RE.match(name):
            raise ConfigError(f"[[job]]: 'name' is missing or not a valid job name: {name!r}")
        where = f"job '{name}'"
        if find_job(config, name):
            raise ConfigError(f"{where} is defined more than once")
        _check_keys(entry, {"name", "ip", "domain", "ttl", "ipv4", "ipv6"}, where)
        ip = entry.get("ip", ["auto"])
        if not isinstance(ip, list):
            ip = [ip]
        try:
            job = {"name": name, "ip": normalise_ip_directive(ip)}
        except ConfigError as exc:
            raise ConfigError(f"{where}: {exc}")
        job["domains"] = _read_domains(entry.get("domain", []), where)
        if "ttl" in entry:
            job["ttl"] = _ttl(entry, MIN_TTL, where)
        for key in ("ipv4", "ipv6"):
            if key in entry:
                job[key] = _get(entry, key, bool, True, where)
        for domain in job["domains"]:
            for record in domain["records"]:
                other = owners.setdefault((domain["name"], record), name)
                if other != name:
                    raise ConfigError(
                        f"{full_name(domain['name'], record)} is in both job '{other}' and {where}"
                    )
        config["jobs"].append(job)
    return config


def find_job(config, name):
    return next((j for j in config["jobs"] if j["name"].casefold() == name.casefold()), None)


def full_name(domain, record):
    return domain if record == "@" else f"{record}.{domain}"


def expand_targets(config):
    """Every (domain, record, type) the config asks for, sorted."""
    targets = set()
    for job in config["jobs"]:
        ttl = job.get("ttl", config["ttl"])
        fixed = [ipaddress.ip_address(item) for item in job["ip"] if item != "auto"]
        for rtype, key in (("A", "ipv4"), ("AAAA", "ipv6")):
            # ipv4/ipv6 switch auto-detection only; a fixed address is always published.
            auto = "auto" in job["ip"] and job.get(key, config[key])
            static = tuple(str(ip) for ip in fixed if ip.version == IP_VERSION[rtype])
            if not auto and not static:
                continue
            for domain in job["domains"]:
                for record in domain["records"]:
                    name = "" if record == "@" else record
                    targets.add(Target(domain["name"], name, rtype, ttl, auto, static))
    return sorted(targets)


def load_config(path):
    """Read the config and return the list of records to manage."""
    targets = expand_targets(read_config(path, missing_ok=True))
    if not targets:
        raise ConfigError("nothing to update yet; add a name with: porkud add <name>")
    return targets


def _toml_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return json.dumps(value)


def dump_config(config):
    settings = ("ttl", "ipv4", "ipv6")
    lines = [CONFIG_HEADER]
    lines += [f"{key} = {_toml_value(config[key])}" for key in settings]
    for job in config["jobs"]:
        lines += ["", "[[job]]", f"name = {_toml_value(job['name'])}"]
        lines.append("ip = [" + ", ".join(_toml_value(item) for item in job["ip"]) + "]")
        lines += [f"{key} = {_toml_value(job[key])}" for key in settings if key in job]
        for domain in job["domains"]:
            lines += ["", "  [[job.domain]]", f"  name = {_toml_value(domain['name'])}"]
            records = ", ".join(_toml_value(record) for record in domain["records"])
            lines.append(f"  records = [{records}]")
    return "\n".join(lines) + "\n"


def write_config(path, config):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(dump_config(config))
    temporary.chmod(0o644)
    os.replace(temporary, path)


def credentials_path(config_path):
    return Path(config_path).parent / "credentials.env"


def load_credentials(config_path):
    """API key and secret from the environment, else from credentials.env."""
    values = {name: os.environ.get(name, "").strip() for name in CREDENTIAL_VARS}
    if not all(values.values()):
        try:
            text = credentials_path(config_path).read_text()
        except OSError:
            text = ""
        for line in text.splitlines():
            name, _, value = line.partition("=")
            name = name.strip()
            if name in values and not values[name]:
                values[name] = value.strip().strip("'\"")
    if not all(values.values()):
        raise ConfigError("no Porkbun API keys found; set them with: porkud auth")
    return tuple(values[name] for name in CREDENTIAL_VARS)


def config_fingerprint(targets):
    text = json.dumps([[t.domain, t.name, t.rtype, t.ttl, t.auto, t.static] for t in targets])
    return hashlib.sha256(text.encode()).hexdigest()


def default_state_path():
    # systemd sets STATE_DIRECTORY from StateDirectory= in the service unit.
    # Root running porkud by hand shares that directory with the service.
    directory = os.environ.get("STATE_DIRECTORY")
    if directory:
        return Path(directory.split(":")[0]) / "state.json"
    if os.geteuid() == 0:
        return Path(SYSTEM_STATE_DIR) / "state.json"
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


def _canonical(content):
    try:
        return str(ipaddress.ip_address(str(content).strip()))
    except ValueError:
        return str(content)


def reconcile(client, target, addresses, dry_run=False):
    """Make the records for one name and type hold exactly these addresses.

    Returns True if anything was (or, in a dry run, would be) changed.
    """
    label = f"{target.fqdn} {target.rtype}"
    wanted = list(dict.fromkeys(addresses))
    missing = list(wanted)
    surplus = []
    for record in client.retrieve(target.domain, target.rtype, target.name):
        content = _canonical(record.get("content", ""))
        if content in missing:
            missing.remove(content)
        else:
            if not record.get("id"):
                raise Failure("Porkbun returned a record without an id; cannot change it")
            surplus.append((record["id"], content))
    if not missing and not surplus:
        log.info("%s: already %s", label, ", ".join(wanted))
        return False

    # Reuse records that hold a wrong address before creating or deleting any.
    prefix = "[dry run] would have " if dry_run else ""
    for (record_id, old), new in zip(surplus, missing):
        if not dry_run:
            client.edit_record(target.domain, record_id, target.rtype, target.name, new, target.ttl)
        log.info("%s: %supdated %s -> %s", label, prefix, old, new)
    for new in missing[len(surplus) :]:
        if not dry_run:
            client.create(target.domain, target.rtype, target.name, new, target.ttl)
        log.info("%s: %screated -> %s", label, prefix, new)
    for record_id, old in surplus[len(missing) :]:
        if not dry_run:
            client.delete_record(target.domain, record_id)
        log.info("%s: %sdeleted extra record %s", label, prefix, old)
    return True


def run(targets, client, state_path, dry_run=False, force=False):
    ok = True
    ips = {}
    for rtype in sorted({target.rtype for target in targets if target.auto}):
        ip = detect_ip(rtype)
        if ip:
            ips[rtype] = ip
        elif rtype == "A":
            log.error("Could not determine the public IPv4 address; those A records left alone")
            ok = False
        else:
            log.warning("No public IPv6 address detected; those AAAA records left alone")

    summary = f"Public IP is {', '.join(ips.values())}" if ips else "No public IP in use"
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
        log.info("%s, unchanged; nothing to do", summary)
        return 0

    log.info("%s; checking %d record set(s)", summary, len(targets))
    for target in targets:
        addresses = list(target.static)
        if target.auto:
            if target.rtype not in ips:
                continue
            addresses.insert(0, ips[target.rtype])
        try:
            reconcile(client, target, addresses, dry_run)
        except (Failure, PorkbunError, *NETWORK_ERRORS) as exc:
            log.error("%s %s: %s", target.fqdn, target.rtype, exc)
            ok = False

    # Only remember a fully successful run, so anything that failed is retried.
    if ok and not dry_run:
        save_state(state_path, {"config": fingerprint, "ips": ips, "checked": time.time()})
    return 0 if ok else 1


# --- Commands ---------------------------------------------------------------


def systemctl(*args):
    try:
        result = subprocess.run(["systemctl", *args], capture_output=True, text=True)
    except OSError as exc:
        raise Failure(f"cannot run systemctl: {exc}")
    if result.returncode:
        raise Failure(result.stderr.strip() or f"systemctl {' '.join(args)} failed")
    return result.stdout.strip()


def parse_duration(text):
    """Seconds from "90s", "5m", "1h" or "1d"; a bare number means minutes."""
    match = re.fullmatch(r"(\d+)\s*([smhd]?)[a-z]*", str(text).strip().lower())
    if not match:
        raise Failure(f"cannot read {text!r} as a time; use something like 5m, 30m or 1h")
    seconds = int(match[1]) * {"s": 1, "": 60, "m": 60, "h": 3600, "d": 86400}[match[2]]
    if seconds < MIN_INTERVAL:
        raise Failure(f"the shortest allowed interval is {format_duration(MIN_INTERVAL)}")
    return seconds


def format_duration(seconds):
    for size, unit in ((86400, "d"), (3600, "h"), (60, "m")):
        if seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


def current_interval():
    try:
        text = Path(TIMER_DROPIN).read_text()
    except OSError:
        return DEFAULT_INTERVAL
    values = re.findall(r"^OnUnitActiveSec=(\d+)s$", text, re.MULTILINE)
    return int(values[-1]) if values else DEFAULT_INTERVAL


def split_name(name, domains):
    """Split a full DNS name into (domain, record) using the longest matching domain."""
    name = str(name).strip().lower().rstrip(".")
    for domain in sorted(domains, key=len, reverse=True):
        if name == domain:
            return domain, "@"
        if name.endswith("." + domain):
            return domain, normalise_record(name[: -len(domain) - 1], domain)
    return None


def account_domains(config_path):
    """Domains in the Porkbun account, or [] when they cannot be listed."""
    try:
        return Porkbun(*load_credentials(config_path)).list_domains()
    except (Failure, PorkbunError, *NETWORK_ERRORS) as exc:
        log.debug("Could not list the account's domains: %s", exc)
        return []


def resolve_name(name, args, known, account):
    """Work out (domain, record) for a name given on the command line."""
    if args.domain:
        domain = normalise_domain(args.domain)
        return split_name(name, [domain]) or (domain, normalise_record(name, domain))
    found = split_name(name, known)
    if not found and account is not None:
        if not account:
            account += account_domains(args.config)
        found = split_name(name, account)
    if not found:
        raise Failure(
            f"cannot tell which domain {name!r} belongs to; "
            f"say so with --domain, e.g. porkud add --domain example.com {name}"
        )
    return found


def known_domains(config):
    return [domain["name"] for job in config["jobs"] for domain in job["domains"]]


def find_name(config, domain, record):
    """The (job, domain entry) holding a name, or (None, None)."""
    for job in config["jobs"]:
        for entry in job["domains"]:
            if entry["name"] == domain and record in entry["records"]:
                return job, entry
    return None, None


def get_job(config, name, create=False):
    job = find_job(config, name)
    if job is None:
        if not create:
            raise Failure(f"there is no job named {name!r} (see: porkud list)")
        if not JOB_RE.match(name):
            raise Failure("job names may only contain letters, digits, - and _")
        job = {"name": name, "ip": ["auto"], "domains": []}
        config["jobs"].append(job)
    return job


def describe_ip(config, job):
    parts = []
    for item in job["ip"]:
        if item == "auto":
            families = [
                label
                for label, key in (("IPv4", "ipv4"), ("IPv6", "ipv6"))
                if job.get(key, config[key])
            ]
            item = "auto" if len(families) == 2 else f"auto ({families[0] if families else 'off'} only)"
            item = item.replace("(off only)", "(off)")
        parts.append(item)
    return ", ".join(parts)


def cmd_add(args):
    config = read_config(args.config, missing_ok=True)
    job = get_job(config, args.job or DEFAULT_JOB, create=True)
    known = known_domains(config)
    account = []
    added = []
    for name in args.names:
        domain, record = resolve_name(name, args, known, account)
        owner, _ = find_name(config, domain, record)
        if owner is job:
            print(f"{full_name(domain, record)} is already in job {job['name']}")
            continue
        if owner:
            raise Failure(
                f"{full_name(domain, record)} is already in job {owner['name']}; "
                f"remove it from there first"
            )
        entry = next((e for e in job["domains"] if e["name"] == domain), None)
        if entry is None:
            entry = {"name": domain, "records": []}
            job["domains"].append(entry)
            known.append(domain)
        entry["records"].append(record)
        added.append(full_name(domain, record))
    if added:
        write_config(args.config, config)
        print(f"Added {', '.join(added)} to job {job['name']} (ip: {describe_ip(config, job)})")
        print("It will be updated on the next timer run, or right away with: porkud update")
    return 0


def cmd_remove(args):
    config = read_config(args.config)
    only = get_job(config, args.job) if args.job else None
    if not args.names:
        if only is None:
            raise Failure("give the names to remove, or --job JOB to remove a whole job")
        count = sum(len(domain["records"]) for domain in only["domains"])
        config["jobs"].remove(only)
        write_config(args.config, config)
        print(f"Removed job {only['name']} and its {count} name(s)")
    else:
        known = known_domains(config)
        removed = []
        for name in args.names:
            domain, record = resolve_name(name, args, known, None)
            job, entry = find_name(config, domain, record)
            if job is None or (only and job is not only):
                where = f"job {only['name']}" if only else "the config"
                raise Failure(f"{full_name(domain, record)} is not in {where} (see: porkud list)")
            entry["records"].remove(record)
            if not entry["records"]:
                job["domains"].remove(entry)
            removed.append(full_name(domain, record))
        write_config(args.config, config)
        print("Removed " + ", ".join(removed))
    print("The DNS records themselves were left as they are at Porkbun.")
    return 0


def cmd_list(args):
    config = read_config(args.config, missing_ok=True)
    rows = []
    for job in config["jobs"]:
        names = [full_name(d["name"], r) for d in job["domains"] for r in d["records"]]
        for name in names or ["(no names yet)"]:
            rows.append((job["name"], name, describe_ip(config, job), str(job.get("ttl", config["ttl"]))))
    if not rows:
        print("Nothing configured yet. Add a name with: porkud add home.example.com")
        return 0
    rows.insert(0, ("JOB", "NAME", "IP", "TTL"))
    widths = [max(len(row[i]) for row in rows) for i in range(3)]
    for row in rows:
        print("  ".join(f"{cell:<{width}}" for cell, width in zip(row, widths)) + "  " + row[3])
    return 0


def cmd_set(args):
    config = read_config(args.config, missing_ok=True)
    if args.setting == "ip":
        try:
            value = normalise_ip_directive(args.values)
        except ConfigError as exc:
            raise Failure(f"{exc} (to choose a job use: porkud set --job JOB ip ...)")
        job = get_job(config, args.job or DEFAULT_JOB, create=True)
        job["ip"] = value
        write_config(args.config, config)
        print(f"Job {job['name']} ip: {describe_ip(config, job)}")
        return 0

    if len(args.values) != 1:
        raise Failure(f"{args.setting} takes a single value")
    text = args.values[0].lower()
    if args.setting == "ttl":
        if not text.isdigit() or int(text) < MIN_TTL:
            raise Failure(f"ttl must be a number of seconds, at least {MIN_TTL}")
        value = int(text)
    else:
        choices = {"on": True, "true": True, "yes": True, "off": False, "false": False, "no": False}
        if text not in choices:
            raise Failure(f"{args.setting} must be on or off")
        value = choices[text]
    table = get_job(config, args.job) if args.job else config
    table[args.setting] = value
    write_config(args.config, config)
    print(f"{args.setting} = {_toml_value(value)}" + (f" for job {table['name']}" if args.job else ""))
    return 0


def cmd_interval(args):
    if args.every is None:
        print(f"Updating every {format_duration(current_interval())}")
        return 0
    seconds = parse_duration(args.every)
    dropin = Path(TIMER_DROPIN)
    dropin.parent.mkdir(parents=True, exist_ok=True)
    # The empty assignment clears the value from the unit file before setting ours.
    dropin.write_text(f"[Timer]\nOnUnitActiveSec=\nOnUnitActiveSec={seconds}s\n")
    systemctl("daemon-reload")
    systemctl("try-restart", TIMER_UNIT)
    print(f"Now updating every {format_duration(seconds)}")
    return 0


def cmd_enable(args):
    systemctl("enable", "--now", TIMER_UNIT)
    print(f"Automatic updates are on, every {format_duration(current_interval())}")
    return 0


def cmd_disable(args):
    systemctl("disable", "--now", TIMER_UNIT)
    print("Automatic updates are off")
    return 0


def cmd_auth(args):
    if sys.stdin.isatty():
        api_key = input("Porkbun API key: ").strip()
        secret_key = getpass.getpass("Porkbun secret API key (hidden): ").strip()
    else:
        api_key = sys.stdin.readline().strip()
        secret_key = sys.stdin.readline().strip()
    if not api_key or not secret_key:
        raise Failure("both the API key and the secret API key are needed")
    Porkbun(api_key, secret_key).ping()

    path = credentials_path(args.config)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(f"{CREDENTIAL_VARS[0]}={api_key}\n{CREDENTIAL_VARS[1]}={secret_key}\n")
    os.replace(temporary, path)
    print(f"Keys are valid and saved to {path}")
    return 0


def cmd_status(args):
    targets = expand_targets(read_config(args.config, missing_ok=True))
    rtypes = sorted({target.rtype for target in targets if target.auto}) or ["A"]
    for rtype in rtypes:
        print(f"Public IPv{IP_VERSION[rtype]}:  {detect_ip(rtype) or 'not detected'}")

    state = load_state(default_state_path())
    if state.get("ips"):
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(float(state.get("checked", 0))))
        print(f"Last applied: {', '.join(state['ips'].values())} (checked {when})")
    else:
        print("Last applied: nothing yet")

    names = {target.fqdn for target in targets}
    print(f"Names:        {len(names)} (see: porkud list)")
    try:
        load_credentials(args.config)
        print("API keys:     set")
    except ConfigError:
        print("API keys:     missing (run: porkud auth)")
    try:
        active = subprocess.run(
            ["systemctl", "is-active", TIMER_UNIT], capture_output=True, text=True
        ).stdout.strip()
    except OSError:
        active = "unknown"
    if active == "active":
        print(f"Timer:        on, every {format_duration(current_interval())}")
    else:
        print(f"Timer:        off ({active or 'not installed'}); turn on with: porkud enable")
    return 0


def cmd_logs(args):
    command = ["journalctl", "-u", SERVICE_UNIT, "-n", str(args.lines), "--no-pager"]
    if args.follow:
        command.append("-f")
    try:
        os.execvp(command[0], command)
    except OSError as exc:
        raise Failure(f"cannot run journalctl: {exc}")


def cmd_update(args):
    targets = load_config(args.config)
    client = Porkbun(*load_credentials(args.config))
    return run(targets, client, default_state_path(), dry_run=args.dry_run, force=args.force)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="porkud",
        description="Keep Porkbun A/AAAA records pointed at this network's public IP.",
    )
    parser.add_argument(
        "-c", "--config", default=DEFAULT_CONFIG, help=f"config file (default: {DEFAULT_CONFIG})"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    def command(name, handler, help):
        sub = commands.add_parser(name, help=help, description=help)
        sub.set_defaults(handler=handler)
        return sub

    domain_help = "the domain the names belong to (only needed when it cannot be worked out)"

    sub = command("add", cmd_add, "start updating one or more DNS names")
    sub.add_argument("names", nargs="+", metavar="NAME", help="full name, e.g. home.example.com")
    sub.add_argument("-j", "--job", help=f"job to add them to, created if new (default: {DEFAULT_JOB})")
    sub.add_argument("-d", "--domain", help=domain_help)

    sub = command("remove", cmd_remove, "stop updating DNS names, or remove a whole job")
    sub.add_argument("names", nargs="*", metavar="NAME", help="full name, e.g. home.example.com")
    sub.add_argument("-j", "--job", help="with no names, remove this job and everything in it")
    sub.add_argument("-d", "--domain", help=domain_help)

    command("list", cmd_list, "show the jobs, their names and where they point")

    sub = command("update", cmd_update, "check the public IP and update DNS now")
    sub.add_argument(
        "-n", "--dry-run", action="store_true", help="show what would change without changing it"
    )
    sub.add_argument(
        "-f", "--force", action="store_true", help="check every record even if the IP is unchanged"
    )

    command("status", cmd_status, "show the public IP, last update and timer state")

    sub = command("interval", cmd_interval, "show or set how often the timer runs")
    sub.add_argument("every", nargs="?", metavar="TIME", help="e.g. 5m, 30m, 1h")

    command("enable", cmd_enable, "turn automatic updates on")
    command("disable", cmd_disable, "turn automatic updates off")
    command("auth", cmd_auth, "set and verify the Porkbun API keys")

    sub = command("set", cmd_set, "change where a job points (ip), or ttl, ipv4, ipv6")
    sub.add_argument("setting", choices=["ip", "ttl", "ipv4", "ipv6"])
    sub.add_argument(
        "values",
        nargs="+",
        metavar="VALUE",
        help="ip: auto and/or one or more addresses; ttl: seconds; ipv4/ipv6: on or off",
    )
    sub.add_argument(
        "-j", "--job", help=f"job to change (ip: default {DEFAULT_JOB}; others: all jobs)"
    )

    sub = command("logs", cmd_logs, "show recent log output from the timer runs")
    sub.add_argument("-n", "--lines", type=int, default=30, help="number of lines (default: 30)")
    sub.add_argument("-f", "--follow", action="store_true", help="keep printing new lines")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
        stream=sys.stdout,
    )
    if not args.command:
        parser.print_help()
        return 2
    try:
        return args.handler(args)
    except Failure as exc:
        log.error("%s", exc)
        return 2
    except PermissionError as exc:
        log.error("%s: permission denied (run porkud as root)", exc.filename)
        return 2
    except (PorkbunError, *NETWORK_ERRORS) as exc:
        log.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
