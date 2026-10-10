import contextlib
import io
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import porkbun_ud as pud
from porkbun_ud import Target

V4 = "8.8.8.8"
V6 = "2001:4860:4860::8888"


class FakeInternet:
    """Stands in for porkbun_ud.request: IP echo services plus the Porkbun DNS API."""

    def __init__(self, ipv4=V4, ipv6=V6):
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.rows = {}  # record id -> ((domain, type, name), content)
        self.last_id = 100
        self.calls = []  # (method, path) for every Porkbun DNS call
        self.fail = {}  # path -> list of (status, body dict) to return first
        self.account = []  # domains in the Porkbun account

    def __call__(self, method, url, *, headers=None, body=None, family=0):
        parts = pud.urllib.parse.urlsplit(url)
        if parts.path.endswith("/ip") or "ipify" in parts.hostname:
            ip = self.ipv6 if family == pud.socket.AF_INET6 else self.ipv4
            if ip is None:
                raise OSError("network unreachable")
            return 200, {}, json.dumps({"status": "SUCCESS", "yourIp": ip, "ip": ip}).encode()

        assert headers["X-API-Key"] == "pk" and headers["X-Secret-API-Key"] == "sk"
        path = parts.path.removeprefix("/api/json/v3")
        self.calls.append((method, path))
        if self.fail.get(path):
            status, payload = self.fail[path].pop(0)
            return status, {"Retry-After": "1"}, json.dumps(payload).encode()

        if path == "/ping":
            return self._ok({"credentialsValid": True})
        if path == "/domain/listAll":
            return self._ok({"domains": [{"domain": name} for name in self.account]})
        _, _, endpoint, domain, *rest = path.split("/")
        payload = json.loads(body) if body else {}
        if endpoint == "create":
            self.seed(domain, payload["type"], payload["name"], payload["content"])
            return self._ok({"id": "1"})
        if endpoint == "edit":
            key, _ = self.rows[rest[0]]
            assert key == (domain, payload["type"], payload["name"])
            self.rows[rest[0]] = (key, payload["content"])
            return self._ok({})
        if endpoint == "delete":
            del self.rows[rest[0]]
            return self._ok({})
        if endpoint == "retrieveByNameType":
            key = (domain, rest[0], rest[1] if len(rest) > 1 else "")
            found = [{"id": i, "content": c} for i, (k, c) in self.rows.items() if k == key]
            return self._ok({"records": found})
        raise AssertionError(f"unexpected call {method} {path}")

    @property
    def records(self):
        """(domain, type, name) -> list of contents"""
        result = {}
        for key, content in self.rows.values():
            result.setdefault(key, []).append(content)
        return result

    def seed(self, domain, rtype, name, *contents):
        for content in contents:
            self.last_id += 1
            self.rows[str(self.last_id)] = ((domain, rtype, name), content)

    @staticmethod
    def _ok(extra):
        return 200, {}, json.dumps({"status": "SUCCESS", **extra}).encode()

    def writes(self):
        return [path for method, path in self.calls if method == "POST"]


class UpdaterTestCase(unittest.TestCase):
    def setUp(self):
        self.net = FakeInternet()
        patcher = mock.patch.object(pud, "request", self.net)
        patcher.start()
        self.addCleanup(patcher.stop)
        sleeper = mock.patch.object(pud.time, "sleep")
        self.sleep = sleeper.start()
        self.addCleanup(sleeper.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "state" / "state.json"
        self.client = pud.Porkbun("pk", "sk")

    def write_config(self, text):
        path = Path(self.tmp.name) / "config.toml"
        path.write_text(text)
        return path

    def run_updater(self, targets, **kwargs):
        return pud.run(targets, self.client, self.state, **kwargs)


class ConfigTests(UpdaterTestCase):
    def test_expands_domains_records_and_types(self):
        targets = pud.load_config(
            self.write_config(
                """
                ttl = 900
                [[job]]
                name = "default"
                [[job.domain]]
                name = "Example.com"
                records = ["@", "www", "*"]
                [[job]]
                name = "JOB02"
                ipv6 = false
                ttl = 600
                [[job.domain]]
                name = "example.net"
                records = ["home"]
                """
            )
        )
        self.assertEqual(
            targets,
            sorted(
                [
                    Target("example.com", "", "A", 900),
                    Target("example.com", "", "AAAA", 900),
                    Target("example.com", "www", "A", 900),
                    Target("example.com", "www", "AAAA", 900),
                    Target("example.com", "*", "A", 900),
                    Target("example.com", "*", "AAAA", 900),
                    Target("example.net", "home", "A", 600),
                ]
            ),
        )

    def test_records_default_to_root(self):
        targets = pud.load_config(self.write_config('ipv6 = false\n[[domain]]\nname = "example.com"\n'))
        self.assertEqual(targets, [Target("example.com", "", "A", 600)])

    def test_rejects_bad_configs(self):
        bad = {
            "no domains": "ttl = 600\n",
            "low ttl": 'ttl = 60\n[[domain]]\nname = "example.com"\n',
            "fqdn as record": '[[domain]]\nname = "example.com"\nrecords = ["www.example.com"]\n',
            "bad record": '[[domain]]\nname = "example.com"\nrecords = ["bad name"]\n',
            "bad domain": '[[domain]]\nname = "localhost"\n',
            "typo in key": '[[domain]]\nname = "example.com"\nrecord = ["www"]\n',
            "wrong type": 'ipv6 = "no"\n[[domain]]\nname = "example.com"\n',
            "all disabled": 'ipv4 = false\nipv6 = false\n[[domain]]\nname = "example.com"\n',
            "not toml": "[[domain\n",
            "bad job name": '[[job]]\nname = "my job"\n',
            "bad ip": '[[job]]\nname = "a"\nip = ["auto", "1.2.3"]\n[[job.domain]]\nname = "example.com"\n',
            "empty ip": '[[job]]\nname = "a"\nip = []\n[[job.domain]]\nname = "example.com"\n',
            "job twice": '[[job]]\nname = "a"\n[[job]]\nname = "A"\n',
            "old per-domain setting": '[[domain]]\nname = "example.com"\nttl = 900\n',
        }
        for label, text in bad.items():
            with self.subTest(label), self.assertRaises(pud.ConfigError):
                pud.load_config(self.write_config(text))

    def test_missing_file(self):
        with self.assertRaises(pud.ConfigError):
            pud.load_config(Path(self.tmp.name) / "nope.toml")


class DetectIpTests(UpdaterTestCase):
    def test_returns_public_addresses(self):
        self.assertEqual(pud.detect_ip("A"), V4)
        self.assertEqual(pud.detect_ip("AAAA"), V6)

    def test_rejects_private_and_cgnat_addresses(self):
        for address in ("192.168.1.10", "10.0.0.2", "100.64.3.4"):
            self.net.ipv4 = address
            with self.subTest(address), self.assertLogs(pud.log, "WARNING"):
                self.assertIsNone(pud.detect_ip("A"))

    def test_rejects_wrong_family_and_garbage(self):
        self.net.ipv6 = V4
        self.assertIsNone(pud.detect_ip("AAAA"))
        self.net.ipv4 = "not an ip"
        self.assertIsNone(pud.detect_ip("A"))

    def test_falls_back_to_second_source(self):
        seen = []

        def flaky(method, url, **kwargs):
            seen.append(url)
            if "porkbun" in url:
                raise OSError("down")
            return 200, {}, json.dumps({"ip": V4}).encode()

        with mock.patch.object(pud, "request", flaky):
            self.assertEqual(pud.detect_ip("A"), V4)
        self.assertEqual(len(seen), 2)


class RunTests(UpdaterTestCase):
    WWW_A = Target("example.com", "www", "A", 600)
    WWW_AAAA = Target("example.com", "www", "AAAA", 600)
    ROOT_A = Target("example.com", "", "A", 600)

    def test_creates_missing_records(self):
        self.assertEqual(self.run_updater([self.ROOT_A, self.WWW_A, self.WWW_AAAA]), 0)
        self.assertEqual(
            self.net.records,
            {
                ("example.com", "A", ""): [V4],
                ("example.com", "A", "www"): [V4],
                ("example.com", "AAAA", "www"): [V6],
            },
        )
        self.assertIn(("GET", "/dns/retrieveByNameType/example.com/A"), self.net.calls)

    def test_updates_stale_record(self):
        self.net.seed("example.com", "A", "www", "1.1.1.1")
        self.assertEqual(self.run_updater([self.WWW_A]), 0)
        self.assertEqual(self.net.records[("example.com", "A", "www")], [V4])
        self.assertEqual(self.net.writes(), ["/dns/edit/example.com/101"])

    def test_leaves_correct_record_alone(self):
        # Same address, different spelling.
        self.net.seed("example.com", "AAAA", "www", "2001:4860:4860:0:0:0:0:8888")
        self.assertEqual(self.run_updater([self.WWW_AAAA]), 0)
        self.assertEqual(self.net.writes(), [])

    def test_dry_run_writes_nothing(self):
        self.net.seed("example.com", "A", "www", "1.1.1.1")
        self.assertEqual(self.run_updater([self.WWW_A, self.ROOT_A], dry_run=True), 0)
        self.assertEqual(self.net.writes(), [])
        self.assertFalse(self.state.exists())

    def test_second_run_skips_the_dns_api(self):
        self.run_updater([self.WWW_A])
        self.net.calls.clear()
        self.assertEqual(self.run_updater([self.WWW_A]), 0)
        self.assertEqual(self.net.calls, [])

    def test_rechecks_when_ip_config_or_age_changes(self):
        self.run_updater([self.WWW_A])

        self.net.calls.clear()
        self.net.ipv4 = "9.9.9.9"
        self.run_updater([self.WWW_A])
        self.assertEqual(self.net.records[("example.com", "A", "www")], ["9.9.9.9"])

        self.net.calls.clear()
        self.run_updater([self.WWW_A, self.ROOT_A])
        self.assertEqual(self.net.writes(), ["/dns/create/example.com"])

        self.net.calls.clear()
        self.run_updater([self.WWW_A, self.ROOT_A], force=True)
        self.assertEqual(len(self.net.calls), 2)

        self.net.calls.clear()
        state = json.loads(self.state.read_text())
        state["checked"] = time.time() - pud.FULL_CHECK_INTERVAL - 1
        self.state.write_text(json.dumps(state))
        self.run_updater([self.WWW_A, self.ROOT_A])
        self.assertEqual(len(self.net.calls), 2)

    def test_no_ipv6_skips_aaaa_but_succeeds(self):
        self.net.ipv6 = None
        with self.assertLogs(pud.log, "WARNING"):
            self.assertEqual(self.run_updater([self.WWW_A, self.WWW_AAAA]), 0)
        self.assertEqual(self.net.records, {("example.com", "A", "www"): [V4]})

    def test_no_ipv4_is_a_failure(self):
        self.net.ipv4 = None
        with self.assertLogs(pud.log, "ERROR"):
            self.assertEqual(self.run_updater([self.WWW_A, self.WWW_AAAA]), 1)
        self.assertEqual(self.net.records, {("example.com", "AAAA", "www"): [V6]})
        self.assertFalse(self.state.exists())

    def test_one_failure_does_not_stop_the_rest_and_is_retried(self):
        other = Target("locked.com", "", "A", 600)
        error = {
            "status": "ERROR",
            "code": "API_ACCESS_DISABLED",
            "message": "nope",
            "next_action": {"hint": "Enable API Access for this domain."},
        }
        self.net.fail["/dns/retrieveByNameType/locked.com/A"] = [(400, error)]
        with self.assertLogs(pud.log, "ERROR") as logs:
            self.assertEqual(self.run_updater([other, self.WWW_A]), 1)
        self.assertIn("nope [API_ACCESS_DISABLED] - Enable API Access", "\n".join(logs.output))
        self.assertEqual(self.net.records, {("example.com", "A", "www"): [V4]})

        # Nothing was cached, so the next run tries the failed record again.
        self.assertEqual(self.run_updater([other, self.WWW_A]), 0)
        self.assertEqual(self.net.records[("locked.com", "A", "")], [V4])

    def test_retries_once_after_rate_limit(self):
        limited = (429, {"status": "ERROR", "code": "RATE_LIMIT_EXCEEDED", "message": "slow down"})
        self.net.fail["/dns/retrieveByNameType/example.com/A/www"] = [limited]
        with self.assertLogs(pud.log, "WARNING"):
            self.assertEqual(self.run_updater([self.WWW_A]), 0)
        self.sleep.assert_called_once_with(1)
        self.assertEqual(self.net.records[("example.com", "A", "www")], [V4])

    def test_fixed_addresses_need_no_detection(self):
        self.net.ipv4 = self.net.ipv6 = None
        fixed = Target("example.com", "nas", "A", 600, False, ("203.0.113.7", "203.0.113.8"))
        self.assertEqual(self.run_updater([fixed]), 0)
        self.assertEqual(self.net.records, {("example.com", "A", "nas"): ["203.0.113.7", "203.0.113.8"]})
        self.net.calls.clear()
        self.assertEqual(self.run_updater([fixed]), 0)
        self.assertEqual(self.net.calls, [])

    def test_several_addresses_reuse_create_and_delete_records(self):
        both = Target("example.com", "www", "A", 600, True, ("203.0.113.7",))
        self.net.seed("example.com", "A", "www", "1.1.1.1")
        self.assertEqual(self.run_updater([both]), 0)
        self.assertEqual(self.net.records, {("example.com", "A", "www"): [V4, "203.0.113.7"]})
        self.assertEqual(self.net.writes(), ["/dns/edit/example.com/101", "/dns/create/example.com"])

        # Back to the public address alone: the extra record goes, the right one stays.
        self.net.calls.clear()
        self.assertEqual(self.run_updater([self.WWW_A]), 0)
        self.assertEqual(self.net.records, {("example.com", "A", "www"): [V4]})
        self.assertEqual(len(self.net.writes()), 1)
        self.assertTrue(self.net.writes()[0].startswith("/dns/delete/example.com/"))

    def test_duplicate_records_are_reduced_to_one(self):
        self.net.seed("example.com", "A", "www", V4, V4)
        self.assertEqual(self.run_updater([self.WWW_A]), 0)
        self.assertEqual(self.net.records, {("example.com", "A", "www"): [V4]})

    def test_wildcard_path_is_not_escaped(self):
        self.run_updater([Target("example.com", "*", "A", 600)])
        self.assertIn(("GET", "/dns/retrieveByNameType/example.com/A/*"), self.net.calls)


class MainTests(UpdaterTestCase):
    def test_missing_credentials(self):
        config = self.write_config('[[domain]]\nname = "example.com"\n')
        with mock.patch.dict(pud.os.environ, {}, clear=True), self.assertLogs(pud.log, "ERROR"):
            self.assertEqual(pud.main(["-c", str(config), "update"]), 2)

    def test_end_to_end(self):
        config = self.write_config('ipv6 = false\n[[domain]]\nname = "example.com"\nrecords = ["www"]\n')
        env = {
            "PORKBUN_API_KEY": "pk",
            "PORKBUN_SECRET_API_KEY": "sk",
            "STATE_DIRECTORY": str(self.state.parent),
        }
        with mock.patch.dict(pud.os.environ, env, clear=True):
            self.assertEqual(pud.main(["-c", str(config), "update"]), 0)
        self.assertEqual(self.net.records, {("example.com", "A", "www"): [V4]})
        self.assertTrue(self.state.exists())


class CliTests(UpdaterTestCase):
    ENV = {"PORKBUN_API_KEY": "pk", "PORKBUN_SECRET_API_KEY": "sk"}

    def setUp(self):
        super().setUp()
        self.config = Path(self.tmp.name) / "etc" / "config.toml"
        self.dropin = Path(self.tmp.name) / "timer.d" / "interval.conf"
        self.systemctl = self.patch(pud, "systemctl")
        self.patch(pud, "TIMER_DROPIN", str(self.dropin))
        env = mock.patch.dict(pud.os.environ, {"STATE_DIRECTORY": str(self.state.parent)}, clear=True)
        env.start()
        self.addCleanup(env.stop)

    def patch(self, target, name, *args):
        patcher = mock.patch.object(target, name, *args)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def porkud(self, *argv, stdin=""):
        """Run a porkud command. Returns (exit status, stdout)."""
        output = io.StringIO()
        with contextlib.redirect_stdout(output), mock.patch.object(pud.sys, "stdin", io.StringIO(stdin)):
            status = pud.main(["-c", str(self.config), *argv])
        return status, output.getvalue()

    def failing(self, *argv, stdin=""):
        with self.assertLogs(pud.log, "ERROR") as logs:
            status, _ = self.porkud(*argv, stdin=stdin)
        self.assertNotEqual(status, 0)
        return "\n".join(logs.output)

    def names(self):
        return sorted({target.fqdn for target in pud.load_config(self.config)})

    def test_add_uses_domains_already_in_the_config(self):
        self.assertEqual(self.porkud("add", "--domain", "example.co.uk", "home.example.co.uk")[0], 0)
        status, output = self.porkud("add", "example.co.uk", "*.lab.example.co.uk", "Home.Example.co.uk.")
        self.assertEqual(status, 0)
        self.assertIn("home.example.co.uk is already in job default", output)
        self.assertEqual(self.names(), ["*.lab.example.co.uk", "example.co.uk", "home.example.co.uk"])
        self.assertEqual(self.net.calls, [])

    def test_add_looks_up_the_domain_in_the_porkbun_account(self):
        self.net.account = ["example.com", "example.co.uk"]
        with mock.patch.dict(pud.os.environ, self.ENV):
            self.assertEqual(self.porkud("add", "a.b.example.co.uk", "www.example.com")[0], 0)
        config = pud.read_config(self.config)
        self.assertEqual(
            config["jobs"][0]["domains"],
            [{"name": "example.co.uk", "records": ["a.b"]}, {"name": "example.com", "records": ["www"]}],
        )
        self.assertEqual(self.net.calls.count(("POST", "/domain/listAll")), 1)

    def test_add_fails_when_the_domain_cannot_be_worked_out(self):
        self.assertIn("--domain", self.failing("add", "home.example.com"))
        self.assertFalse(self.config.exists())

    def test_add_with_domain_accepts_bare_labels(self):
        self.porkud("add", "-d", "example.com", "www", "@")
        self.assertEqual(self.names(), ["example.com", "www.example.com"])
        self.assertIn("invalid record name", self.failing("add", "-d", "example.com", "bad name"))

    def test_remove(self):
        self.porkud("add", "-d", "example.com", "www", "home")
        status, output = self.porkud("remove", "www.example.com")
        self.assertEqual(status, 0)
        self.assertIn("left as they are", output)
        self.assertEqual(self.names(), ["home.example.com"])
        self.assertIn("not in the config", self.failing("remove", "nope.example.com"))
        self.porkud("remove", "home.example.com")
        self.assertEqual(pud.read_config(self.config)["jobs"][0]["domains"], [])

    def test_list(self):
        self.assertIn("Nothing configured", self.porkud("list")[1])
        self.porkud("add", "-d", "example.com", "www")
        self.porkud("add", "-j", "JOB02", "-d", "example.net", "@")
        self.porkud("set", "-j", "job02", "ip", "wan", "203.0.113.7")
        self.porkud("set", "-j", "JOB02", "ipv6", "off")
        self.porkud("set", "-j", "JOB03", "ip", "2001:db8::1")
        rows = [line.split("  ") for line in self.porkud("list")[1].splitlines()]
        rows = [[cell.strip() for cell in row if cell.strip()] for row in rows]
        self.assertEqual(
            rows,
            [
                ["JOB", "NAME", "IP", "TTL"],
                ["default", "www.example.com", "auto", "600"],
                ["JOB02", "example.net", "auto (IPv4 only), 203.0.113.7", "600"],
                ["JOB03", "(no names yet)", "2001:db8::1", "600"],
            ],
        )

    def test_set(self):
        self.porkud("add", "-d", "example.com", "www")
        self.porkud("add", "-j", "other", "-d", "example.net", "www")
        self.assertEqual(self.porkud("set", "ttl", "900")[0], 0)
        self.assertEqual(self.porkud("set", "ipv6", "off")[0], 0)
        self.assertEqual(self.porkud("set", "ttl", "3600", "-j", "other")[0], 0)
        self.assertEqual(
            pud.load_config(self.config),
            [Target("example.com", "www", "A", 900), Target("example.net", "www", "A", 3600)],
        )
        self.failing("set", "ttl", "60")
        self.failing("set", "ttl", "900", "1200")
        self.failing("set", "ipv4", "maybe")
        self.failing("set", "ttl", "900", "-j", "missing")

    def test_set_ip(self):
        self.porkud("add", "-d", "example.com", "www")
        self.porkud("add", "-j", "JOB02", "-d", "example.com", "nas")
        self.porkud("add", "-j", "JOB03", "-d", "example.com", "lab")
        self.assertEqual(self.porkud("set", "-j", "JOB02", "ip", "203.0.113.7", "203.0.113.8", "2001:DB8::1")[0], 0)
        self.assertEqual(self.porkud("set", "-j", "JOB03", "ip", "auto", "203.0.113.9")[0], 0)
        self.assertEqual(
            pud.load_config(self.config),
            sorted(
                [
                    Target("example.com", "www", "A", 600),
                    Target("example.com", "www", "AAAA", 600),
                    Target("example.com", "nas", "A", 600, False, ("203.0.113.7", "203.0.113.8")),
                    Target("example.com", "nas", "AAAA", 600, False, ("2001:db8::1",)),
                    Target("example.com", "lab", "A", 600, True, ("203.0.113.9",)),
                    Target("example.com", "lab", "AAAA", 600, True, ()),
                ]
            ),
        )
        # Without --job it is the default job that changes.
        self.porkud("set", "ip", "198.51.100.4")
        self.assertIn(Target("example.com", "www", "A", 600, False, ("198.51.100.4",)), pud.load_config(self.config))
        self.assertIn("--job", self.failing("set", "ip", "JOB02", "auto"))

    def test_jobs_run_end_to_end(self):
        self.porkud("auth", stdin="pk\nsk\n")
        self.porkud("set", "ipv6", "off")
        self.porkud("add", "-d", "example.com", "www")
        self.porkud("add", "-j", "JOB02", "-d", "example.com", "nas")
        self.porkud("set", "-j", "JOB02", "ip", "203.0.113.7", "203.0.113.8")
        self.assertEqual(self.porkud("update")[0], 0)
        self.assertEqual(
            self.net.records,
            {
                ("example.com", "A", "nas"): ["203.0.113.7", "203.0.113.8"],
                ("example.com", "A", "www"): [V4],
            },
        )

    def test_a_name_belongs_to_one_job(self):
        self.porkud("add", "-d", "example.com", "www")
        self.assertIn("already in job default", self.failing("add", "-j", "JOB02", "www.example.com"))
        self.config.write_text(
            '[[job]]\nname = "a"\n[[job.domain]]\nname = "example.com"\nrecords = ["www"]\n'
            '[[job]]\nname = "b"\n[[job.domain]]\nname = "example.com"\nrecords = ["www"]\n'
        )
        self.assertIn("in both job", self.failing("list"))

    def test_remove_job(self):
        self.porkud("add", "-d", "example.com", "www")
        self.porkud("add", "-j", "JOB02", "-d", "example.com", "nas", "lab")
        self.assertIn("not in job JOB02", self.failing("remove", "-j", "JOB02", "www.example.com"))
        status, output = self.porkud("remove", "--job", "job02")
        self.assertEqual(status, 0)
        self.assertIn("Removed job JOB02 and its 2 name(s)", output)
        self.assertEqual(self.names(), ["www.example.com"])
        self.failing("remove")
        self.failing("remove", "-j", "JOB02")

    def test_config_written_before_jobs_is_still_read(self):
        self.config.parent.mkdir()
        self.config.write_text('ttl = 900\nipv6 = false\n[[domain]]\nname = "example.com"\nrecords = ["@", "*"]\n')
        before = pud.load_config(self.config)
        self.assertEqual(before, [Target("example.com", "", "A", 900), Target("example.com", "*", "A", 900)])
        self.porkud("add", "-d", "example.net", "www")
        self.porkud("remove", "www.example.net")
        self.assertEqual(pud.load_config(self.config), before)
        self.assertIn("[[job]]", self.config.read_text())

    def test_interval(self):
        self.assertIn("every 5m", self.porkud("interval")[1])
        self.assertEqual(self.porkud("interval", "30m")[0], 0)
        self.assertIn("OnUnitActiveSec=1800s", self.dropin.read_text())
        self.assertEqual(
            self.systemctl.call_args_list,
            [mock.call("daemon-reload"), mock.call("try-restart", "porkbun-ud.timer")],
        )
        self.assertIn("every 30m", self.porkud("interval")[1])
        self.failing("interval", "10s")
        self.failing("interval", "soon")

    def test_parse_duration(self):
        cases = {"90s": 90, "5": 300, "5m": 300, "15min": 900, "1h": 3600, "2 hours": 7200, "1d": 86400}
        for text, seconds in cases.items():
            with self.subTest(text):
                self.assertEqual(pud.parse_duration(text), seconds)
        self.assertEqual(pud.format_duration(90), "90s")
        self.assertEqual(pud.format_duration(7200), "2h")

    def test_enable_and_disable(self):
        self.porkud("enable")
        self.porkud("disable")
        self.assertEqual(
            self.systemctl.call_args_list,
            [mock.call("enable", "--now", "porkbun-ud.timer"), mock.call("disable", "--now", "porkbun-ud.timer")],
        )

    def test_auth_saves_valid_keys_and_update_reads_them(self):
        self.assertEqual(self.porkud("auth", stdin="pk\nsk\n")[0], 0)
        path = self.config.parent / "credentials.env"
        self.assertEqual(path.read_text(), "PORKBUN_API_KEY=pk\nPORKBUN_SECRET_API_KEY=sk\n")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

        self.porkud("add", "-d", "example.com", "www")
        self.porkud("set", "ipv6", "off")
        self.assertEqual(self.porkud("update")[0], 0)
        self.assertEqual(self.net.records, {("example.com", "A", "www"): [V4]})

    def test_auth_rejects_invalid_keys(self):
        error = {"status": "ERROR", "code": "INVALID_API_KEYS", "message": "Invalid API key."}
        self.net.fail["/ping"] = [(400, error)]
        self.assertIn("Invalid API key", self.failing("auth", stdin="pk\nsk\n"))
        self.assertFalse((self.config.parent / "credentials.env").exists())

    def test_update_without_names_or_keys(self):
        self.assertIn("porkud add", self.failing("update"))
        self.porkud("add", "-d", "example.com", "www")
        self.assertIn("porkud auth", self.failing("update"))

    def test_status(self):
        self.porkud("add", "-d", "example.com", "www")
        with mock.patch.object(pud.subprocess, "run") as run:
            run.return_value.stdout = "inactive\n"
            output = self.porkud("status")[1]
        self.assertIn(f"Public IPv4:  {V4}", output)
        self.assertIn("Last applied: nothing yet", output)
        self.assertIn("API keys:     missing", output)
        self.assertIn("Timer:        off (inactive)", output)

    def test_no_command_prints_help(self):
        status, output = self.porkud()
        self.assertEqual(status, 2)
        self.assertIn("add", output)


if __name__ == "__main__":
    unittest.main()
