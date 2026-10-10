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
        self.records = {}  # (domain, type, name) -> list of contents
        self.calls = []  # (method, path) for every Porkbun DNS call
        self.fail = {}  # path -> list of (status, body dict) to return first

    def __call__(self, method, url, *, headers=None, body=None, family=0):
        parts = pud.urllib.parse.urlsplit(url)
        if not parts.path.startswith("/api/json/v3/dns/"):
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

        _, _, endpoint, domain, *rest = path.split("/")
        payload = json.loads(body) if body else {}
        if endpoint == "create":
            key = (domain, payload["type"], payload["name"])
            self.records.setdefault(key, []).append(payload["content"])
            return self._ok({"id": "1"})
        key = (domain, rest[0], rest[1] if len(rest) > 1 else "")
        if endpoint == "retrieveByNameType":
            contents = self.records.get(key, [])
            return self._ok({"records": [{"id": "1", "content": c} for c in contents]})
        if endpoint == "editByNameType":
            self.records[key] = [payload["content"]] * len(self.records[key])
            return self._ok({})
        raise AssertionError(f"unexpected call {method} {path}")

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
                [[domain]]
                name = "Example.com"
                records = ["@", "www", "*"]
                [[domain]]
                name = "example.net"
                records = ["home"]
                ipv6 = false
                ttl = 600
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
        self.net.records[("example.com", "A", "www")] = ["1.1.1.1"]
        self.assertEqual(self.run_updater([self.WWW_A]), 0)
        self.assertEqual(self.net.records[("example.com", "A", "www")], [V4])
        self.assertEqual(self.net.writes(), ["/dns/editByNameType/example.com/A/www"])

    def test_leaves_correct_record_alone(self):
        # Same address, different spelling.
        self.net.records[("example.com", "AAAA", "www")] = ["2001:4860:4860:0:0:0:0:8888"]
        self.assertEqual(self.run_updater([self.WWW_AAAA]), 0)
        self.assertEqual(self.net.writes(), [])

    def test_dry_run_writes_nothing(self):
        self.net.records[("example.com", "A", "www")] = ["1.1.1.1"]
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

    def test_wildcard_path_is_not_escaped(self):
        self.run_updater([Target("example.com", "*", "A", 600)])
        self.assertIn(("GET", "/dns/retrieveByNameType/example.com/A/*"), self.net.calls)


class MainTests(UpdaterTestCase):
    def test_missing_credentials(self):
        config = self.write_config('[[domain]]\nname = "example.com"\n')
        with mock.patch.dict(pud.os.environ, {}, clear=True), self.assertLogs(pud.log, "ERROR"):
            self.assertEqual(pud.main(["-c", str(config)]), 2)

    def test_end_to_end(self):
        config = self.write_config('ipv6 = false\n[[domain]]\nname = "example.com"\nrecords = ["www"]\n')
        env = {
            "PORKBUN_API_KEY": "pk",
            "PORKBUN_SECRET_API_KEY": "sk",
            "STATE_DIRECTORY": str(self.state.parent),
        }
        with mock.patch.dict(pud.os.environ, env, clear=True):
            self.assertEqual(pud.main(["-c", str(config)]), 0)
        self.assertEqual(self.net.records, {("example.com", "A", "www"): [V4]})
        self.assertTrue(self.state.exists())


if __name__ == "__main__":
    unittest.main()
