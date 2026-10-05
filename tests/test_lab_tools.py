import contextlib
import io
import os
import socket
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import flow_parser  # noqa: E402
import port_scanner  # noqa: E402
import subnet_calc  # noqa: E402


class PortScannerTests(unittest.TestCase):
    def test_refuses_public_targets(self):
        self.assertFalse(port_scanner.is_private("8.8.8.8"))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(port_scanner.main(["8.8.8.8", "--i-am-authorized", "-p", "53"]), 2)

    def test_requires_authorization_flag(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(port_scanner.main(["127.0.0.1", "-p", "1"]), 2)

    def test_private_ranges(self):
        for ip in ["127.0.0.1", "10.1.2.3", "172.20.0.5", "192.168.50.1"]:
            self.assertTrue(port_scanner.is_private(ip), ip)
        self.assertFalse(port_scanner.is_private("172.32.0.1"))

    def test_parse_ports(self):
        self.assertEqual(port_scanner.parse_ports("22,80,8000-8002,80"), [22, 80, 8000, 8001, 8002])

    def test_finds_open_local_port(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        port = srv.getsockname()[1]
        try:
            open_ports = port_scanner.scan("127.0.0.1", [port, port + 1 if port < 65535 else port - 1], 0.3, 4)
            self.assertIn(port, open_ports)
        finally:
            srv.close()


class FlowParserTests(unittest.TestCase):
    def setUp(self):
        self.summary = flow_parser.summarize(
            flow_parser.load_flows(os.path.join(ROOT, "data", "sample_flows.csv")))

    def test_counts(self):
        self.assertEqual(self.summary["total_flows"], 82)
        self.assertEqual(self.summary["protocols"], {"TCP": 67, "UDP": 15})

    def test_detects_beaconing(self):
        suspects = {(b["src"], b["dst"]) for b in self.summary["beaconing_suspects"]}
        # Only the regular 60s call-home is flagged; random-time DNS lookups are not.
        self.assertEqual(suspects, {("10.10.20.10", "10.10.10.66:4444")})
        self.assertEqual(self.summary["beaconing_suspects"][0]["interval_s"], 60.0)

    def test_detects_port_scan(self):
        scans = self.summary["scan_suspects"]
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["src"], "10.10.10.5")
        self.assertEqual(scans[0]["distinct_ports"], 14)


class SubnetCalcTests(unittest.TestCase):
    def test_describe_24(self):
        import ipaddress
        out = subnet_calc.describe(ipaddress.IPv4Network("192.168.1.0/24"))
        self.assertIn("Broadcast:      192.168.1.255", out)
        self.assertIn("Usable hosts:   254  (192.168.1.1 - 192.168.1.254)", out)
        self.assertIn("Wildcard:       0.0.0.255", out)

    def test_edge_prefixes(self):
        import ipaddress
        self.assertEqual(subnet_calc.host_range(ipaddress.IPv4Network("10.0.0.0/31")), (2, "10.0.0.0", "10.0.0.1"))
        self.assertEqual(subnet_calc.host_range(ipaddress.IPv4Network("10.0.0.7/32")), (1, "10.0.0.7", "10.0.0.7"))
        self.assertEqual(subnet_calc.host_range(ipaddress.IPv4Network("10.0.0.0/8"))[0], 16777214)

    def test_cli_runs(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = subnet_calc.main(["10.0.0.0/16", "--split", "4", "--contains", "10.0.200.1"])
        self.assertEqual(rc, 0)
        self.assertIn("10.0.192.0/18", buf.getvalue())
        self.assertIn("10.0.200.1 in 10.0.0.0/16? yes", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
