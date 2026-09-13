import asyncio
import io
import sys
import unittest
import socket
from unittest.mock import MagicMock, patch
from pathlib import Path

from lightscan.scan.active import _PORT_VALIDATORS, validate_port, register_validator
from lightscan.cve.template_engine import Template, TemplateRunner, Matcher, TemplateStep
from lightscan.core.engine import ScanResult, Severity
from lightscan.core.target import parse_targets, parse_ports
from lightscan.core.reporter import Reporter
from lightscan.scan.orchestrator import run_auto, TargetContext

class UltimateChallengeTest(unittest.IsolatedAsyncioTestCase):
    
    async def test_plugin_registry_multiple_dispatch_overlap(self):
        """Challenge the active scan validator registry with multiple handlers on the same port."""
        test_port = 9999
        
        @register_validator(test_port)
        async def mock_vuln_one(host, port, timeout):
            return ScanResult("active:test1", host, port, "VULN", Severity.HIGH, "Finding One")
            
        @register_validator(test_port)
        async def mock_vuln_two(host, port, timeout):
            return ScanResult("active:test2", host, port, "VULN", Severity.CRITICAL, "Finding Two")
            
        try:
            self.assertIn(test_port, _PORT_VALIDATORS)
            self.assertEqual(len(_PORT_VALIDATORS[test_port]), 2)
            
            results = await validate_port("127.0.0.1", test_port, 1.0)
            
            modules = {r.module for r in results}
            self.assertIn("active:test1", modules)
            self.assertIn("active:test2", modules)
            self.assertEqual(len(results), 2)
            
        finally:
            if test_port in _PORT_VALIDATORS:
                del _PORT_VALIDATORS[test_port]

    async def test_matcher_dsl_nested_evaluations(self):
        """Test logical AND/OR evaluations and negative rules in the Matcher DSL."""
        runner = TemplateRunner()
        
        step_and = TemplateStep(
            type="match",
            matchers_condition="and",
            matchers=[
                Matcher(type="status", status=[200]),
                Matcher(type="word", words=["denied", "forbidden"], condition="or", part="body", negative=True)
            ]
        )
        
        self.assertTrue(runner._check_match(step_and, "Welcome to the home page!", 200, ""))
        self.assertFalse(runner._check_match(step_and, "Access forbidden!", 200, ""))
        self.assertFalse(runner._check_match(step_and, "Welcome home", 404, ""))

        step_or = TemplateStep(
            type="match",
            matchers_condition="or",
            matchers=[
                Matcher(type="regex", regex=[r"version \d\.\d"], part="body"),
                Matcher(type="regex", regex=[r"build-\d{4}"], part="body")
            ]
        )
        
        self.assertTrue(runner._check_match(step_or, "App version 1.2 build", 200, ""))
        self.assertTrue(runner._check_match(step_or, "App build-8899", 200, ""))
        self.assertFalse(runner._check_match(step_or, "Clean release build", 200, ""))

    def test_stdin_pipe_target_parsing_and_ranges(self):
        """Test target parsing from standard input with CIDR subnets and hyphenated ranges."""
        stdin_content = "10.0.0.1\n# comment line\n192.168.1.50-52\n10.10.10.0/30\n"
        
        with patch("sys.stdin", io.StringIO(stdin_content)):
            targets = parse_targets("-")
            
        expected = [
            "10.0.0.1",
            "192.168.1.50", "192.168.1.51", "192.168.1.52",
            "10.10.10.1", "10.10.10.2"
        ]
        for ip in expected:
            self.assertIn(ip, targets)
        self.assertEqual(len(targets), 6)

    def test_reporter_clean_stdout_generation(self):
        """Test clean stdout serialization when output is set to standard output."""
        results = [
            ScanResult("active:test", "127.0.0.1", 80, "VULN", Severity.HIGH, "Exposed page")
        ]
        meta = {"target": "127.0.0.1"}
        
        captured_stream = io.StringIO()
        Reporter.stdout_override = captured_stream
        
        reporter = Reporter("-")
        path = reporter.save(results, meta, fmt="json")
        
        self.assertEqual(path, "-")
        raw_output = captured_stream.getvalue()
        
        import json
        data = json.loads(raw_output)
        self.assertEqual(data["meta"]["target"], "127.0.0.1")
        self.assertEqual(data["results"][0]["host"], "127.0.0.1")
        self.assertEqual(data["results"][0]["severity"], "HIGH")

    async def test_orchestrator_sweep_mode_skips(self):
        """Test that sweep mode restricts active and autonomous runs strictly to discovery phases."""
        from lightscan.scan.active import active_scan
        
        with patch("lightscan.scan.active.tcp_scan") as mock_tcp_scan, \
             patch("lightscan.scan.active.discover_hosts") as mock_discover:
             
            mock_discover.return_value = [("127.0.0.1", "icmp", 0.5, 64, "localhost")]
            mock_tcp_scan.return_value = ScanResult("portscan", "127.0.0.1", 80, "open", Severity.INFO, "open")
            
            results = await active_scan(
                targets=["127.0.0.1"],
                ports=[80],
                mode="sweep",
                skip_discovery=False
            )
            
            modules = {r.module for r in results}
            self.assertIn("active:discovery", modules)
            self.assertIn("portscan", modules)
            self.assertNotIn("active:service", modules)
            self.assertNotIn("active:http", modules)

if __name__ == "__main__":
    unittest.main()
