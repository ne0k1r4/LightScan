import unittest
import io
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from lightscan.brute.mutation import MutationEngine
from lightscan.scan.passive import PassiveHost, PassiveSniffer
from lightscan.scan.ipv6scan import mac_to_eui64, predict_slaac
from lightscan.scan.traceroute import _get_local_ip
from lightscan.cve.bridge import versions_from_results
from lightscan.web.scanner import WebScanner
from lightscan.core.engine import ScanResult, Severity

class ModuleCoverageTest(unittest.IsolatedAsyncioTestCase):
    
    # ── 1. Brute Force Mutation Engine ──
    def test_brute_force_mutation_engine(self):
        """Test password variants generation and context capitalization."""
        engine = MutationEngine(
            base_words=["cyber", "security"],
            target_info={"org": "Google"},
            include_common=False
        )
        mutations = engine.generate(username="admin")
        
        # Verify custom user combinations and context org words
        self.assertIn("admin!", mutations)
        self.assertIn("admin2024", mutations)
        self.assertIn("Google!", mutations)
        self.assertIn("cyber!", mutations)
        
        # Leet translate (a->4, e->3, o->0, etc)
        self.assertIn("cyb3r", mutations)

    # ── 2. Passive Sniffer Data Structure ──
    def test_passive_host_summary(self):
        """Test the string representation of passive sniffer hosts."""
        host = PassiveHost(ip="192.168.1.5", mac="00:0c:29:11:22:33", hostname="win10.local")
        host.os_hints.append("VMware")
        host.services.append("http")
        
        summary = host.summary()
        self.assertIn("192.168.1.5", summary)
        self.assertIn("00:0c:29:11:22:33", summary)
        self.assertIn("(win10.local)", summary)
        self.assertIn("[VMware]", summary)
        self.assertIn("svcs=http", summary)

    # ── 3. EUI-64 SLAAC Conversion ──
    def test_eui64_mac_conversion(self):
        """Test conversion of standard MAC addresses to IPv6 EUI-64 identifiers."""
        mac = "00:0c:29:11:22:33"
        eui = mac_to_eui64(mac)
        
        # EUI-64 inserts ff:fe in the middle and flips 7th bit
        # 00 -> 02 -> 020c:29ff:fe11:2233
        self.assertEqual(eui, "020c:29ff:fe11:2233")
        
        # Test SLAAC target prediction with 4-block subnet prefix
        pred = predict_slaac("2001:db8:1111:2222::/64", mac)
        self.assertEqual(pred, "2001:db8:1111:2222:20c:29ff:fe11:2233")

    # ── 4. Local Route Identification ──
    def test_traceroute_local_route_resolver(self):
        """Test local IP identification for packet routing."""
        ip = _get_local_ip("127.0.0.1")
        self.assertTrue(len(ip.split(".")) == 4)

    # ── 5. OAuth Audit Flow Deduplication ──
    def test_cve_bridge_versions_extractor(self):
        """Test extracting active service versions in the CVE bridge."""
        results = [
            ScanResult("active:service", "10.0.0.5", 80, "detected", Severity.INFO, "Apache 2.4.41", {"version": "2.4.41"})
        ]
        vers = versions_from_results(results)
        self.assertEqual(vers.get(80), "2.4.41")
        
        # Import oauth tester inside the function to avoid pytest collection issues
        from lightscan.cve.oauth import test_open_redirect
        self.assertTrue(callable(test_open_redirect))

    # ── 6. WebApp Scanner Tech Heuristics ──
    def test_web_app_scanner_signatures(self):
        """Test the WebScanner technology heuristic detection system."""
        scanner = WebScanner(base_url="http://127.0.0.1")
        
        # Mock _get return response
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Server": "cloudflare-nginx",
            "X-Powered-By": "Next.js",
            "X-AspNet-Version": "4.0",
            "Set-Cookie": "PHPSESSID=abc123xyz"
        }
        mock_resp.text = "<html><head><meta name='generator' content='WordPress 6.4'/></head><body>Welcome to the site</body></html>"
        
        # Inject mock handlers
        scanner._get = MagicMock(return_value=mock_resp)
        scanner._headers = MagicMock(return_value=mock_resp.headers)
        scanner._text = MagicMock(return_value=mock_resp.text)
        
        techs = scanner.fingerprint_tech()
        
        self.assertIn("server", techs)
        self.assertEqual(techs["server"], "cloudflare-nginx")
        self.assertEqual(techs["powered_by"], "Next.js")
        self.assertEqual(techs["backend"], "PHP")
        self.assertEqual(techs["generator"], "WordPress 6.4")

if __name__ == "__main__":
    unittest.main()
