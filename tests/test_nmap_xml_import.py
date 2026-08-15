from __future__ import annotations

from pathlib import Path

import pytest

from lightscan.core.nmap_xml import NmapXMLImportError, import_nmap_xml


def write_xml(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "inventory.xml"
    path.write_text(text, encoding="utf-8")
    return path


def test_import_nmap_xml_preserves_os_and_open_service_evidence(tmp_path: Path) -> None:
    source = write_xml(
        tmp_path,
        """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up" />
    <address addr="192.0.2.10" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" />
        <service name="ssh" product="OpenSSH" version="9.6" method="probed" conf="10">
          <cpe>cpe:/a:openbsd:openssh:9.6</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="23">
        <state state="closed" reason="reset" />
      </port>
    </ports>
    <os>
      <osmatch name="Linux 6.x" accuracy="96">
        <osclass vendor="Linux" osfamily="Linux" osgen="6.X" type="general purpose">
          <cpe>cpe:/o:linux:linux_kernel:6</cpe>
        </osclass>
      </osmatch>
    </os>
  </host>
</nmaprun>
""",
    )

    results, summary = import_nmap_xml(source)

    assert summary == {
        "source": "nmap-xml",
        "path": str(source),
        "hosts_seen": 1,
        "hosts_imported": 1,
        "os_observations": 1,
        "service_observations": 1,
    }
    assert [(result.module, result.target, result.port) for result in results] == [
        ("nmap-os-import", "192.0.2.10", 0),
        ("nmap-service-import", "192.0.2.10", 22),
    ]
    assert results[0].data["reported_accuracy"] == 96
    assert results[0].data["classes"] == [
        {"vendor": "Linux", "osfamily": "Linux", "osgen": "6.X", "type": "general purpose"}
    ]
    assert results[0].data["cpes"] == ["cpe:/o:linux:linux_kernel:6"]
    assert results[1].status == "open"
    assert results[1].data["name"] == "ssh"
    assert results[1].data["cpes"] == ["cpe:/a:openbsd:openssh:9.6"]


def test_import_nmap_xml_supports_ipv6_when_ipv4_is_absent(tmp_path: Path) -> None:
    source = write_xml(
        tmp_path,
        """<nmaprun><host><address addr="2001:db8::20" addrtype="ipv6" />
<ports><port protocol="tcp" portid="443"><state state="open|filtered" /></port></ports>
</host></nmaprun>""",
    )

    results, summary = import_nmap_xml(source)

    assert summary["hosts_imported"] == 1
    assert len(results) == 1
    assert results[0].target == "2001:db8::20"
    assert results[0].status == "open|filtered"


@pytest.mark.parametrize(
    "document, message",
    [
        ("<inventory />", "<nmaprun> root"),
        (
            "<!DOCTYPE nmaprun [<!ENTITY sample 'unsafe'>]><nmaprun />",
            "DTD or entity declarations",
        ),
        ("<nmaprun>", "Invalid Nmap XML"),
    ],
)
def test_import_nmap_xml_rejects_unsafe_or_invalid_documents(
    tmp_path: Path, document: str, message: str
) -> None:
    source = write_xml(tmp_path, document)

    with pytest.raises(NmapXMLImportError, match=message):
        import_nmap_xml(source)
