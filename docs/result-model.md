# Result model

Scanners return `lightscan.core.models.ScanResult`. Report writers use the
same record, and `to_dict()` defines its JSON-compatible base representation.

| Field | Type | Meaning |
| --- | --- | --- |
| `module` | `str` | Scanner or check that produced the observation |
| `target` | `str` | Host or URL associated with it |
| `port` | `int` | Port number; zero represents a host-level observation |
| `status` | `str` | Module-specific outcome such as `open` or `vulnerable` |
| `severity` | `Severity` | Display and triage severity |
| `detail` | `str` | Human-readable summary |
| `data` | `dict[str, Any]` | Structured evidence and module metadata |
| `timestamp` | `float` | Unix timestamp in seconds |

`status` remains a string because a TCP port state and a vulnerability result
do not share one finite state vocabulary. Keep structured machine-readable
evidence in `data`; do not make consumers parse `detail`. Add new fields only
with a compatibility review of JSON, CSV, HTML, and XML output.
