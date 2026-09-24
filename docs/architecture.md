# Architecture

LightScan currently has two broad execution paths. The public command entry
point is `lightscan.cli:main`. Argument definitions live in
`lightscan/commands/parser.py`, while command orchestration remains in
`lightscan/cli.py`. Shared `ScanResult` and `Severity` models live in
`lightscan/core/models.py`; `core/engine.py` re-exports them for compatibility.
The bounded
TCP inventory path is implemented in `lightscan/scan/streaming.py`; it uses
`lightscan/core/target.py` for input expansion, `lightscan/core/models.py` for
the shared result record, and `lightscan/core/reporter.py` for serialization.
The optional Go executable implements the TCP connect path independently.

## Main data flow

```text
CLI options → target and port validation → scanner → ScanResult → Reporter
```

Focused command forms (`scan`, `services`, `web`, and `dns`) are translated to
the existing option interface for now. `report` reads a LightScan JSON report
and writes another supported format without starting a scan. Existing option
forms remain available for compatibility.

`ScanResult` is the compatibility record used by the current scanners. Its
`module`, `target`, `port`, `status`, `severity`, `detail`, `data`, and
`timestamp` fields are serialized by reporters. New scanner work should use
this record rather than introducing a module-specific result dictionary.

## Boundaries and known debt

- Command implementations and orchestration still share `lightscan/cli.py`.
  The extracted parser is the first boundary; later command extraction should
  preserve the installed `lightscan.cli:main` entry point.
- `scan/` currently contains both focused scanners and orchestration helpers.
  New code should depend on core contracts instead of importing CLI behavior.
- `ScanResult` is intentionally retained as the stable serialized contract.
  A stricter replacement needs a migration plan because existing modules use
  varied status strings and positional construction.
- The Go implementation shares the TCP scan semantics described in
  `engine-compatibility.md`; it does not implement every Python feature.
- Rate control and report data contracts are documented in
  `rate-limiting.md` and `result-model.md`.

The small TCP inventory flow is the reference path for new scanner work:
bounded target expansion, controlled connection starts, optional service
observation, structured results, and report output.
