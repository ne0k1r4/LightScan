# Contributing

Keep changes focused on a specific scanner behavior or report contract. Prefer
the bounded TCP inventory flow as the reference for target limits, rate
controls, result handling, and metrics. Avoid adding another top-level CLI
flag when an existing focused command or a subcommand can express the task.

Before changing scan controls, update `engine-compatibility.md` and run the
Python and Go suites. Prefer tests that assert observable behavior: expanded
targets, connection start spacing, in-flight limits, retry counts, cancellation,
and serialized reports. Network tests should use local fixtures.

Run the checks from the repository root:

```bash
python -m pytest -q
go test ./...
python -m compileall -q lightscan tests
```
