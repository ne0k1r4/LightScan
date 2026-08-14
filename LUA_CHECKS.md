# Constrained Lua Checks

LightScan v2.4 introduces a **Lua-inspired, NSE-style extension point** for custom vulnerability and configuration checks on systems you own or are explicitly authorized to test. It adopts familiar script metadata and service-oriented execution, but it is intentionally **not a general NSE interpreter**.

> **Safety boundary:** A Lua check receives only a read-only observation collected by LightScan. Lua code cannot open sockets, access the filesystem, load modules, spawn processes, or invoke operating-system APIs.

Nmap documents that NSE scripts are not sandboxed and advises users to trust or audit third-party scripts before execution.[1] LightScan takes the opposite approach for this extension point: it accepts a narrower API so a custom check can evaluate service observations without gaining ambient machine or network authority.

## Execution model

| Stage | LightScan responsibility | Lua check responsibility |
| --- | --- | --- |
| Port discovery | Confirms open TCP ports using the selected scan engine. | None. Checks are never scheduled against unconfirmed ports. |
| Observation | Opens a short TCP connection and reads up to 4 KiB. For known HTTP ports, sends a fixed `HEAD / HTTP/1.0` request and records the response. | None. A check never receives a socket. |
| Evaluation | Runs Lua 5.4 in a dedicated short-lived process with a 2-second execution limit. | Decides whether the supplied read-only context indicates a non-destructive finding. |
| Result normalization | Validates severity, detail length, and evidence shape, then converts the output into `ScanResult`. | Returns declarative findings through `lightscan.finding(...)`. |

The engine permits only `default`, `discovery`, `safe`, `version`, and `vuln` categories. The `vuln` category in LightScan still means **non-destructive detection only**; `exploit`, `dos`, `brute`, `fuzzer`, `intrusive`, and external-network categories are not accepted. This retains the useful selection vocabulary of NSE categories without exposing categories designed for higher-impact activity.[2]

## Lua API

Every check defines `metadata()` and `run(context)`.

```lua
function metadata()
  return {
    name = "example-header-check",
    description = "Reports a missing response header from the safe HEAD observation.",
    categories = {"safe", "vuln"},
    ports = {80, 443, 8080},
  }
end

function run(context)
  if context.protocol_hint ~= "http" then
    return {}
  end
  if not string.find(string.lower(context.headers or ""), "x%-frame%-options:") then
    return {
      lightscan.finding(
        "low",
        "HTTP response does not advertise X-Frame-Options.",
        {header = "X-Frame-Options", observation = "missing"}
      ),
    }
  end
  return {}
end
```

| Function or value | Contract |
| --- | --- |
| `metadata()` | Returns `name`, `description`, `categories`, and optional `ports`. The check name must be a lowercase identifier. |
| `run(context)` | Returns an array of zero or more findings. |
| `lightscan.finding(severity, detail, evidence)` | Creates a declarative finding. Allowed severities are `info`, `low`, `medium`, `high`, and `critical`. |
| `context.host`, `context.port` | Target identity and confirmed open port. |
| `context.banner` | First 512 characters of the read-only service observation. |
| `context.headers`, `context.body_preview` | Captured HTTP response components, populated only after the fixed safe HEAD request on recognized HTTP ports. |
| `context.protocol_hint` | `http` for recognized HTTP ports; otherwise `tcp`. |

Checks may use Lua’s basic string, table, and math operations. The runtime rejects source that references `dofile`, `load`, `loadfile`, `require`, `package`, `io`, `os`, `debug`, or `socket`, and does not expose those libraries to the check environment.

## Running checks

Built-in checks are listed without touching the network:

```bash
lightscan --list-lua-scripts
```

Run a specific check only after port discovery on an authorized scope:

```bash
lightscan --scan -t file:approved-targets.txt -p 80,443,8080 \
  --lua-script http-security-headers --lua-concurrency 10 \
  --format json --output reports
```

A reviewed custom directory can be supplied explicitly:

```bash
lightscan --scan -t 192.0.2.10 -p 443 \
  --lua-script-dir ./reviewed-lua-checks \
  --lua-script example-header-check
```

LightScan refuses to combine `--stream-open` with Lua checks because retention-free streaming intentionally discards the open-port list required to schedule service checks. Run enrichment as a separate pass from the retained discovery output.

## Review checklist

Treat every custom check as source code requiring review. Confirm that its category is permitted, its port rule is narrowly scoped, its result text is actionable, and its evidence contains no secrets. Although the runtime blocks ambient network and operating-system APIs, a check can still consume CPU until the enforced execution timeout, so avoid unbounded loops and exceptionally large tables.

## References

[1]: https://nmap.org/book/man-nse.html "Nmap Scripting Engine"
[2]: https://nmap.org/book/nse-usage.html "NSE Usage and Script Categories"
