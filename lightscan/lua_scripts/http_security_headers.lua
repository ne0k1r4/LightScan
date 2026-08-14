function metadata()
  return {
    name = "http-security-headers",
    description = "Reports missing baseline HTTP response headers from a safe HEAD observation.",
    categories = {"safe", "vuln"},
    ports = {80, 443, 8000, 8080, 8081, 8443, 8888},
  }
end

function run(context)
  if context.protocol_hint ~= "http" then
    return {}
  end
  local headers = string.lower(context.headers or "")
  if headers == "" then
    return {}
  end

  local findings = {}
  if not string.find(headers, "x%-content%-type%-options:") then
    findings[#findings + 1] = lightscan.finding(
      "low",
      "HTTP response does not advertise X-Content-Type-Options.",
      {header = "X-Content-Type-Options", observation = "missing"}
    )
  end
  if not string.find(headers, "content%-security%-policy:") then
    findings[#findings + 1] = lightscan.finding(
      "low",
      "HTTP response does not advertise Content-Security-Policy.",
      {header = "Content-Security-Policy", observation = "missing"}
    )
  end
  return findings
end
