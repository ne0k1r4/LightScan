function metadata()
  return {
    name = "tcp-banner-inventory",
    description = "Records a non-empty TCP banner from the read-only observation context.",
    categories = {"default", "discovery", "safe"},
    ports = {},
  }
end

function run(context)
  local banner = context.banner or ""
  if banner == "" then
    return {}
  end
  return {
    lightscan.finding(
      "info",
      "Service returned a TCP banner for inventory review.",
      {banner = string.sub(banner, 1, 200), protocol_hint = context.protocol_hint}
    ),
  }
end
