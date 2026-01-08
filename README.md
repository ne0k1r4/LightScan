# lightscan

async TCP port scanner — pure stdlib, no dependencies

## usage

```
lightscan -t 192.168.1.1 -p 22,80,443
lightscan -t 192.168.1.1 -p top20
lightscan -t 192.168.1.1 -p 1-1024 -c 256
```

very early version, just tcp connect scan for now
