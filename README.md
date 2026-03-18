# nanoDNS for Playstation

- Playstation network DNS server set to 127.0.0.1 (Loopback)
- Web configure settings and rules (http://PS_IP:8080)
<img width="2823" height="1698" alt="image" src="https://github.com/user-attachments/assets/edbb5137-2b2e-449f-b7e0-15966257de01" />

# Minimal Playstaiton payload DNS proxy that:

- listens on all local IPv4 addresses on port `53`
- applies local IPv4 overrides for domains matching shell-style masks
- forwards all other DNS queries to upstream resolvers from `/data/nanodns/nanodns.ini`
- stores runtime files under `/data/nanodns`
- writes DNS queries and responses to a log file
- can additionally mirror logs to `stdout`/`klog` when `debug=1`
- supports an exceptions block to bypass local overrides for selected domains

## Build

```sh
# Install PS4 or PS5 SDK before make
make PS_HOST=ps4
make PS_HOST=ps5
```

## Config

At startup the payload uses the directory `/data/nanodns`.
The config file path is `/data/nanodns/nanodns.ini`.
If the file does not exist, it creates one with defaults:

```ini
[general]
log=/data/nanodns/nanodns.log
debug=0

[upstream]
server=1.1.1.1
server=8.8.8.8
server=77.77.88.88
timeout_ms=1500

[overrides]
*playstation*=0.0.0.0
*sonyentertainmentnetwork*=0.0.0.0
*ribob01*=0.0.0.0
*akamai*=0.0.0.0
*youtube*=0.0.0.0
*ggpht*=0.0.0.0
*googlevideo*=0.0.0.0
*yt.be*=0.0.0.0
*ytimg.com*=0.0.0.0
*yt3.googleusercontent.com*=0.0.0.0
# *.example.com=192.168.0.10
# exact.host.local=10.0.0.42

[exceptions]
feature.api.playstation.com
*.stun.playstation.net
stun.*.playstation.net
ena.net.playstation.net
post.net.playstation.net
gst.prod.dl.playstation.net
# auth.api.playstation.net
# *.allowed.playstation.net
```

Override masks use shell-style matching via `fnmatch(3)`, for example:

- `*.example.com`
- `api??.test.local`
- `exact.host.local`

`debug=0` disables mirrored output to console and `klog`, but the file specified by
`log=` still receives all requests and responses.

Entries in `[exceptions]` are also shell-style masks, one per line. If a query
matches an exception, it is forwarded to upstream DNS and bypasses all local
override rules.
