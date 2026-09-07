# AutoDNS

DashLaunch plugin for an Xbox 360 on BadAvatar or XeUnshackle. The console
boots on Wi-Fi with no way to reach Xbox Live during the exploit. Once
loaded, AutoDNS puts it online with Cloudflare's DNS.

## First-time setup

On the console, go to System Settings > Network Settings > your network >
Configure Network > DNS Settings > Manual and set both servers to
`192.0.2.1` [RFC 5737](https://www.rfc-editor.org/info/rfc5737/).

## Setup

Build `AutoDNS.xex` (see below), copy it to the root of the USB stick, and
put it in `launch.ini` ahead of any plugin that needs the network.

```ini
[Plugins]
plugin1 = Usb:\xbdm.xex
plugin2 = Usb:\AutoDNS.xex
plugin3 = Usb:\xbGuard.xex
plugin4 = Usb:\JRPC2.xex
```

## How it works

The stored DNS server doesn't exist, so the dashboard that runs before the
exploit can't resolve a single Live hostname. After boot, AutoDNS decrypts
the stored network settings with `XnpLoadConfigParams`, swaps in
1.1.1.1 and 1.0.0.1, and applies them with `XnpConfig`. `XnpConfig` only
touches the live stack, never storage, so the next boot starts offline
again.

## Build

You need the Xbox 360 XDK. Point `XEDK` at the SDK folder and run
`./build.sh` or `make`. The result is `build/Release/bin/AutoDNS.xex`.
