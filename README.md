# Xbox360AutoDNS

DashLaunch plugin for an Xbox 360 on BadAvatar or XeUnshackle. The console
boots on Wi-Fi with no way to reach Xbox Live during the exploit. Once
loaded, AutoDNS puts it online using Cloudflare's DNS.

## Setup

1. Download `AutoDNS.xex` from the
[latest release](https://github.com/dclstn/Xbox360AutoDNS/releases/latest),
copy it to the root of the USB stick, and put it in `launch.ini` ahead of any
plugin that needs the network.

```ini
[Plugins]
plugin1 = Usb:\xbdm.xex
plugin2 = Usb:\AutoDNS.xex
plugin3 = Usb:\xbGuard.xex
plugin4 = Usb:\JRPC2.xex
```

2. On the console, go to System Settings > Network Settings > your network >
Configure Network > DNS Settings > Manual and set both servers to
`192.0.2.1`.

## How it works

The stored DNS server doesn't exist ([RFC 5737](https://www.rfc-editor.org/info/rfc5737/)),
so the dashboard that runs before the exploit can't resolve a single Live
hostname. After boot, AutoDNS decrypts the stored network settings with
`XnpLoadConfigParams`, swaps in 1.1.1.1 and 1.0.0.1, and applies them with
`XnpConfig`. `XnpConfig` only touches the live stack, never storage, so the
next boot starts offline again.

## Build

You need the Xbox 360 XDK. Point `XEDK` at the SDK folder and run
`./build.sh`. The result is `build/AutoDNS.xex`.
