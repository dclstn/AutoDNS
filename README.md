# AutoDNS

DashLaunch plugin for an Xbox 360 on BadAvatar or XeUnshackle. The console
boots on Wi-Fi with no way to reach Xbox Live. Once the exploit has loaded,
AutoDNS puts it online.

## First-time setup

On the console, go to System Settings > Network Settings > your network >
Configure Network > DNS Settings > Manual and set both servers to
`10.255.255.1`. Leave IP on Automatic and stay connected to Wi-Fi.

## Setup

Copy `dist/AutoDNS.xex` to the root of the USB stick. Put it in `launch.ini`
ahead of any plugin that needs the network.

```ini
[Plugins]
plugin1 = Usb:\AutoDNS.xex
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
