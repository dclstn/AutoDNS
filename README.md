# AutoDNS

DashLaunch plugin for Xbox 360 consoles on BadAvatar / XeUnshackle. The
console boots on Wi-Fi but can't reach Xbox Live; once the exploit has
loaded, AutoDNS brings it online.

## First-time setup

On the console: System Settings > Network Settings > your network >
Configure Network > DNS Settings > Manual. Set both servers to
`10.255.255.1`. Leave IP on Automatic and stay connected to Wi-Fi.

## Setup

Copy `dist/AutoDNS.xex` to the root of the USB stick and add it to
`launch.ini` before any plugin that needs the network:

```ini
[Plugins]
plugin1 = Usb:\AutoDNS.xex
```

## How it works

Stored DNS is dead, so the pre-exploit dashboard can't resolve any Live
hostname. After boot, AutoDNS decrypts the stored network settings
(`XnpLoadConfigParams`), swaps the DNS servers for 1.1.1.1 / 8.8.8.8, and
applies them live (`XnpConfig`). That change is never persisted, so every
boot starts offline again. Log: `Usb:\AutoDNS.log`.

## Build

Requires the Xbox 360 XDK. Set `XEDK` to the SDK folder, then `./build.sh`
or `make`. Output: `build/Release/bin/AutoDNS.xex`.
