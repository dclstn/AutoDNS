# AutoDNS

A DashLaunch plugin for an Xbox 360 running the BadAvatar / XeUnshackle
chain. It lets the console sit on Wi-Fi during boot without ever reaching
Xbox Live, then brings it online once the exploit has loaded.

## How it works

The console's stored network settings hold a dead DNS server, 10.255.255.1.
The dashboard that runs before the exploit has an address but cannot resolve
a single hostname, and Live logon is hostname based, so it stops at the
lookup. When DashLaunch loads the plugin it decrypts the stored settings with
`NetDll_XnpLoadConfigParams`, writes 1.1.1.1 and 8.8.8.8 into the DNS
fields, and applies them with `NetDll_XnpConfig`. That call changes the live
stack only. Storage keeps the dead DNS, so the next boot starts offline
again.

Per boot the plugin waits for an address, decrypts the stored settings,
swaps the DNS if it is the dead one, resolves `example.com` once as proof,
and re-reads storage to confirm the dead DNS is still there. It writes about
fifteen lines to `Usb:\AutoDNS.log` and nothing to the screen.

## Setup

On the console, once: System Settings, Network Settings, your network,
Configure Network, DNS Settings, Manual, `10.255.255.1` for both servers.
Leave IP settings on Automatic and the Wi-Fi network connected.

On the USB stick: copy `AutoDNS.xex` to the root and add it to `launch.ini`
ahead of anything that needs the network.

```ini
[Plugins]
plugin1 = Usb:\AutoDNS.xex
```

## Build

Needs the Xbox 360 XDK (2.0.21256) and nothing else. Point `XEDK` at the
SDK folder and run one of:

```bash
./build.sh
```

```bash
make
```

Both drive the XDK's own `cl.exe`, `link.exe` and `imagexex.exe` directly,
so Visual Studio is not required. Output is `build/Release/bin/AutoDNS.xex`.
The plain C runtime headers (`excpt.h`, `stdio.h`) are not in the XDK's
`include\xbox`; `build.sh` expects them in the SDK's
`TechPreview\Jul12Compiler\include\xbox` folder, or set `CRT_INC`.

## Knobs

At the top of `AutoDNS.cpp`: the dead DNS address, the two working DNS
servers, and the two timeouts. Nothing else should need editing.

## Two things to never do again

`NetDll_XnpSaveConfigParams` put the console into standby the first time it
ran. Querying or closing an `ExCreateThread(flags 0)` handle after that
thread had exited faulted inside the kernel. Both are absent from this code
on purpose.
