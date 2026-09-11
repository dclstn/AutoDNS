# Xbox360AutoDNS

DashLaunch plugin for an Xbox 360 (RGH/JTAG) that enables a secure "Blind Boot" setup. The console boots on Wi-Fi 
with no way to reach Xbox Live during the initial exploit phase. Once loaded, AutoDNS safely brings the console 
online using Cloudflare's DNS, **now fully supporting both the Dashboard and Games/Apps**, while remaining compatible 
with local stealth plugins.

## Setup

1. Download `AutoDNS.xex`  
copy it to the root of the USB stick, and put it in `launch.ini` **ahead of** any local stealth or 
network-hooking plugin (e.g., `xbGuard`).

```ini
[Plugins]
plugin1 = Usb:\xbdm.xex
plugin2 = Usb:\AutoDNS.xex
plugin3 = Usb:\xbGuard.xex
plugin4 = Usb:\JRPC2.xex

Note: The order is crucial. AutoDNS must load first to wake up the Dashboard, then pause to let the stealth plugin arm 
its hooks before waking up the Games/Apps context.On the console, go to System Settings > Network Settings > your 
network > Configure Network > DNS Settings > Manual and set both servers to 192.0.2.1.

## How it works
The stored DNS server (192.0.2.1) is a documentation-only address (RFC 5737) that doesn't exist. Therefore, the dashboard 
that runs before the exploit loads can't resolve a single Live hostname, preventing any telemetry from leaking during boot.
After the exploit chain loads this plugin, it performs a two-phase injection:

Phase 1: It decrypts the stored network settings with XnpLoadConfigParams, swaps in working DNS servers (1.1.1.1 and 1.0.0.1),
 and applies them only to the SYSAPP context. This allows the Dashboard to authenticate and log into Xbox Live.

Phase 2: The plugin intentionally pauses (Sleep) for a few seconds. This gives subsequent DashLaunch plugins (like xbGuard) 
time to load and hook the xam.xex network stack.

Phase 3: It applies the working DNS to the TITLE context.
Because of this delay, games and applications (YouTube, Netflix, multiplayer) can now reach the internet, but their DNS 
requests are safely intercepted and filtered by the already-active stealth plugin.XnpConfig only touches the live memory 
stack, never the NAND storage. The storage still holds the dead server, so the next boot starts offline again automatically.

## Build
You need the Xbox 360 XDK. Point XEDK at the SDK folder and run ./build.sh. The result is build/AutoDNS.xex.
