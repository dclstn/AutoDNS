#!/usr/bin/env bash
# Builds AutoDNS.xex with the Xbox 360 XDK's own compiler. No Visual Studio.
set -e
cd "$(dirname "$0")"

XEDK="${XEDK:-/c/XDK21256/XDK}"
[ -f "$XEDK/bin/win32/cl.exe" ] || XEDK=/c/XDK21256/XDK   # the XDK installer sets XEDK to a tools-only install
CRT="${CRT_INC:-/c/XDK21256/TP/XDK/TechPreview/Jul12Compiler/include/xbox}"   # plain C headers the XDK keeps here
BIN="$XEDK/bin/win32"
INC="$(cygpath -w "$XEDK/include/xbox")"

mkdir -p build

INCLUDE="$INC;$(cygpath -w "$CRT")" "$BIN/cl.exe" -nologo -c -W4 -WX -Ox -MT -GR- -EHsc -TP \
    -D _XBOX -D NDEBUG -FI"$INC\\xbox_intellisense_platform.h" -Fobuild/AutoDNS.obj AutoDNS.cpp

LIB="$(cygpath -w "$XEDK/lib/xbox")" "$BIN/link.exe" -nologo -RELEASE -OPT:REF -DLL -ENTRY:_DllMainCRTStartup \
    -XEX:NO -ALIGN:128,4096 -OUT:build/AutoDNS.exe build/AutoDNS.obj xboxkrnl.lib xapilib.lib

"$BIN/imagexex.exe" -nologo -config:AutoDNS.xex.xml -out:build/AutoDNS.xex build/AutoDNS.exe
echo build/AutoDNS.xex
