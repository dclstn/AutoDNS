#!/usr/bin/env bash
# AutoDNS.xex build for Git Bash on Windows - same steps as the Makefile,
# without needing `make`. Drives the XDK's cl.exe / link.exe / imagexex.exe.
#
#   ./build.sh            # Release -> build/Release/bin/AutoDNS.xex
#   CONFIG=Debug ./build.sh
#   XEXTOOL=/path/to/xextool.exe ./build.sh   # also emit AutoDNS.retail.xex
set -euo pipefail
cd "$(dirname "$0")"

XEDK="${XEDK:-/c/XDK21256/XDK}"
# The XDK installer sets a machine-wide XEDK that points at a tools-only
# install with no compiler. Fall back to the carved toolchain in that case.
[ -f "$XEDK/bin/win32/cl.exe" ] || XEDK=/c/XDK21256/XDK
CONFIG="${CONFIG:-Release}"
PROJECT="${PROJECT:-AutoDNS}"

BIN="$XEDK/bin/win32"
INC="$XEDK/include/xbox"
LIB="$XEDK/lib/xbox"
OUT="build/$CONFIG/bin"
INT="build/$CONFIG/obj"

# The XDK's include\xbox only carries the Xbox-specific headers; the plain
# C runtime headers (excpt.h, stdio.h, string.h, ...) normally come from
# VS2010's VC\include. Without VS2010, the XDK's own "Jul12 TechPreview"
# compiler folder has a full set, and works as a fallback searched *after*
# include\xbox so the real XDK headers win on any overlap.
CRT_INC="${CRT_INC:-/c/XDK21256/TP/XDK/TechPreview/Jul12Compiler/include/xbox}"

for f in "$BIN/cl.exe" "$BIN/link.exe" "$BIN/imagexex.exe" "$INC/xtl.h" "$LIB/xboxkrnl.lib" "$CRT_INC/excpt.h"; do
    [ -f "$f" ] || { echo "missing: $f"; exit 1; }
done
mkdir -p "$OUT" "$INT"

# Windows-style paths for the MSVC tools' INCLUDE / LIB environment.
INC_W="$(cygpath -w "$INC");$(cygpath -w "$CRT_INC")"
LIB_W="$(cygpath -w "$LIB")"

CXX_FLAGS=(-c -Zi -nologo -W4 -MT -D _XBOX -Gm- -EHsc -GS -fp:fast -fp:except-
           -Zc:wchar_t -Zc:forScope -GR- -openmp- -Fd"$INT/vc100.pdb" -TP
           -FI"$(cygpath -w "$INC")\\xbox_intellisense_platform.h")
LD_FLAGS=(-ERRORREPORT:QUEUE -NOLOGO -DEBUG -PDB:"$OUT/$PROJECT.pdb"
          -STACK:262144,262144 -TLBID:1 -RELEASE -IMPLIB:"$OUT/$PROJECT.lib"
          -XEX:NO -ALIGN:128,4096 -DLL -ENTRY:_DllMainCRTStartup)
case "$CONFIG" in
    Debug)   CXX_FLAGS+=(-WX- -Od -D _DEBUG -Gy- -GF-) ;;
    Release) CXX_FLAGS+=(-WX -Ox -Oi -Os -D NDEBUG -Gy -GF); LD_FLAGS+=(-OPT:REF) ;;
    *) echo "unknown CONFIG=$CONFIG"; exit 1 ;;
esac

echo "Compiling..."
INCLUDE="$INC_W" "$BIN/cl.exe" "${CXX_FLAGS[@]}" -Fo"$INT/$PROJECT.obj" "$PROJECT.cpp"

echo "Linking..."
LIB="$LIB_W" "$BIN/link.exe" "${LD_FLAGS[@]}" -OUT:"$OUT/$PROJECT.exe" "$INT/$PROJECT.obj" xboxkrnl.lib xapilib.lib

echo "Creating XEX..."
"$BIN/imagexex.exe" -nologo -config:"$PROJECT.xex.xml" -out:"$OUT/$PROJECT.xex" "$OUT/$PROJECT.exe"

if [ -n "${XEXTOOL:-}" ]; then
    echo "Retail conversion..."
    "$XEXTOOL" -m r -r a -o "$OUT/$PROJECT.retail.xex" "$OUT/$PROJECT.xex"
fi

echo "Done: $OUT/$PROJECT.xex"
ls -la "$OUT/$PROJECT.xex"
