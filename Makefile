# ================================================================
# AutoDNS.xex - Makefile build (no Visual Studio required)
#
# Drives the XDK's own cl.exe / link.exe / imagexex.exe directly, the same
# way ClementDreptin's Hayzen and xdk-docker do. Needs:
#   - XEDK   environment variable pointing at the Xbox 360 SDK folder
#            (the one containing bin/win32, include/xbox, lib/xbox)
#   - make, find, mkdir  (Git Bash / MSYS on Windows, or any Linux)
#   - wine   only when building on Linux (set WINDOWS_SHIM=wine)
#
# Usage:
#   make                      # Release build -> build/Release/bin/AutoDNS.xex
#   make CONFIG=Debug
#   make WINDOWS_SHIM=wine    # Linux / xdk-docker
#   make retail XEXTOOL=/path/to/xextool.exe   # optional retail conversion
#   make clean
# ================================================================

PROJECT_NAME := AutoDNS
WINDOWS_SHIM ?=
CONFIG ?= Release
XEXTOOL ?=

BUILD_DIR := build
OUT_DIR := $(BUILD_DIR)/$(CONFIG)/bin
INT_DIR := $(BUILD_DIR)/$(CONFIG)/obj

TARGET := $(OUT_DIR)/$(PROJECT_NAME).xex
IMAGEXEX_CONFIG := $(PROJECT_NAME).xex.xml

SRCS := $(PROJECT_NAME).cpp
OBJS := $(SRCS:%.cpp=$(INT_DIR)/%.obj)


# ================================================================
# XDK toolchain
# ================================================================

ifeq ($(XEDK),)
$(error XEDK is not set - point it at your Xbox 360 SDK folder)
endif

XDK_BIN_DIR := $(XEDK)/bin/win32
XDK_INC_DIR := "$(XEDK)/include/xbox"
XDK_LIB_DIR := "$(XEDK)/lib/xbox"

CXX := "$(XDK_BIN_DIR)/cl.exe"
LD := "$(XDK_BIN_DIR)/link.exe"
IMAGEXEX := "$(XDK_BIN_DIR)/imagexex.exe"


# ================================================================
# Flags (from Hayzen's Makefile, minus PCH and XexUtils)
# ================================================================

CXX_FLAGS := -c -Zi -nologo -W4 -MP -MT -D _XBOX -Gm- -EHsc -GS \
			 -fp:fast -fp:except- -Zc:wchar_t -Zc:forScope -GR- -openmp- \
			 -Fd"$(INT_DIR)/vc100.pdb" -TP \
			 -FI"$(XDK_INC_DIR)/xbox_intellisense_platform.h"

# -DLL + _DllMainCRTStartup is what makes this a plugin module rather than
# a title; -XEX:NO leaves the XEX step to imagexex below.
LD_FLAGS := -ERRORREPORT:QUEUE -NOLOGO -MANIFESTUAC:"level='asInvoker' uiAccess='false'" \
			-DEBUG -PDB:"$(OUT_DIR)/$(PROJECT_NAME).pdb" -STACK:"262144","262144" -TLBID:1 \
			-RELEASE -IMPLIB:"$(OUT_DIR)/$(PROJECT_NAME).lib" -XEX:NO -ALIGN:128,4096 \
			-DLL -ENTRY:"_DllMainCRTStartup"

LIBS := xboxkrnl.lib xapilib.lib

IMAGEXEX_FLAGS := -nologo -config:"$(IMAGEXEX_CONFIG)"

ifeq ($(CONFIG),Debug)
	CXX_FLAGS += -WX- -Od -D _DEBUG -Gy- -GF-
else ifeq ($(CONFIG),Release)
	CXX_FLAGS += -WX -Ox -Oi -Os -D NDEBUG -Gy -GF
	LD_FLAGS += -OPT:REF
else
	$(error Unknown CONFIG=$(CONFIG))
endif


# ================================================================
# Targets
# ================================================================

all: $(TARGET)

$(TARGET): $(OUT_DIR)/$(PROJECT_NAME).exe $(IMAGEXEX_CONFIG)
	@echo "Creating $@..."
	@mkdir -p $(@D)
	@$(WINDOWS_SHIM) $(IMAGEXEX) $(IMAGEXEX_FLAGS) -out:"$@" "$<"

$(OUT_DIR)/$(PROJECT_NAME).exe: $(OBJS)
	@echo "Linking $@..."
	@mkdir -p $(@D)
	@LIB=$(XDK_LIB_DIR) $(WINDOWS_SHIM) $(LD) $(LD_FLAGS) -OUT:"$@" $^ $(LIBS)

$(INT_DIR)/%.obj: %.cpp
	@mkdir -p $(@D)
	@INCLUDE=$(XDK_INC_DIR) $(WINDOWS_SHIM) $(CXX) $(CXX_FLAGS) -Fo"$@" $<

# Optional: the same retail conversion XeUnshackle applies to its payload.
# Hayzen ships without it and loads fine post-exploit, so try the plain
# build first and only reach for this if DashLaunch refuses the module.
retail: $(TARGET)
ifeq ($(XEXTOOL),)
	$(error XEXTOOL is not set - pass XEXTOOL=/path/to/xextool.exe)
endif
	@echo "Converting $(TARGET) with xextool..."
	@$(WINDOWS_SHIM) "$(XEXTOOL)" -m r -r a -o "$(OUT_DIR)/$(PROJECT_NAME).retail.xex" "$(TARGET)"

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all retail clean
