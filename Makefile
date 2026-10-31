.DEFAULT_GOAL := all
PROJ_ROOT := $(shell pwd)
BUILD_DIR := $(PROJ_ROOT)/build
NATIVE ?= 1
DIAGNOSTIC_STAGE ?= 0
P256_DIAGNOSTIC ?= 0
NATIVE_SAE_EXPERIMENTAL ?= 0
NATIVE_PMF_PROBE ?= 0
ifeq ($(NATIVE_PMF_PROBE),1)
ifneq ($(NATIVE_SAE_EXPERIMENTAL),1)
$(error PMF probe requires NATIVE_SAE_EXPERIMENTAL=1)
endif
else
ifneq ($(NATIVE_PMF_PROBE),0)
$(error NATIVE_PMF_PROBE must be 0 or 1)
endif
endif
ifeq ($(NATIVE_SAE_EXPERIMENTAL),1)
ifneq ($(NATIVE),1)
$(error experimental SAE requires NATIVE=1)
endif
ifneq ($(DIAGNOSTIC_STAGE),0)
$(error experimental SAE requires normal DIAGNOSTIC_STAGE=0)
endif
else
ifneq ($(NATIVE_SAE_EXPERIMENTAL),0)
$(error NATIVE_SAE_EXPERIMENTAL must be 0 or 1)
endif
endif
ifeq ($(P256_DIAGNOSTIC),1)
ifneq ($(NATIVE),1)
$(error P256_DIAGNOSTIC requires NATIVE=1)
endif
ifneq ($(DIAGNOSTIC_STAGE),4)
$(error P256_DIAGNOSTIC requires DIAGNOSTIC_STAGE=4)
endif
else
ifneq ($(P256_DIAGNOSTIC),0)
$(error P256_DIAGNOSTIC must be 0 or 1)
endif
ifeq ($(DIAGNOSTIC_STAGE),4)
$(error DIAGNOSTIC_STAGE=4 requires P256_DIAGNOSTIC=1)
endif
endif
ifeq ($(NATIVE),1)
BUILD_DIR := $(PROJ_ROOT)/build/native
endif
OUT_DIR   := $(BUILD_DIR)/out
OUT_KEXT  := $(OUT_DIR)/Ath10kMac.kext
OUT_BIN   := $(OUT_KEXT)/Contents/MacOS/Ath10kMac

SDK   = $(shell xcrun --show-sdk-path)
PYTHON ?= python3
MKSDK := $(PROJ_ROOT)/vendor/MacKernelSDK
ARCH  := -arch x86_64
MINOS := -mmacosx-version-min=11.0
CC    := xcrun clang
CXX   := xcrun clang++
LD    := xcrun clang++

HT_VHT ?= 1
MAX_WIDTH ?= 80
MAX_NSS ?= 2
TX_SLOTS ?= 64
AMPDU_LIMIT ?= 64
AMSDU_LIMIT ?= 3
OPT ?= -O2
PAYLOAD_CACHE ?= 1
RUNTIME_IRQ ?= 1
RX_BATCH ?= 1
RX_RESERVE ?= 1
DIAGNOSTICS ?= 0
KFLAGS = -MMD -MP -DATH10K_P256_DIAGNOSTIC=$(P256_DIAGNOSTIC) -DATH10K_DIAGNOSTICS=$(DIAGNOSTICS) -fstack-usage -Wframe-larger-than=4096 -Werror=frame-larger-than $(OPT) -DATH10K_PAYLOAD_CACHE=$(PAYLOAD_CACHE) -DATH10K_RUNTIME_IRQ=$(RUNTIME_IRQ) -DATH10K_RX_BATCH=$(RX_BATCH) -DATH10K_RX_RESERVE=$(RX_RESERVE) -DATH10K_MAX_WIDTH=$(MAX_WIDTH) -DATH10K_MAX_NSS=$(MAX_NSS) -DATH10K_AMPDU_LIMIT=$(AMPDU_LIMIT) -DATH10K_AMSDU_LIMIT=$(AMSDU_LIMIT) -DATH10K_HT_VHT=$(HT_VHT) -DATH10K_DATA_TX_SLOTS=$(TX_SLOTS) -fno-stack-check -fno-stack-protector -mkernel $(ARCH) $(MINOS) \
          -isysroot $(SDK) \
          -I$(MKSDK)/Headers \
          -I$(SDK)/System/Library/Frameworks/Kernel.framework/Headers

CXXFLAGS = $(KFLAGS) -fapple-kext -fno-exceptions -fno-rtti -std=c++17 \
            -DKERNEL -Wno-deprecated-declarations -Wno-nullability-completeness

LDFLAGS = $(ARCH) -static -nostdlib -Xlinker -kext \
           $(MKSDK)/Library/x86_64/libkmod.a \
           $(MKSDK)/Library/universal/libkmodc++.a \
           -F$(SDK)/System/Library/Frameworks

ifeq ($(NATIVE),1)
CXXFLAGS += -DATH10K_NATIVE=1 -I$(PROJ_ROOT)/build/generated/itlwm
NATIVE_OBJECT := $(BUILD_DIR)/Ath10kNative.o $(BUILD_DIR)/Ath10kSAEWorker.o $(BUILD_DIR)/Ath10kSAESession.o $(BUILD_DIR)/Ath10kNativeSAEPreparation.o $(BUILD_DIR)/Ath10kNativePSKPreparation.o $(BUILD_DIR)/Ath10kNativeOWEJob.o $(BUILD_DIR)/Ath10kNativeSAEKernelBackend.o $(BUILD_DIR)/Ath10kP256CheckJob.o $(BUILD_DIR)/Ath10kPMFSession.o
endif

ifeq ($(P256_DIAGNOSTIC),1)
# Standalone registry diagnostic: no controller, networking, firmware or DMA code.
OBJS := $(BUILD_DIR)/Ath10kSAEWorker.o $(BUILD_DIR)/Ath10kP256CheckJob.o $(BUILD_DIR)/Ath10kP256RegistryJob.o $(BUILD_DIR)/Ath10kP256DiagnosticService.o $(BUILD_DIR)/kmod_info.o
else
OBJS := $(NATIVE_OBJECT) $(BUILD_DIR)/Ath10kUserClient.o $(BUILD_DIR)/Ath10kNetwork.o $(BUILD_DIR)/Ath10kRuntime.o $(BUILD_DIR)/Ath10kPower.o $(BUILD_DIR)/Ath10kPowerNotifications.o $(BUILD_DIR)/Ath10kRecovery.o $(BUILD_DIR)/Ath10kPCIDevice.o $(BUILD_DIR)/kmod_info.o
endif
$(OBJS): $(wildcard src/security/*.hpp)
ifeq ($(NATIVE),1)
$(OBJS): $(wildcard src/macos/native/*)
endif

$(BUILD_DIR)/Ath10kNative.o: src/macos/native/Ath10kNative.cpp $(wildcard src/macos/native/*) $(wildcard src/core/*.hpp src/macos/controller/*.hpp src/macos/abi/*.hpp) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/Ath10kSAEWorker.o: src/macos/native/Ath10kSAEWorker.cpp src/macos/native/Ath10kSAEWorker.hpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/Ath10kSAESession.o: src/macos/native/Ath10kSAESession.cpp src/macos/native/Ath10kSAESession.hpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/Ath10kNativeSAEPreparation.o: src/macos/native/Ath10kNativeSAEPreparation.cpp src/macos/native/Ath10kNativeSAEPreparation.hpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/Ath10kNativeOWEJob.o: src/macos/native/Ath10kNativeOWEJob.cpp src/macos/native/Ath10kNativeOWEJob.hpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/Ath10kNativePSKPreparation.o: src/macos/native/Ath10kNativePSKPreparation.cpp src/macos/native/Ath10kNativePSKPreparation.hpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/Ath10kNativeSAEKernelBackend.o: src/macos/native/Ath10kNativeSAEKernelBackend.cpp src/macos/native/Ath10kNativeSAEKernelBackend.hpp src/macos/native/Ath10kP256KernelBinding.hpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/Ath10kP256CheckJob.o: src/macos/native/Ath10kP256CheckJob.cpp src/macos/native/Ath10kP256CheckJob.hpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/Ath10kP256RegistryJob.o: src/macos/native/Ath10kP256RegistryJob.cpp src/macos/native/Ath10kP256RegistryJob.hpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/Ath10kP256DiagnosticService.o: src/macos/native/Ath10kP256DiagnosticService.cpp src/macos/native/Ath10kP256RegistryJob.hpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/Ath10kPMFSession.o: src/macos/native/Ath10kPMFSession.cpp src/macos/native/Ath10kPMFSession.hpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

.PHONY: all kext clean check-sdk prepare-firmware
all: kext
kext: check-sdk $(OUT_BIN)
	$(PYTHON) scripts/validation/check-kext-symbols.py "$(OUT_BIN)"
	@echo "Built and symbol-checked: $(OUT_KEXT)"

# Always validate source containers, even when a generated header exists.
# The header dependency serializes preparation before compiling with make -j.
prepare-firmware:
	$(PYTHON) scripts/build/prepare-firmware.py

src/core/Ath10kPayload.hpp: prepare-firmware
	@test -f "$@"

check-sdk:
	@test -f "$(MKSDK)/Library/x86_64/libkmod.a" || \
	  (echo "ERROR: MacKernelSDK missing. Run: git submodule update --init --recursive"; exit 1)

$(BUILD_DIR):
	@mkdir -p $@

$(BUILD_DIR)/Ath10kPCIDevice.o: src/macos/controller/Ath10kPCIDevice.cpp src/macos/controller/Ath10kPCIDevice.hpp src/core/Ath10kHw.hpp src/core/Ath10kRegisterIO.hpp src/core/Ath10kTarget.hpp src/core/Ath10kCE.hpp src/core/Ath10kCERing.hpp src/core/Ath10kDMA.hpp src/core/Ath10kBMI.hpp src/core/Ath10kPLL.hpp src/core/Ath10kBoot.hpp src/core/Ath10kHTC.hpp src/core/Ath10kWMI.hpp src/core/Ath10kRxSetup.hpp src/core/Ath10kScanPlan.hpp src/core/Ath10kRegulatory.hpp src/core/Ath10kRegulatoryData.hpp src/core/Ath10kBSS.hpp src/core/Ath10kConnection.hpp src/core/Ath10kRX.hpp src/core/Ath10kPerformance.hpp src/core/Ath10kRXRate.hpp src/core/Ath10kPayload.hpp src/core/Ath10kPayloadProfile.hpp src/core/Ath10kInPlace.hpp src/macos/controller/Ath10kPower.hpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/Ath10kNetwork.o: src/macos/controller/Ath10kNetwork.cpp $(wildcard src/core/*.hpp src/macos/controller/*.hpp src/macos/abi/*.hpp src/security/*.hpp) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/Ath10kRuntime.o: src/macos/controller/Ath10kRuntime.cpp $(wildcard src/core/*.hpp src/macos/controller/*.hpp src/macos/abi/*.hpp src/security/*.hpp) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/Ath10kRecovery.o: src/macos/controller/Ath10kRecovery.cpp $(wildcard src/core/*.hpp src/macos/controller/*.hpp src/macos/abi/*.hpp src/security/*.hpp) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/Ath10kPower.o: src/macos/controller/Ath10kPower.cpp $(wildcard src/core/*.hpp src/macos/controller/*.hpp src/macos/abi/*.hpp src/security/*.hpp) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/Ath10kPowerNotifications.o: src/macos/controller/Ath10kPowerNotifications.cpp $(wildcard src/core/*.hpp src/macos/controller/*.hpp src/macos/abi/*.hpp src/security/*.hpp) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/Ath10kUserClient.o: src/macos/controller/Ath10kUserClient.cpp $(wildcard src/core/*.hpp src/macos/controller/*.hpp src/macos/abi/*.hpp src/security/*.hpp) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/kmod_info.o: src/macos/controller/kmod_info.c | $(BUILD_DIR)
	$(CC) $(KFLAGS) -c $< -o $@

# Rebuild all objects when experiment flags change, even without make clean.
.PHONY: FORCE
FORCE:
$(BUILD_DIR)/experiment-config: FORCE | $(BUILD_DIR)
	@printf '%s\n' 'NATIVE_PMF_PROBE=$(NATIVE_PMF_PROBE) NATIVE_SAE_EXPERIMENTAL=$(NATIVE_SAE_EXPERIMENTAL) P256_DIAGNOSTIC=$(P256_DIAGNOSTIC) DIAGNOSTIC_STAGE=$(DIAGNOSTIC_STAGE) DIAGNOSTICS=$(DIAGNOSTICS) OPT=$(OPT) PAYLOAD_CACHE=$(PAYLOAD_CACHE) RUNTIME_IRQ=$(RUNTIME_IRQ) RX_BATCH=$(RX_BATCH) RX_RESERVE=$(RX_RESERVE) HT_VHT=$(HT_VHT) MAX_WIDTH=$(MAX_WIDTH) MAX_NSS=$(MAX_NSS) TX_SLOTS=$(TX_SLOTS) AMPDU_LIMIT=$(AMPDU_LIMIT) AMSDU_LIMIT=$(AMSDU_LIMIT)' > "$@.tmp"
	@cmp -s "$@.tmp" "$@" || cp "$@.tmp" "$@"
	@rm -f "$@.tmp"

$(OBJS): Makefile $(BUILD_DIR)/experiment-config
$(OBJS): src/core/Ath10kMulticast.hpp src/core/Ath10kConnection.hpp src/core/Ath10kControl.hpp
$(OBJS): src/core/Ath10kRuntimePower.hpp src/core/Ath10kFirmwareStats.hpp
$(OBJS): $(wildcard src/security/*.hpp)

.PHONY: test-development native-preflight
test-development:
	$(PYTHON) tests/run-development-tests.py

native-preflight:
	$(PYTHON) scripts/diagnostics/collect-native-preflight.py

$(OUT_BIN): Makefile $(OBJS) packaging/Ath10kMac.kext/Contents/Info.plist scripts/build/prepare-kext-info.py
	@mkdir -p "$(OUT_KEXT)/Contents/MacOS"
	$(PYTHON) scripts/build/prepare-kext-info.py $(NATIVE) "$(OUT_KEXT)/Contents/Info.plist" --diagnostic-stage $(DIAGNOSTIC_STAGE) $(if $(filter 1,$(P256_DIAGNOSTIC)),--p256-diagnostic,) $(if $(filter 1,$(NATIVE_SAE_EXPERIMENTAL)),--native-sae-experimental,) $(if $(filter 1,$(NATIVE_PMF_PROBE)),--native-pmf-probe,)
	$(LD) $(LDFLAGS) -o $@ $(OBJS)

clean:
	rm -rf $(BUILD_DIR)

ifeq ($(NATIVE),1)
$(OBJS): $(wildcard src/macos/native/*)
endif

$(OBJS): src/macos/controller/Ath10kDiagnostics.hpp

# Follow actual transitive project/vendor includes, including ABI-only changes.
-include $(OBJS:.o=.d)

# Offline symbol availability probe only. It is not part of the driver bundle,
# has no IOKit personality, never calls crypto, and refuses module start/stop.
CRYPTO_PROBE_DIR := $(PROJ_ROOT)/build/sae-crypto-link-probe
CRYPTO_PROBE_KEXT := $(CRYPTO_PROBE_DIR)/Ath10kCryptoLinkProbe.kext
CRYPTO_PROBE_BIN := $(CRYPTO_PROBE_KEXT)/Contents/MacOS/Ath10kCryptoLinkProbe
.PHONY: sae-crypto-link-probe
sae-crypto-link-probe: check-sdk $(CRYPTO_PROBE_BIN)
	$(PYTHON) scripts/validation/check-kext-symbols.py "$(CRYPTO_PROBE_BIN)"

$(CRYPTO_PROBE_DIR):
	@mkdir -p $@

$(CRYPTO_PROBE_DIR)/probe.o: tools/sae/corecrypto-link-probe.c Makefile | $(CRYPTO_PROBE_DIR)
	$(CC) $(KFLAGS) -c $< -o $@

$(CRYPTO_PROBE_BIN): $(CRYPTO_PROBE_DIR)/probe.o tools/sae/CoreCryptoLinkProbe.plist
	@mkdir -p "$(CRYPTO_PROBE_KEXT)/Contents/MacOS"
	cp tools/sae/CoreCryptoLinkProbe.plist "$(CRYPTO_PROBE_KEXT)/Contents/Info.plist"
	$(LD) $(LDFLAGS) -o $@ $(CRYPTO_PROBE_DIR)/probe.o

-include $(CRYPTO_PROBE_DIR)/probe.d
-include $(CRYPTO_PROBE_DIR)/p256-kernel-compile.d

# Executes math tests in an ordinary macOS process, not in the kernel.
P256_CHECK_BIN := $(CRYPTO_PROBE_DIR)/p256-userland-check
.PHONY: sae-p256-userland-check sae-p256-kernel-compile
sae-p256-userland-check: $(P256_CHECK_BIN)
	$(P256_CHECK_BIN)

$(P256_CHECK_BIN): tools/sae/p256-userland-check.cpp src/security/Ath10kP256CoreCrypto.hpp src/security/Ath10kSAE.hpp src/security/Ath10kSAEWire.hpp src/security/Ath10kSAEExchange.hpp src/security/Ath10kSHA256.hpp src/security/Ath10kSecurity.hpp src/security/Ath10kRSN.hpp tests/fixtures/p256_corecrypto_fixtures.hpp Makefile | $(CRYPTO_PROBE_DIR)
	$(CXX) -std=c++17 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer $< -o $@

sae-p256-kernel-compile: $(CRYPTO_PROBE_DIR)/p256-kernel-compile.o
	$(PYTHON) scripts/validation/check-kext-symbols.py "$<"

$(CRYPTO_PROBE_DIR)/p256-kernel-compile.o: tools/sae/p256-kernel-compile.cpp src/security/Ath10kP256CoreCrypto.hpp src/security/Ath10kSecurity.hpp Makefile | $(CRYPTO_PROBE_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

-include $(CRYPTO_PROBE_DIR)/p256-kernel-compile.d

# Typed offline candidate: refuses module start; never part of the driver bundle.
TYPED_PROBE_KEXT := $(CRYPTO_PROBE_DIR)/Ath10kCryptoTypedProbe.kext
TYPED_PROBE_BIN := $(TYPED_PROBE_KEXT)/Contents/MacOS/Ath10kCryptoTypedProbe
.PHONY: sae-crypto-typed-link-probe
sae-crypto-typed-link-probe: check-sdk $(TYPED_PROBE_BIN)
	$(PYTHON) scripts/validation/check-kext-symbols.py "$(TYPED_PROBE_BIN)"

$(CRYPTO_PROBE_DIR)/typed-probe.o: tools/sae/corecrypto-typed-link-probe.cpp src/macos/native/Ath10kP256KernelBinding.hpp src/security/Ath10kP256BackendCheck.hpp src/security/Ath10kP256CoreCrypto.hpp Makefile | $(CRYPTO_PROBE_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TYPED_PROBE_BIN): $(CRYPTO_PROBE_DIR)/typed-probe.o tools/sae/CoreCryptoTypedProbe.plist
	@mkdir -p "$(TYPED_PROBE_KEXT)/Contents/MacOS"
	cp tools/sae/CoreCryptoTypedProbe.plist "$(TYPED_PROBE_KEXT)/Contents/Info.plist"
	$(LD) $(LDFLAGS) -o $@ $(CRYPTO_PROBE_DIR)/typed-probe.o

-include $(CRYPTO_PROBE_DIR)/typed-probe.d

.PHONY: prepare-native-headers
prepare-native-headers:
	$(PYTHON) scripts/build/prepare-native-headers.py
$(OBJS): | prepare-native-headers
