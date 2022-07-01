include vendor/vendorpull/targets.mk

include build/system.mk
include build/deps.mk

all: vendor compile patch check

.PHONY: lief
lief: dist/lief

dist/lief: JOBS ?= $(shell nproc)
# disable android formats
dist/lief: BUILD_OPTS ?= --ninja --lief-no-android
dist/lief:
	cd vendor/lief && python3 ./setup.py $(BUILD_OPTS) build_ext -b ../../$@ -j $(JOBS)


.PHONY: check
check:
	$(MAKE) -C examples/
