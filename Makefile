include vendor/vendorpull/targets.mk

all: vendor compile patch check

.PHONY: lief
lief: dist/lief

dist/lief: BUILD_OPTS ?=
ifeq ($(OS), linux)
dist/lief: BUILD_OPTS += --ninja
endif
dist/lief:
	cd vendor/lief && python3 ./setup.py $(BUILD_OPTS) build_ext -b ../../$@ -j $(shell nproc)


.PHONY: check
check:
	$(MAKE) -C examples/
