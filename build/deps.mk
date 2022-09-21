
EXECUTOR ?= $(OS)

.PHONY: install-deps
install-deps:
ifneq (,$(filter $(EXECUTOR),linux))
	sudo apt-get update
	sudo apt-get install --no-install-recommends -y \
		build-essential ninja-build cmake \
		python3 python3-dev python3-setuptools
endif
ifeq ($(EXECUTOR), macos)
	brew install cmake
endif
