
EXECUTOR ?= $(OS)

.PHONY: install-deps
install-deps:
# this assumes the linux executor on CircleCI runs ubuntu/debian
ifneq (,$(filter $(EXECUTOR),debian linux))
	apt-get update
	apt-get install --no-install-recommends -y \
		build-essential ninja-build cmake \
		python3 python3-dev python3-setuptools
endif
ifeq ($(EXECUTOR), alpine)
	apk update
	apk add --no-cache \
		build-base ninja cmake \
		python3 python3-dev py3-setuptools
endif
