
ifndef OS

ifeq ($(shell uname), Linux)
OS = linux
endif

ifeq ($(shell uname), Darwin)
OS = macos
endif

ifeq ($(shell uname -o), Msys)
OS = windows
endif

endif

export OS
