
ifndef OS

ifeq ($(shell uname), Linux)
OS = linux
else ifeq ($(shell uname), Darwin)
OS = macos
else ifeq ($(shell uname -o), Msys)
OS = windows
endif

endif

export OS
