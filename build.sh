#!/bin/sh

cd vendor/lief
python3 ./setup.py build -b ../../dist/lief $@
