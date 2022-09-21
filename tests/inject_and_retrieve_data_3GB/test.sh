#!/bin/sh

set -o errexit
set -o nounset

bin="$TEMPORARY_DIRECTORY/a.out"
cc test.c -o "$bin"

input="$TEMPORARY_DIRECTORY/input.txt"
head -c 3221225472 /dev/urandom > "$input"

../../postject.py --overwrite "$bin" "foobar" "$input"

output="$TEMPORARY_DIRECTORY/output.txt"

"$bin" > "$output"

diff "$input" "$output"
