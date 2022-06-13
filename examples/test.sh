#!/bin/sh

set -o errexit
set -o nounset

want=$(cat ./data.txt)
have=$(./test)

if test "$have" = "$want"; then
	exit 0
else
	printf "have:  \"%s\"\n" "$have"
	printf "want:  \"%s\"\n" "$want"
	exit 1
fi
