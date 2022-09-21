#!/bin/sh

set -o errexit
set -o nounset

while IFS= read -r test_directory
do
  echo "---- Running $test_directory" 1>&2
  TEMPORARY_DIRECTORY="$(mktemp -d)"
  pwd="$PWD"
  cd "$test_directory"
  TEMPORARY_DIRECTORY="$TEMPORARY_DIRECTORY" ./test.sh \
    && EXIT_CODE="$?" || EXIT_CODE="$?"
  cd "$pwd"
  rm -rf "$TEMPORARY_DIRECTORY"

  if [ "$EXIT_CODE" = "0" ]
  then
    echo "\033[33;32m✓ PASS\x1b[0m $test_directory" 1>&2
  else
    echo "\033[33;31m× FAIL\x1b[0m $test_directory" 1>&2
    exit "$EXIT_CODE"
  fi
done < test.list
