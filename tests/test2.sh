#!/bin/bash


if [ ! -f gdbleed.py ]; then
  echo "[x] error, launch the script in the repository folder ...quit"
  exit -1
fi


gdb -q -nx -x ./tests/gdb_scripts/test2.gdb /bin/bash

echo "# TEST-2 : test memory-related CLI commands [done]"

