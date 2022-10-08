#!/bin/bash


if [ ! -f gdbleed.py ]; then
  echo "[x] error, launch the script in the repository folder ...quit"
  exit -1
fi


gdb -q -nx -x ./tests/gdb_scripts/test3.gdb /bin/bash

echo "# TEST-3 : test simple hooking, we hook fork method and instead execute the sleep method [done]"

