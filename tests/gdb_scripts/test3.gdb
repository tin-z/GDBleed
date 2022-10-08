
source ./tests/gdbinit-gef.py
start
source gdbleed.py

hook-got fork sleep 20
b sleep

c
# you will see that we reach the sleep breakpoint, and
# that if we didn't hook with sleep, then no sleep breakpoint would have been reached

quit
