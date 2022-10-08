
source ./tests/gdbinit-gef.py
start
source gdbleed.py


# dump memory
dump-all

# map memory
info proc mappings
mem-map 0
mem-map 0x40000 0x2000
info proc mappings

# unmap memory
mem-unmap 0x40000 0x2000
info proc mappings

quit
