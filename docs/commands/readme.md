# Commands list #

### Runtime information gathering commands

`got-entries [symbol]` : print all GOT entries or only the [symbol] entry

`base-address` : print process base address

`binary-name` : file path of the process

`binary-name-local` : local file path of the binary 

---

### Hook GOT entries using breakpoints ###

`trace-bp --symbol fork` : trace fork calls and print function args using breakpoints

`trace-bp --trace-all` : trace @plt calls and print function args using breakpoints

`trace-bp --reset` : remove breakpoints that was setted with trace-bp

---

### Hook/instrument GOT entries using trampoline points ###

`hook-got` : old method used for doing GOT hooking, the command will be deprecated soon for now just use it for clearing GOT entries as `hook-got --reset-all`

`hook-got-inline` : read other docs

---

### Memory management ###

`hook-memory_mng` : manage shadow memory

`dump-all` : dump process memory and save it to `<tmp_folder>/dump_dir` folder

`mem-map` : allocate memory using mmap, then malloc if mmap call failed

`mem-unmap` : unallocate memory

---

### Save session (#TODO)

`store-state` : use serialization for saving current gdbleed session to `<tmp_folder>/state.bin`

`load-state` : load previous gdbleed session saved


