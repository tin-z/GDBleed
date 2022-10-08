
## TODO

 - Example of how to dump/restore memory of a process  
    * Might be usefull in case the kernel does not support write_process_memory and read_process_memory syscalls 

 - `proc_dump.py` python version

 - C version

```
# compile
gcc -no-pie -static proc_dump.c -o main

# usage
./main <pid> <offset> <length> [--ptrace]

```




