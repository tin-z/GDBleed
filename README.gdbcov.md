# GDBcov

[DEMO]

GDBcov - Hooking and instrumentation tool built on top of GDBleed

GDBcov is'an extension of GDBleed that permits to hook conditional branch instructions and thus to reach some level of instrumentation. Currently only x86-64 architecture is supported and only for JCC-type instructions occupying at least 5 bytes. As it's stated on GDBleed's README file, we do not want to do heavily changes on the control flow of the program, so instead of using well-known techniques of binary instrumentation then we prefer to hook conditional branches by converting them into call instructions and then retrieving the visited basic block by comparing the return addresses.

Please note, the tool is not complete and this is just a demo, refer to [README](./README.md) for more information about the GDBleed architecture in general

<br />

### Requirements and limitations

 - GDBleed must be installed and GDBLEED_HOME env must be set (follow the [readme](https://github.com/tin-z/GDBleed#req))

 - tested on docker image ubuntu 20.04
 - Capability of mapping the 0 address on userspace is required 
 - Hooking of short JCC-type (2 bytes) on x86-64 is not supported
 - Thread support is still ongoing


<br />

### Demo


 - Setup:
 
```
# 1. spawn gdbserver and attach it to a process that can map the 0-address (required only for kernel 4.+ or 5.+, something like so)
# gdbserver --attach <ip-listening>:<port-listening> <pid>
# e.g.
gdbserver --attach 127.0.0.1:12345  554449


# 2. delete old gdbleed session
rm -rf /tmp/gdbleed/

# 3. spawn gdb from gdbleed working directory 
cd $GDBLEED_HOME

gdb /bin/bash -ex "source ./.gdbinit-gef.py" -ex "target remote 127.0.0.1:12345" -ex "source gdbleed.py" -ex "hook-got-inline --gdbcov --init-data" -ex "hook-got-inline --gdbcov --init-trampoline fork" -ex "hook-got-inline --create ./plugins/code_cov/gdbcov_dichotomic.c.bleed" -ex "hook-got-inline --create ./plugins/code_cov/gdbcov_entrypoint.c.bleed" -ex "hook-got-inline --list gdbcov.entry" -ex "hook-got-inline --gdbcov --trace" -ex "b *0"
```

 - Poc:

![gdbcov_demo.gif](./docs/img/gdbcov_demo.gif)

