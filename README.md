# GDBleed

[![Docs](https://img.shields.io/badge/Documentation-blue.svg)](https://tin-z.github.io/gdbleed/) [![MIT](https://img.shields.io/packagist/l/doctrine/orm.svg?maxAge=2592000?style=plastic)](https://github.com/tin-z/GDBleed/blob/main/LICENSE)

GDBleed - Dynamic-Static binary instrumentation framework on top of GDB

`GDBleed` is a gdb wrapper exposing a set of commands for x86-64, ARM and MIPS
(x86 and ARM thumb-mode in progress) architectures to perform binary
instrumentation. The objective was to exploit the hackish features of GDB
python API, while ignoring the software performance attribute (for now). And in
the end to have a user-friendly framework. GDBleed focus is applicability, then
we have efficiency. The more CPU archs it does suport the better it is.



### Why?

 - "easy"-fast minimal static-dynamic code instrumentation supporting all main CPU archs

 - Framework based on tools with a strong community support: GDB, gcc, r2, keystone, LIEF, etc.

 - No control flow information is needed

 - ideal for IoT devices, why?

    * no binary instrumentation for MIPS

    * cross-compilation is boring (and if it works then it will break somewhere during the execution)

    * A lot of the new IoT devices still using old linux kernel versions not supporting EBPF



### Usage

 - run gdb from the current folder

 - Start the process using `start` command or attach gdb to the debugged process

 - Run the command 

```
source gdbleed.py
```

 - For more info take a look at the `tests` folder

---

### Usage of the hooking functionalities ###

 - [Start guide](https://tin-z.github.io/gdbleed/start/)

    * For more clearance on how hooking/instrument stuff is working take a look at [strategy doc section](https://tin-z.github.io/gdbleed/strategy/strategy/)

---

### Req

 - Tested on ubuntu 20.04

 - Dep: keystone, LIEF


### Installation

 - Install 
```
# GEF gdb extension, ref https://github.com/hugsy/gef
sudo apt-get -y install unzip cmake binutils
```

 - Declare env vars
```
# python's version which your gdb intalled supports
export PYTHON_VER="python3"
sudo apt-get install ${PYTHON_VER}-distutils ${PYTHON_VER}-setuptools

# don't change these values
export KEYSTONE_VER="0.9.2"
export LIEF_VER="0.12.1"
```

 - From current folder run:
```
./setup.sh

```


**Required for hooking/instrumentation also aka Inline GOT hooking**

 - Install
```sh

export TARGET=arm-linux-gnueabi
sudo apt-get install -y binutils-${TARGET} gcc-${TARGET}

export TARGET=mips-linux-gnu
sudo apt-get install -y binutils-${TARGET} gcc-${TARGET}
```

 - add vim highlighting

```vim
augroup filetypedetect
  au! BufRead,BufNewFile *.c.bleed setfiletype c
augroup END
```



