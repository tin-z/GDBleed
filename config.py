# -*- coding: utf-8 -*-

# Configurable constants

hexdump_max_length = 200



slog_path = None
"""
Save output to 'slog_path', default stdout
"""

tmp_folder = "/tmp/gdbleed"
log_file="{}/log_exec.txt".format(tmp_folder)

LITTLE_ENDIAN=0
BIG_ENDIAN=1

LE = LITTLE_ENDIAN
BE = BIG_ENDIAN


compiler_path = {
    "mips" : {LE:"mipsel-linux-gnu-gcc", BE:"mips-linux-gnu-gcc"} ,\
    "x86-64" : {LE:"/usr/bin/gcc", BE:None} ,\
    "arm": {LE:"/usr/bin/arm-linux-gnueabi-gcc", BE:"/usr/bin/arm-linux-gnueabi-gcc"}
}
"""
Cross-Compiler paths
"""

default_flag = dflg = "-g -fPIC -c"

compiler_flags = {
    "mips" : {LE:dflg, BE:dflg} ,\
    "x86-64" : {LE:dflg, BE:dflg} ,\
    "arm" : {LE:dflg, BE:dflg}
}
"""
Cross-Compiler flags
"""


ARCH_supported = ["mips", "x86-64", "arm"]
"""
Archs supported
"""



