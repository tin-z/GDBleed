#######################################################################################
# GDBleed :-: Static, Dynamic Binary Instrumentation framework based on GDB
#
# by  @tin-z (Altin 0v4rl0r5[at]gmail[dot]com)
#######################################################################################
#
# GDBleed is distributed under the MIT License (MIT)
# Copyright (c) 2022, Altin (tin-z)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# -*- coding: utf-8 -*-
import gdb
import sys
import os
from os.path import exists
from os import listdir, mkdir


g_home = os.getenv("GDBLEED_HOME")
if not g_home :
  raise Exception("GDBLEED_HOME env not defined ...quit")

os.chdir(g_home)
sys.path.append(".")


# before importing else modules, import the march one
import config
from core.march import *
from utils.utilsX import *
from utils import gdb_utils

tmp_folder = config.tmp_folder
if not exists(tmp_folder) :
  mkdir(tmp_folder)


details = {
  "capsize" : None,
  "word" : None,
  "arch" : None,
  "isa" : None,
  "running" : False,
  "slog" : slog,
  "endian" : None,
  "is_pie" : None,
  "binary_path" : None,
  "libc_path" : None,
  "pid" : None ,
  "session_loaded" : False ,
  "qemu_usermode" : False
}
"""
General info dict
"""

# get 'binary_path' and 'libc_path' from last session
try :
  with open(config.log_file, "r") as fp:
    rets = [ x.strip() for x in fp.read().split("\n") if not x.startswith("#") ]
    for x in rets :
      k, v = x.split(" : ")
      details[k] = v
except :
  pass


rets_tmp = getarch(details)
if not rets_tmp :
  print("Error with getarch() method")
  sys.exit(-1)

rets_tmp = getendianess(details)
if not rets_tmp :
  print("Error, can't find binary endianes")
  sys.exit(-1)

_ = gdb_utils.getpid(details)


# from here import the other deps
from utils.colorsX import *
from core import memory, GOT, sections

import hook
import CLI


# configure settings
mm_regions, mm_addresses = memory.map_memory(details)

mm_regions_ctrl, mm_addresses_ctrl = dict(), list()
binary_name, binary_name_local = gdb_utils.get_binary_name(details)
base_address, size_base_address, libc_base_address, libc_size_base_address = gdb_utils.get_base_address(binary_name, binary_name_local, mm_regions, details)

# before doing symbol stuff re-load libc symbols
if details["arch"] != "x86-64" :
  import lief

  libc_path = details["libc_path"]
  if not libc_path :
    print("Insert libc path (you need to save it on your local machine)")
    libc_path = input().strip()

  libc_binary = lief.parse(libc_path)
  libc_text = [x for x in libc_binary.sections if x.name == ".text"][0].file_offset + libc_base_address
  details["libc_path"] = libc_path
  gdb.execute("add-symbol-file {} 0x{:x}".format(libc_path, libc_text))


if details["qemu_usermode"] :
  gdb_utils.make_executable(details, base_address, size_base_address)


got_entries = GOT.got_symbols(binary_name, binary_name_local, base_address, size_base_address, details)
executable_offset, executable_size, section_entries = sections.elf_sections(binary_name, binary_name_local, base_address, details)

details_mem = {
  "mm_regions" : mm_regions ,\
  "mm_addresses" : mm_addresses ,\
  "mm_regions_ctrl" : mm_regions_ctrl ,\
  "mm_addresses_ctrl" : mm_addresses_ctrl ,\
}
"""
Memory status dict
"""

details_data = {
  "binary_name" : binary_name ,\
  "binary_name_local" : binary_name_local ,\
  "base_address" : base_address ,\
  "executable_offset" : executable_offset ,\
  "executable_size" : executable_size ,\
  "size_base_address" : size_base_address ,\
  "libc_base_address" : libc_base_address ,\
  "libc_size_base_address" : libc_size_base_address ,\
  "got_entries" : got_entries ,\
  "section_entries" : section_entries ,\
  "parser" : None ,\
  "compiler" : None ,\
}
"""
Binary related info dict
"""


# post-configure settings
CLI.init(details, details_mem, details_data)
hook.init(details, details_mem, details_data)


# save libary and binary paths for later usage
with open(config.log_file, "w") as fp:
  output = []
  for k in ["binary_path", "libc_path"] :
    output.append("{} : {}".format(k, details[k]))
  fp.write("\n".join(output))


## clean stuff
del mm_regions
del mm_addresses
del mm_regions_ctrl
del mm_addresses_ctrl
del binary_name
del binary_name_local
del base_address
del got_entries



###      #
## Main ##
#      ###

max_callstack_depth = 16
gdb.execute("set confirm off")
gdb.execute("set pagination off")
gdb.execute("set breakpoint pending on")
backtrace_limit_command = "set backtrace limit " + str(max_callstack_depth)
gdb.execute(backtrace_limit_command)

gdb.execute("set hex-dump-align on")


print("# Done\n")


