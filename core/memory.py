# -*- coding: utf-8 -*-

"""
Memory area regions of the process

"""

import re
import gdb
import mmap

import lief


## Utils
match_entry = r"^(0x[A-f0-9]+)[ ]+(0x[A-f0-9]+)[ ]+(0x[A-f0-9]+)[ ]+(0x[A-f0-9]+)[ ]*(.*)"

permissions_table = {"-":0, "r":mmap.PROT_READ, "w":mmap.PROT_WRITE, "x":mmap.PROT_EXEC}
permissions_table_l = ["r","w","x"]


## Classes

class MemoryRegion:
  """
    MemoryRegion class
  """
  def __init__(self, 
      addr_from, 
      addr_to, 
      addr_size, 
      addr_offset, 
      addr_name, 
      perm=0,
      allocated_with_malloc = False,
      is_main_proc = False
    ) :
    """
      addr_from   : memory region start
      addr_to     : memory region end
      addr_size   : size memory region
      addr_offset : offset inside memory region
      addr_name   : memory region name
      perm        : memory region permission
    """
    self.addr = addr_from
    self.eaddr = addr_to
    self.size = addr_size
    self.offset = addr_offset
    self.name = addr_name
    self.perm = perm
    self.allocated_with_malloc = allocated_with_malloc
    self.is_main_proc = is_main_proc

  def print_permissions(self):
    output = ""
    for k in permissions_table_l :
      if self.perm & permissions_table[k] :
        output += k
      else :
        output += "-"
    return output

  def __check_perm(self, perm):
    return (self.perm & permissions_table[perm]) != 0

  def is_readable(self):
    return self.__check_perm("r")

  def is_writable(self):
    return self.__check_perm("w")

  def is_executable(self):
    return self.__check_perm("x")

  def is_main_proc(self):
    return self.is_main_proc

  def __str__(self) :
    return "MemoryRegion 0x{:x} 0x{:x} 0x{:x} 0x{:x} {} {}".format(
       self.addr, 
       self.eaddr, 
       self.size, 
       self.offset, 
       self.print_permissions(), 
       self.name
    )



## Runtime methods

def map_memory(details):
  """
    Create memory mapping view
  """
  output_list = list()
  output_dict = dict()

  # check if qemu user-mode
  rets = gdb.execute("vmmap", to_string=True)
  if "0x00000000 0xffffffff 0x00000000 rwx" in rets :
    details["qemu_usermode"] = True

  rets = gdb.execute("info proc mappings", to_string=True)
  if "unable to open" in rets :
    details["qemu_usermode"] = True

  if details["qemu_usermode"] :
    return map_memory_qemu(details)

  for x in rets.split("\n") :
    x = x.strip()
    if not x.startswith("0x") :
      continue

    rets = re.search(match_entry, x)
    if not rets :
      details["slog"].append("[!] can't parse entry '{}' .. ignoring".format(x))
      continue

    rets = rets.groups()
    addr_from = int(rets[0].strip(), 16)
    addr_to = int(rets[1].strip(), 16)
    addr_size = int(rets[2].strip(), 16)
    addr_offset = int(rets[3].strip(), 16)
    addr_name = rets[4].strip()

    mm = MemoryRegion(addr_from, addr_to, addr_size, addr_offset, addr_name)
    output_dict.update({mm.addr : mm})
    output_list.append(mm.addr)

  output_list.sort()
  update_memory_perm(output_dict, details)
  return output_dict, output_list



def map_memory_qemu(details):
  details["slog"].append(
    "[!] Unable to open /proc/<pid>/maps files .. trying the other method"
  )

  # NOTE: in future if we want to remove vmmap, we should modify this code, e.g:
  #   - "are you running qemu-user-mode?" etc.

  cmd = "show solib-search-path".strip()
  rets = gdb.execute(cmd, to_string=True)
  match_now = r"The search path for loading non-absolute shared library symbol files is(.*)\."
  
  rets = re.search(match_now, rets).groups()[0].strip()
  if rets == "" :
    raise Exception(
      "[X] run gdb command `set solib-search-path <path-to-firmware-extracted>/lib:<path-to-firmare-extracted>/usr/lib` ..quit"
    )

  lib_paths = rets.split(":")
  lib_files = list_files(lib_paths)

  rets = gdb.execute("info files", to_string=True).split("\n")

  match_hex = r"(0x[A-f0-9]+)"
  match_lib = r"^[ \t]+{0} - {0} is (\..*) in (.*)$".format(match_hex)
  match_bin = r"^[ \t]+{0} - {0} is (\..*)$".format(match_hex)

  index = rets.index("Local exec file:")
  binary_name = rets[index+1].strip().split("`")[1].split("'")[0]
  prev_fname = binary_name

  output = {binary_name:{}}

  for x in rets[index+2:] :
    rets = re.search(match_lib, x)
    is_bin = False
    if not rets :
      rets = re.search(match_bin, x)
      is_bin = True
      if not rets :
        details["slog"].append("[!] Skipping entry '{}'".format(x))
        continue

    rets = rets.groups()
    addr = int(rets[0], 16)
    eaddr = int(rets[1], 16)
    section = rets[2].strip()
    fname = binary_name

    if not is_bin :
      fname = rets[3].strip()

    if prev_fname != fname :
      prev_fname = fname
      output.update({fname:{}})

    output[fname].update({section : {"addr":addr, "eaddr":eaddr, "size":None}})

  return map_memory_qemu_2(details, output, binary_name, lib_files)



def map_memory_qemu_2(details, output, binary_name, lib_files) :

  section_order = [
    [".gnu.hash", permissions_table["r"]],\
    [".text", permissions_table["r"] | permissions_table["x"]],\
    [".rodata", permissions_table["r"]],\
    [".data", permissions_table["r"] | permissions_table["w"]],\
    [".bss", permissions_table["r"]]
  ]

  output_list = list()
  output_dict = dict()

  for x,v in output.items() :
  
    is_main_proc = True
    if x != binary_name :
      is_main_proc = False
      if x not in lib_files :
        raise Exception("[x] Can't find library '{}'".format(x))

    path_lib_now = x
    binary_path_lib_now = lief.parse(path_lib_now)
    section_now = {x[0]:None for x in section_order}

    for section in binary_path_lib_now.sections :
      if section.name in section_now :
        section_now[section.name] = section.file_offset

    baddr = v[".gnu.hash"]["addr"] - section_now[".gnu.hash"]
    prev_addr = baddr
    prev_perm = section_order[0][1]

    for sname, perm in section_order :
      if sname == ".gnu.hash" :
        continue

      eaddr = v[sname]["addr"] >> 12 << 12
      size = eaddr - prev_addr
      mm = MemoryRegion(prev_addr, eaddr, size, 0, x, is_main_proc=is_main_proc)
      mm.perm = prev_perm
      
      output_dict.update({mm.addr : mm})
      output_list.append(mm.addr)

      prev_addr = eaddr
      prev_perm = perm
    
    eaddr = (v[sname]["eaddr"] + 0x1000) >> 12 << 12
    size = eaddr - prev_addr
    mm = MemoryRegion(prev_addr, eaddr, size, 0, x, is_main_proc=is_main_proc)
    mm.perm = prev_perm

    output_dict.update({mm.addr : mm})
    output_list.append(mm.addr)

  output_list.sort()
  return output_dict, output_list



def list_files(lib_paths):
  import os 
  output = []
  for x in lib_paths :
    output += [ "{}/{}".format(x,y) for y in os.listdir(x) if os.path.isfile("{}/{}".format(x,y)) ]
  return output



def update_memory_perm(output_dict, details) :
  """ 
    Update memory regions permission
    (GEF extension required) 
  """
  try :
    rets = gdb.execute("vmmap", to_string=True)
  except :
      details["slog"].append("Cannot find memory region area permissions.. check if GEF interface is loaded by GDB")
      return
    
  for x in rets.split("\n")[2:] :
    x = x.strip()

    # remove unicode colors
    x = x.replace("\x1b[0m", "")
    for y in range(101) :
        x = x.replace("\x1b[{}m".format(y), "")

    if not x.startswith("0x") :
      continue

    rets = x.split(" ")
    if not rets :
      details["slog"].append("[!] [vmmap] can't parse entry '{}' .. ignoring".format(x))
      continue

    addr_from = int(re.search("^(0x[A-f0-9]+).*", rets[0].strip() ).groups()[0], 16)
    addr_perm = re.search("^([rwx-]{3})(.*)", rets[3].strip()).groups()[0]
    addr_name = rets[4].strip()

    # adjust permissions
    perm_tmp = 0
    for x in list(addr_perm) :
        perm_tmp |= permissions_table[x]
    addr_perm = perm_tmp

    output_dict[addr_from].perm = addr_perm
    output_dict[addr_from].name = addr_name


