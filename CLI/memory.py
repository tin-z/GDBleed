# -*- coding: utf-8 -*-

"""
    Allocate memory using vmmap syscall, 
    and malloc.

    If vmmap call fails then use malloc, 
    or select to call directly malloc.

    Also keep track of memory region areas.
"""

import gdb
import re
import mmap

import os
from os.path import exists
from os import listdir, mkdir
import shutil


from core import memory
from utils.gdb_utils import make_executable
import config


tmp_folder = config.tmp_folder
DUMP_DIR = "{}/dump_dir".format(tmp_folder)


class MemCommand(gdb.Command):

  def __init__(self, name, details, details_mem):
    super(MemCommand, self).__init__(name, gdb.COMMAND_NONE)
    self.details_mem = details_mem
    self.details = details

  def __get_details_mem(self, k) :
    return self.details_mem[k]

  @property
  def mm_regions(self) :
    return self.__get_details_mem("mm_regions")

  @property
  def mm_addresses(self) :
    return self.__get_details_mem("mm_addresses")

  @property
  def mm_regions_ctrl(self) :
    return self.__get_details_mem("mm_regions_ctrl")

  @property
  def mm_addresses_ctrl(self) :
    return self.__get_details_mem("mm_addresses_ctrl")

  def invoke(self, argv, from_tty):
    """
      Abstract method
    """
    pass


class DumpAll(MemCommand):
  """
    Dump all process memory area and save output into <tmp_folder>/dump_dir folder
  """

  cmd_default = "dump-all"

  def __init__(self, name, details, details_mem):
    super(DumpAll, self).__init__(name, details, details_mem)

  def invoke(self, argv, from_tty):

    if exists(DUMP_DIR) :
      if listdir(DUMP_DIR) :
        self.details["slog"].append(
          "[{}] Found some files inside folder '{}'\n".format(DumpAll.cmd_default, DUMP_DIR) +\
          " \---> Do you want to delete them? (y/Y/-)"
        )
        if input().strip().upper() != "Y" :
          shutil.rmtree(DUMP_DIR)
          os.mkdir(DUMP_DIR)

    else : 
      os.mkdir(DUMP_DIR)

    for addr in self.mm_addresses :
      mm = self.mm_regions[addr]
      addr = hex(addr)
      eaddr = hex(mm.eaddr)
      addr_name = "{}.bin".format(addr)
      cmd = "dump binary memory {}/{} {} {}".format(DUMP_DIR, addr_name, addr, eaddr)
      try :
        gdb.execute(cmd)
      except Exception as ex :
        self.details["slog"].append("[{}] exeception on entry '{}' ..ignoring".format(DumpAll.cmd_default, cmd))
        self.details["slog"].append(str(ex))
        self.details["slog"].append("")


class MemMap(MemCommand):
  """
    Map memory using mmap and/or malloc
  """

  cmd_default = "mem-map"
  match_with   = r"\$[0-9]+ = (\(.*\))[ ]+(0x[A-f0-9]+)[ ]+.*"
  match_with_2 = r"\$[0-9]+ = (\(.*\))[ ]+(0x[A-f0-9]+)"
  match_without_decl = r"\$[0-9]+ = .*(0x[A-f0-9]+)"

  def __init__(self, name, details, details_mem):
    super(MemMap, self).__init__(name, details, details_mem)
    rets = gdb.execute("p &mmap", to_string=True).strip()
    rets_2 = re.search(MemMap.match_with, rets)

    if not rets_2 :
      self.details["slog"].append("[!] can't find mmap declaration ..ignoring it")
      rets_2 = re.search(MemMap.match_without_decl, rets)
      rets = rets_2.groups()
      rets = ["", rets[0]]
    else :
      rets = rets_2.groups()

    self.mmap_decl = rets[0]
    self.mmap_addr = int(rets[1], 16)


  def do_mmap(self, addr, size, permissions) :
    perm = {"-":0, "r":mmap.PROT_READ, "w":mmap.PROT_WRITE, "x":mmap.PROT_EXEC}
    flags = mmap.MAP_ANONYMOUS | mmap.MAP_PRIVATE

    # adjust permissions
    perm_tmp = 0
    for x in list(permissions) :
      perm_tmp |= perm[x]
    permissions = perm_tmp

    # adjust address
    adjust_addr = False
    if addr in self.mm_addresses :
      adjust_addr = True
      self.details["slog"].append("Address '{}' already mapped ..changing".format(hex(addr)))
      # size mu be updated here, for now is fine
    #
    if addr == 0 :
      adjust_addr = True
    if adjust_addr :
      addr = self.mm_addresses[0] - size

    cmd = "call (void *) mmap({}, {}, {}, {}, 0, 0)".format(hex(addr), hex(size), permissions, flags)
    try :
      rets = gdb.execute(cmd, to_string=True).strip()
    except :
      rets = "Command aborted."

    if "Command aborted." not in rets :
      rets_2 = re.search(MemMap.match_with_2, rets)
      rets = rets_2.groups()
    else :
      rets = [-1,-1]

    if rets[1] != hex(addr) :
      return None

    addr = int(rets[1], 16)
    return addr


  def do_malloc(self, size) :
    cmd = "call (void *) malloc({})".format(hex(size))
    rets = gdb.execute(cmd, to_string=True).strip()
    rets_2 = re.search(MemMap.match_with_2, rets)
    rets = rets_2.groups()
    addr = int(rets[1], 16)
    return addr


  def invoke(self, argv, from_tty):
    argv = [x.strip() for x in argv.split(" ") if x.strip() != "" ]
    permissions = "rw"
    allocated_with_malloc = False

    try_malloc = False
    if "--try-malloc" in argv[0] :
      try_malloc = True
      argv = argv[1:]

    malloc = False
    if "--malloc" in argv[0] :
      malloc = True
      argv = argv[1:]

    try :

      if argv[0].startswith("0x") :
        size = int(argv[0], 16)
      else :
        size = int(argv[0])

      if not malloc :
        addr = size
        size = 0x2000 

        if len(argv) > 1 :
          if argv[1].startswith("0x") :
            size = int(argv[1], 16)
          else :
            size = int(argv[1])

        permissions = "rwx" if len(argv) < 3 else argv[2]
        rets = self.do_mmap(addr, size, permissions)
        if rets == None :
          tmp_str = "[!] mmap call Fail, address given:'{}', returned value: '{}'".format(hex(addr), rets)
          if not try_malloc :
            raise Exception(tmp_str)

          self.details["slog"].append(
            tmp_str + "\n" +\
            " \---> calling malloc instead"
          )

        else :
          # if we here all went fine
          try_malloc = False

      if malloc or try_malloc :
        rets = self.do_malloc(size)
        allocated_with_malloc = True
        if rets == None :
          raise Exception("[x] calling malloc failed!")

      addr = rets

      # update mm_regions and mm_addresses vars
      mm = memory.MemoryRegion(
        addr, 
        addr+size, 
        size, 
        0, 
        "", 
        perm=permissions, 
        allocated_with_malloc = allocated_with_malloc
      )

      if allocated_with_malloc and "x" in permissions :
        make_executable(self.details, addr, size)

      self.details_mem["mm_regions"].update({addr:mm})
      self.details_mem["mm_addresses"].append(addr)
      self.details_mem["mm_addresses"].sort()
      self.details_mem["mm_regions_ctrl"].update({addr:mm})
      self.details_mem["mm_addresses_ctrl"].append(addr)
      self.details_mem["mm_addresses_ctrl"].sort()

      print(hex(addr))

    except Exception as ex :
      self.details["slog"].append(str(ex))
      self.details["slog"].append(
        "Usage: {} [--try-malloc] <address> [size] [permissions]".format(MemMap.cmd_default) + "\n" +\
        ":      {} [--malloc] <size>".format(MemMap.cmd_default) + "\n" +\
        "     --try-malloc : if mmap fails try malloc instead\n" +\
        "     address      : choose the address to map (insert '0' to let gdb choose)\n" +\
        "     size         : size to map (default: '0x2000')\n" +\
        "     permissions  : memory region permissions, e.g 'rx' (default: 'rwx')\n" +\
        "\n" +\
        "     --malloc     : allocate memory using malloc only\n" +\
        "     size         : size\n"
      )


class MemUnmap(MemCommand):
  """
    Unmap memory using munmap
  """

  cmd_default = "mem-unmap"
  match_with   = r"\$[0-9]+ = (\(.*\))[ ]+(0x[A-f0-9]+)[ ]+.*"
  match_without_decl = r"\$[0-9]+ = .*(0x[A-f0-9]+)"

  def __init__(self, name, details, details_mem):
    super(MemUnmap, self).__init__(name, details, details_mem)
    rets = gdb.execute("p &munmap", to_string=True).strip()
    rets_2 = re.search(MemUnmap.match_with, rets)

    if not rets_2 :
      self.details["slog"].append("[!] can't find munmap declaration ..ignoring it")
      rets_2 = re.search(MemUnmap.match_without_decl, rets)
      rets = rets_2.groups()
      rets = ["", rets[0]]
    else :
      rets = rets_2.groups()

    self.munmap_decl = rets[0]
    self.munmap_addr = int(rets[1], 16)


  def invoke(self, argv, from_tty):
    argv = [x.strip() for x in argv.split(" ") if x.strip() != "" ]

    try :

      if argv[0].startswith("0x") :
        addr = int(argv[0], 16)
      else :
        addr = int(argv[0])

      if argv[1].startswith("0x") :
        size = int(argv[1], 16)
      else :
        size = int(argv[1])

      if addr not in self.mm_addresses :
        raise Exception("Address '0x{:x}' sems to not be mapped".format(addr))

      mm = self.mm_regions[addr]
      allocated_with_malloc = mm.allocated_with_malloc

      cmd = "call (int) munmap({}, {})".format(hex(addr), hex(size))
      if allocated_with_malloc :
        cmd = "call (long long) free({})".format(hex(addr))

      rets = gdb.execute(cmd, to_string=True).strip()

      match_with = r"\$[0-9]+ = (0x[A-f0-9]+)"
      rets_2 = re.search(MemUnmap.match_without_decl, rets)
      rets = rets_2.groups()

      ret_addr = int(rets[0].strip(), 16)

      if allocated_with_malloc :
        if ret_addr == 0 :
          raise Exception("[!] free call Fail, returned value: '{}'".format(rets))

      else :
        if ret_addr != 0 :
          raise Exception("[!] munmap call Fail, returned value: '{}'".format(rets))

      # update mm_regions and mm_addresses vars
      del self.mm_regions[addr]
      del self.mm_addresses[self.mm_addresses.index(addr)]
      if addr in self.mm_addresses_ctrl :
        del self.mm_regions_ctrl[addr]
        del self.mm_addresses_ctrl[self.mm_addresses_ctrl.index(addr)]
      print(hex(addr))

    except Exception as ex :
      self.details["slog"].append(str(ex))
      self.details["slog"].append(
        "Usage: {} <address> <size>".format(MemUnmap.cmd_default) + "\n" +\
        "     address     : choose the address to unmap/free\n" +\
        "     size        : size of the memory region to unmap\n"
      )


def init(details, details_mem, details_data, extra=dict()) :
  DumpAll(DumpAll.cmd_default, details, details_mem)
  MemMap(MemMap.cmd_default, details, details_mem)
  MemUnmap(MemUnmap.cmd_default, details, details_mem)

