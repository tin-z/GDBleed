# -*- coding: utf-8 -*-

"""
This module does a lot of stuff. Mainly it does:
    - map memory addresses for the code injection stuff (refer to mem_inj_area variable)
    - implements GOT highjacking (ref to the HookTrace class)
"""

import gdb

from hook.default_hooks import Pre_regs, Post_regs
from hook.poor_ltrace import HookTrace
from hook.inline_hooks import HookTrampoline

from hook import examples



initialized = False
default_list = {}
regs_ = {"pre_regs" : Pre_regs, "post_regs" : Post_regs}
hook_trace = None
hook_trampoline = None


default_mem_inj_area = { 
  "text"  : {"addr":0x200000, "size":0x40000, "offset":0, "mapped":False} ,\
  "data"  : {"addr":0x250000, "size":0x40000, "offset":0, "mapped":False} ,\
  "stack" : {"addr":0x2A0000, "size":0x40000, "offset":0, "mapped":False}
}

mem_inj_area = {
  "text"  : {} ,\
  "data"  : {} ,\
  "stack" : {}
}


"""
allocated memory areas for code/data injection purpose
"""


def inject_code(data) :
  return inject(data, "text", align_to=4)

def inject_data(data) :
  return inject(data, "data")

def inject_stack(data) :
  """
    We don't need this one, 
    it's against the framework design.

    We use it just once to save the SP addresses:
      0: injected memory SP
      4/8: original SP
  """
  return inject(data, "stack")

def inject_gdbcov_data(data) :
  return inject(data, "gdbcov.data", align_to=4)


def inject(data, mem_area_k, align_to=0) :
  """
    Inject code/data and temporary bytes

    For now we do not consider the following condition, which are in TODO list, that are:
      - EOM condition, overflow
      - align memory issues
  """
  global mem_inj_area
  size = len(data)
  mem_area = mem_inj_area[mem_area_k]
  addr = mem_area["addr"] + mem_area["offset"]

  if align_to > 0 :
    addendium = align_to - (mem_area["offset"] % align_to)
    mem_area["offset"] += addendium

  if mem_area["offset"] + size <= mem_area["size"] :
    i = gdb.inferiors()[0]
    i.write_memory(addr, data, size)
    mem_area["offset"] += size
    return addr
  raise Exception("No memory space to inject bytes")


def init(details, details_mem, details_data) :
  """
    Initialize

     - memory region area used by gdbleed

     - the singleton objects:
        * hook_trace : HookTrace
        * hook_trampoline : HookTrampoline

  """
  global mem_inj_area, default_mem_inj_area 
  global default_list, initialized, regs_
  global hook_trace, hook_trampoline 
  if initialized :
    return

  for k,v in default_mem_inj_area.items() :
    mem_inj_area[k] = v.copy()

  for k,v in mem_inj_area.items() :
    if v["mapped"] :
      continue

    addr = v["addr"]
    size = v["size"]
    rets = gdb.execute("mem-map --try-malloc 0x{:x} 0x{:x}".format(addr, size), to_string=True).strip().split("\n")[-1].strip()
    if rets.startswith("0x") :
      tmp_addr = int(rets, 16)
      if tmp_addr != addr :
        details["slog"].append(
          "[!] section '{}' mapped to '{}' instead of '{}'".format(k, hex(tmp_addr), hex(addr))
        )
        mem_inj_area[k]["addr"] = tmp_addr
      mem_inj_area[k]["mapped"] = True

  # 0. 0: injected memory SP
  inject_stack("\x00" * details["capsize"])
  # 1. 4/8: this SP
  inject_stack("\x00" * details["capsize"])
  # 2. 8/16: addr. function-hooking (pre-function type)
  inject_stack("\x00" * details["capsize"])
  # 3. 12/24: addr. function-hooking (post-function type)
  inject_stack("\x00" * details["capsize"])
  #
  # 4. 16/32: length of function name hooked
  inject_stack("\x00" * details["capsize"])
  # 5. 20/40: address of function name hooked
  inject_stack("\x00" * details["capsize"])
  # 6. 24/48: addr. function-hooked
  inject_stack("\x00" * details["capsize"])
  # 7. 28/56: num of arguments
  inject_stack("\x00" * details["capsize"])

  regs_["pre_regs"] = Pre_regs(details)
  regs_["post_regs"] = Post_regs(details)

  default_list = examples.default_list.copy()
  for k,v in list(default_list.items()) :
    default_list[k] = v(details, details_data, regs_)

  hook_trace = HookTrace(details, details_data, regs_)
  hook_trampoline = HookTrampoline(details, details_data, regs_)

  initialized = True




def init_gdbcov_0_address(details_mem, size):
  # check if '0' address is already mapped
  if 0 in details_mem["mm_addresses"] :
    print("[!] NOTE: '0' address is already mapped")
    return

  MAP_ANONYMOUS=0x20
  MAP_FIXED=0x10
  addr = 0
  permissions = "rwx"
  flags = MAP_ANONYMOUS | MAP_FIXED

  rets = gdb.execute(
    "mem-map --try-malloc 0x{:x} 0x{:x} {} 0x{:x}".format(addr, size, permissions, flags) ,\
    to_string=True
  ).strip().split("\n")[-1].strip()
  
  if rets.startswith("0x") :
    tmp_addr = int(rets, 16)
    if tmp_addr != 0 :
      raise Exception("[!] ERROR: can't map '0' address, the process must have CAP_SYS_RAWIO to do so")
  else : 
    raise Exception("[!] ERROR: mmap(0, ...) returned an invalid value: '{}'".format(rets))


def init_gdbcov(details, details_mem, details_data, size_gdbcov_data) :
  """
    Memory initialization for gdbcov functionalities

  """
  global mem_inj_area, default_mem_inj_area 
  global default_list, initialized, regs_
  global hook_trace, hook_trampoline 
 
  # 1. map gdbcov data section
  if "gdbcov.data" in mem_inj_area :
    print("[!] Note: 'gdbcov.data' section is already mapped .. return")
    return
  else :
    size_gdbcov_data += (4096 - (size_gdbcov_data % 4096))
    mem_inj_area.update(
      {"gdbcov.data" : {"addr":0x0, "size":size_gdbcov_data, "offset":0, "mapped":False}}
    )

    MAP_ANONYMOUS=0x20
    addr = 0
    size = size_gdbcov_data
    permissions = "rwx"
    flags = MAP_ANONYMOUS
    rets = gdb.execute(
      "mem-map 0x{:x} 0x{:x} {} 0x{:x}".format(addr, size, permissions, flags) ,\
      to_string=True
    ).strip().split("\n")[-1].strip()

    if rets.startswith("0x") :
      tmp_addr = int(rets, 16)
      if tmp_addr != addr :
        details["slog"].append(
          "[!] section '{}' mapped to '{}' instead of '{}'".format(k, hex(tmp_addr), hex(addr))
        )
        mem_inj_area[k]["addr"] = tmp_addr
      mem_inj_area[k]["mapped"] = True

    else : 
      raise Exception("[!] ERROR: mmap(0, ...) returned an invalid value: '{}'".format(rets))

  # 2. Check '0' address for arch intel (if arch x86 or x86_64 we need to map 0 - 0x1000)
  if details["arch"] in ["x86-64"] and "0" not in mem_inj_area :
    size = 0x1000
    init_gdbcov_0_address(details_mem, size)
    if "0" not in mem_inj_area :
      mem_inj_area.update({
        "0" : {"addr":0x0, "size":size, "offset":0, "mapped":True}
      })



def remove(details, details_mem, details_data) :
  global mem_inj_area, default_mem_inj_area

  got_entries = details_data["got_entries"]
  result = [k for k,v in got_entries.items() if v.is_hooked() ]

  if result :
    output = ["[x] Can't unmap memory allocated from 'hook' modules"]
    for x in result :
      output.append(
        " \---> '{}' is still hooked".format(x)
      )
    details["slog"].append(
      "\n".join(output) + "\n"
    ) 
    return

  for k,v in mem_inj_area.items() :

    if v["mapped"] :
      addr = v["addr"]
      size = v["size"]
      rets = gdb.execute("mem-unmap 0x{:x} 0x{:x}".format(addr, size), to_string=True).strip().split("\n")[-1].strip()
      if not rets.startswith("0x") :
        raise Exception("[x] Can't unmap address '0x{:x}' (size: 0x{:x})".format(addr, size))
      mem_inj_area[k] = default_mem_inj_area[k].copy()

  return 1


def reset(details, details_mem, details_data) :
  global initialized
  remove(details, details_mem, details_data)
  initialized = False
  init(details, details_mem, details_data)
  return 1


