# -*- coding: utf-8 -*-
import r2pipe

"""
  The following module will be used to disasm the binary

  Example task such as find calls/etc.
"""


def get_binary_name(details) :
  """
    Get binary's name
  """
  rets = gdb.execute("info proc cmdline", to_string=True)

  if "unable to open /proc file" in rets :
    details["qemu_usermode"] = True
    return get_binary_name_qemu(details)

  binary_name = rets.split("\n")[1].split("=")[1].strip().replace("'","").split(" ")[0]

  if binary_name.startswith("-") :
    binary_name = binary_name[1:]

  binary_name_local = gdb.current_progspace().filename

  if details["binary_path"] :
    binary_name_local = details["binary_path"]
    return binary_name, binary_name_local

  msgs = [
    "Which path-filename do you want to use? (select number, if you are using gdbserver you must select the local path file)" ,
    "1. for '{}'".format(binary_name) ,
    "2. for '{}'".format(binary_name_local) ,
    "3. custom" 
  ]

  err_msgs = [
    "Invalid choice .. default choise is '{}'".format(binary_name)
  ]

  for x in msgs :
    print(x)
    if not details["slog"].is_stdout :
      details["slog"].append(x)

  select = input().strip()

  try :
    select = int(select)
    if select < 1 or select > 3 :
      raise Exception()
  except :
    print(err_msgs[0])
    if not details["slog"].is_stdout :
      details["slog"].append(err_msgs[0])
    select = 1

  if select == 1 :
    binary_name_local = binary_name

  elif select == 3 :
    binary_name_local = input("Insert path-filename of the binary: ").strip()

  details["binary_path"] = binary_name_local
  return binary_name, binary_name_local


def get_libc_base_address(output_dict, details) :
  """
    Get libc's base address and size
  """
  output = []
  output_tmp_dict = {}
  size = 0
  for v in output_dict.values() :
    if "/libc." in v.name or "/libc-" in v.name :
      output.append(v.addr)
      size += v.size
      output_tmp_dict.update({v.addr : v.name})
  output.sort()

  if details["qemu_usermode"] :
    details["libc_path"] = output_tmp_dict[output[0]]

  return output[0], size


def get_base_address(binary_name, binary_name_local, output_dict, details) :
  """
    Get binary's base address and size
  """
  output = []
  size = 0
  for v in output_dict.values() :
    if v.name == binary_name or v.name == binary_name_local :
      output.append(v.addr)
      size += v.size
  output.sort()
  return (output[0], size) + get_libc_base_address(output_dict, details)


def find_function_addr(fname, details) :
  """
    Return address of a function, and its declaration 
  """
  match_with = r"\$[0-9]+ = (\(.*\))[ ]+(0x[A-f0-9]+)[ ]+.*"
  match_with_2 = r"\$[0-9]+ = (\{.*\})[ ]+(0x[A-f0-9]+)[ ]+.*"
  rets = gdb.execute("p &{}".format(fname), to_string=True).strip()
  rets_2 = re.search(match_with, rets)
  if not rets_2 :
    details["slog"].append("[!] can't find '{}' declaration".format(fname))
    rets_2 = re.search(match_with_2, rets)
    rets = rets_2.groups()
    if rets :
      rets = ["", rets[1]]
    else :
      return None, None
  else :
    rets = rets_2.groups()
  decl = rets[0]
  addr = int(rets[1], 16)
  return (decl, addr)


def search_string(addr, eaddr, find) :
  """
    Search in memory string <find>
  """
  cmd = "find 0x{:x},0x{:x},\"{}\"".format(addr,eaddr,find)
  return gdb.execute(cmd, to_string=True).strip()


def get_data_memory(word_size, addr) :
  """
    Return <word_size> value contained by <addr> memory area
  """
  rets = gdb.execute("x/{} {}".format(word_size, addr), to_string=True).strip()
  rets = int(":".join(rets.split(":")[1:]).strip(), 16)
  return rets


def getpid(details) :
  details["pid"] = gdb.selected_inferior().pid
  return details["pid"]



def get_binary_name_qemu(details) :
  binary_name = gdb.current_progspace().filename
  binary_name_local = binary_name
  details["binary_path"] = binary_name_local
  return binary_name, binary_name_local



def make_executable(details, addr, size, perm=7):
  size = size >> 12 << 12
  cmd = "call (int) mprotect({}, {}, {})".format(addr, size, perm)
  rets = gdb.execute(cmd, to_string=True).strip().split("=")[1].strip()
  ret_code = int(rets, 16)

  if ret_code != 0 :
    details["slog"].append(
      "[!] Can't make 'rwx' permissions on process memory in qemu user-mode ... DIY"
    )
    return

  try :
    size = size + 0x1000
    cmd = "call (int) mprotect({}, {}, {})".format(addr, size, perm)
    rets = gdb.execute(cmd, to_string=True).strip().split("=")[1].strip()
  except :
    pass


