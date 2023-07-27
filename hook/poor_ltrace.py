# -*- coding: utf-8 -*-

"""
  Poor ltrace implementation
"""

import hook
from hook.default_hooks import GeneralHook, HookItAgain


from core.constants import *
from utils.gdb_utils import search_string


class HookTrace (GeneralHook) :
  """
    Example of GOT hijacking.
    Infect GOT entries with trampoline point, then invoke write(".. <function-name> ..")
  """
  def __init__(self, details, details_data, regs_) :
    fname = "write"
    self.trace_pre = "##[==> \0".encode()
    self.new_line = "\n\0\0\0".encode()
    self.trace_pre_addr = hook.inject_data(self.trace_pre)
    self.new_line_addr = hook.inject_data(self.new_line)
    super(HookTrace, self).__init__(details, details_data, regs_, fname)
    self.puts_addr = self.addr


  def x86_code_write_to_stdout(self, str_value, str_addr) :
    """
      x86_64

      invoke write(stdout, ...)
    """
    code = \
      "MOV RDI, 0" +\
      "; MOV RSI, 0x{:x}".format(str_addr) +\
      "; MOV RDX, {}".format(len(str_value)) +\
      "; MOV RAX, 0x{:x}; CALL RAX".format(self.addr)
    code = code.encode()
    return self.do_asm(code)

  
  def arm_code_write_to_stdout(self, str_value, str_addr) :
    """
      arm

      invoke write(stdout, ...)
    """
    code = \
      "MOV R0, #0x{:x}".format(0) +\
      "; " + self.insert_arg_arm_inj_addr(str_addr, "R1") +\
      "; " + "MOV R2, #0x{:x}".format(len(str_value)) +\
      "; " + self.do_call_arm_inj_addr(self.addr)
    code = code.encode()
    return self.do_asm(code)


  def mips_code_write_to_stdout(self, str_value, str_addr) :
    """
      mips 

      invoke write(stdout, ...)
    """
    code = \
      "li $a0, 0x{:x}".format(0) +\
      "; " + self.insert_arg_mips_inj_addr(str_addr, "$a1") +\
      "; " + "li $a2, 0x{:x}".format(len(str_value)) +\
      "; " + self.do_call_mips_inj_addr(self.addr)
    code = code.encode()
    return self.do_asm(code)

  def powerpc_code_write_to_stdout(self, str_value, str_addr) :
    """
      powerpc 

      invoke write(stdout, ...)
    """
    code = \
      "li r3, 0x{:x}".format(0) +\
      "; " + self.insert_arg_powerpc_inj_addr(str_addr, "r4") +\
      "; " + "li r5, 0x{:x}".format(len(str_value)) +\
      "; " + self.do_call_powerpc_inj_addr(self.addr)
    code = HookItAgain.replace_powerpc_regs(code).encode()
    return self.do_asm(code)

  def x86_64_code(self) :
    self.pre_write = self.x86_code_write_to_stdout(self.trace_pre, self.trace_pre_addr)
    self.post_write = self.x86_code_write_to_stdout(self.new_line, self.new_line_addr)
    # from here it's junk code, we do not want to break the abstract class
    code = NOP_ins[self.details["arch"]].encode()
    return self.do_asm(code)

  def powerpc_code(self) :
    self.pre_write = self.powerpc_code_write_to_stdout(self.trace_pre, self.trace_pre_addr)
    self.post_write = self.powerpc_code_write_to_stdout(self.new_line, self.new_line_addr)
    # from here it's junk code, we do not want to break the abstract class
    code = NOP_ins[self.details["arch"]].encode()
    return self.do_asm(code)

  def arm_code(self) :
    self.pre_write = self.arm_code_write_to_stdout(self.trace_pre, self.trace_pre_addr)
    self.post_write = self.arm_code_write_to_stdout(self.new_line, self.new_line_addr)
    # from here it's junk code, we do not want to break the abstract class
    code = NOP_ins[self.details["arch"]].encode()
    return self.do_asm(code)

  def mips_code(self) :
    self.pre_write = self.mips_code_write_to_stdout(self.trace_pre, self.trace_pre_addr)
    self.post_write = self.mips_code_write_to_stdout(self.new_line, self.new_line_addr)
    # from here it's junk code, we do not want to break the abstract class
    code = NOP_ins[self.details["arch"]].encode()
    return self.do_asm(code)


  def inject(self, args=None, return_point=None, extra=None) :
    """
      #TODO :
        - print arguments in hexdump format
    """
    assert(args != None)
    assert(return_point != None)
    arch = self.details["arch"]

    args_tmp = []
    for x in args :
      if x.startswith("0x") :
        x = int(x, 16)
      else :
        x = int(x)
      args_tmp.append(x)
    args = args_tmp

    buff = b""
    buff += self.regs_["pre_regs"].inject_code
    buff += self.pre_write

    # TODO: add arugment etc.
    #buff += self.regs_["pre_regs"].inject_code
    #if args :
    #    buff += self.insert_arg(args)

    fname = extra["fname"]
    fname_addr = None
    for k,v in self.details_data["section_entries"][".dynstr"].symname.items() :
      if fname == k or k.startswith(fname + "@") :
        fname_addr = v

    if not fname_addr :
      self.details["slog"].append(
              "[TraceHook] Can't find symbol on '.dynstr', is imported by ordinale number.. searching it on LIBC memory space"
      )
      mem_regions = extra["details_mem"]["mm_regions"]
      output_libc = []
      for x in mem_regions.values() :
        lib_name = x.name
        if "/libc." in lib_name or "/libc-" in lib_name :
          output_libc.append(x)

      if output_libc :
        output_libc.sort(key=lambda x: x.addr)
        addr = output_libc[0].addr
        eaddr = output_libc[0].eaddr

        rets = search_string(addr, eaddr, fname)
        rets = rets.split("\n")
        if rets : 
          if rets[0].startswith("0x") :
            fname_addr = int(rets[0], 16)
            self.details["slog"].append(
              "[TraceHook] Found '{}' symbol in 0x{:x} address".format(fname, fname_addr)
            )

      if not fname_addr :
        fname_addr = hook.inject_data(fname + "\0")
        self.details["slog"].append(
          "[TraceHook] Can't find symbol '{}' on libc, inserting it by hand at addr '0x{:x}'".format(fname, fname_addr)
        )

    #rets = self.write_to_stdout(fname, fname_addr)
    #if not rets :
    #    return None

    if arch == "x86-64" :
      buff += self.x86_code_write_to_stdout(fname, fname_addr)

    elif arch == "arm" :
      buff += self.arm_code_write_to_stdout(fname, fname_addr)

    elif arch == "mips" :
      buff += self.mips_code_write_to_stdout(fname, fname_addr)

    elif arch == "powerpc" :
      buff += self.powerpc_code_write_to_stdout(fname, fname_addr)

    else :
      self.details["slog"].append(
        "[TraceHook] Arch '{}' not supported ...quit".format(arch)
      )
      return None

    buff += self.post_write
    buff += self.regs_["post_regs"].inject_code
    buff += self.jmp_to(return_point)

    if arch == "mips" :
      if self.details["endian"] == BIG_ENDIAN :
        output = b""
        for x in range(0,len(buff), self.details["capsize"]) :
          output += buff[x:x+self.details["capsize"]][::-1]
        buff = output

    rets = hook.inject_code(buff)
    return rets 


