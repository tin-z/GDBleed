# -*- coding: utf-8 -*-

"""
Inline hooking
"""

import hook
from hook.default_hooks import *

from hook.inline_objects import InjPoint
from hook._constants import   ONLY_PRE_FUNC ,\
                              ONLY_POST_FUNC ,\
                              ALL_FUNC ,\
                              RET_PRE_FUNC ,\
                              RET_POST_FUNC

from core.constants import *
from utils.gdb_utils import search_string

from core.disasm.disasm import WrapDisasm

from config import  tmp_folder ,\
                    LITTLE_ENDIAN ,\
                    BIG_ENDIAN


class HookTrampoline (GeneralHook) :
  """
    The trampoline point is a section of code which redirect
    the control flow to our inject code 'pre_func' and 'post_func'

    This class is the real dynamic/static binary instrumentation part,
    in the sense we do not need to extend or change this class but only
    to change our .bleed scripts

    #TODO:
      - post_func method
  """


  def __init__(self, details, details_data, regs_, disasm_strategy="r2") :
    fname = "write"
    self.str_unknown = "<unknown> \0".encode()
    self.str_emtpy = "\0\0\0\0".encode()
    self.str_new_line = "\n\0\0\0".encode()
    self.addr_str_unknown = hook.inject_data(self.str_unknown)
    self.addr_str_emtpy = hook.inject_data(self.str_emtpy)
    self.addr_str_new_line = hook.inject_data(self.str_new_line)
    super(HookTrampoline, self).__init__(details, details_data, regs_, fname)
    self.__init_trampolines()
    self.__init_gdbcov(disasm_strategy)

  def __init_trampolines(self) :
    self.trampoline_l = []
    self.inj_point_l = []
    self.__inject_trampoline_1()
    self.__inject_trampoline_2()

  def __init_gdbcov(self, disasm_strategy):
    self.disasm = WrapDisasm(
      self.details, 
      self.details_data, 
      strategy=disasm_strategy
    )
    self.disasm.init()
    #self.__inject_gdbcov_data()
    #self.__inject_gdbcov_trampoline()

  def x86_64_code(self) :
    # junk code, to not break the abstract class
    code = NOP_ins[self.details["arch"]].encode()
    return self.do_asm(code)

  def arm_code(self) :
    # junk code, to not break the abstract class
    code = NOP_ins[self.details["arch"]].encode()
    return self.do_asm(code)

  def mips_code(self) :
    # junk code, to not break the abstract class
    code = NOP_ins[self.details["arch"]].encode()
    return self.do_asm(code)


  def find_function_name_address(self, fname, details_mem) :
    """
      Find the name of a function inside libc process memory
    """
    fname_addr = None

    for k,v in self.details_data["section_entries"][".dynstr"].symname.items() :
      if fname == k or k.startswith(fname + "@") :
        fname_addr = v

    if not fname_addr :
      self.details["slog"].append(
              "[TraceHook] Can't find symbol on '.dynstr', is imported by ordinale number.. searching it on LIBC memory space"
      )
      mem_regions = details_mem["mm_regions"]
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

    return fname_addr


  def get_num_arg(self, fname, fname_addr):
    """
      TODO:
        - number of argument, in future use Dwarf core recon number 
          of arg (e.g. taviso github profile blog)
    """
    return 0


  def realign_stack(self):
    arch = self.details["arch"]
    output = []
    if arch == "x86-64" :
      output.append("ADD RSP, 0x{:x}".format(self.increment_stack_to * self.details["capsize"]))

    elif arch == "arm" :
      output.append("MOV R10, #0x{:x}".format(self.increment_stack_to * self.details["capsize"]))
      output.append("ADD R13, R13, R10")

    elif arch == "mips" :
      output.append("li $a0, 0x{:x}".format(self.increment_stack_to * self.details["capsize"]))
      output.append("add $sp, $sp, $a0")

    else :
      self.details["slog"].append(
        "[x] not supported!"
      )

    code = "; ".join(output).encode()
    return self.do_asm(code)


  def inject_function(self, code, extra=None) :
    """
      Inject binary code
    """
    return hook.inject_code(code)


  def inject_new_arguments(self):
    self.increment_stack_to = -1
    arch = self.details["arch"]
    output = []
    sp_arg = self.regs_["pre_regs"].sp_pivot * self.details["capsize"]
    self.increment_stack_to = 6

    stack_area = hook.mem_inj_area["stack"]
    stack_addr = stack_area["addr"]
    arch = self.details["arch"]
 
    if arch == "x86-64" :
      output.append("LEA RAX, [RSP+0x{:x}]".format(sp_arg + (1*self.details["capsize"])))
      output.append("PUSH RAX")
      #
      output.append("MOV R10, 0x{:x}".format(stack_addr))
      output.append("MOV R10, [R10+{}]".format(7*self.details["capsize"]))
      output.append("PUSH R10")
      #
      output.append("MOV R10, [RAX-0x{:x}]".format(self.details["capsize"]))
      output.append("PUSH R10")
      #
      for x in range(6,3,-1) :
        output.append("MOV R10, 0x{:x}".format(stack_addr))
        output.append("MOV RAX, [R10+{}]".format(x*self.details["capsize"]))
        output.append("PUSH RAX")

    elif arch == "arm" :
      output.append("MOV R10, #0x{:x}".format(sp_arg + (1*self.details["capsize"])))
      output.append("ADD R10, R10, R13")
      output.append("PUSH {R10}")
      #
      output.append(self.insert_arg_arm_inj_addr(stack_addr, "R10"))
      output.append("LDR R10, [R10, #{}]".format(7*self.details["capsize"]))
      output.append("PUSH {R10}")
      #
      output.append("MOV R10, LR")
      output.append("PUSH {R10}")
      #
      for x in range(6,3,-1) :
        output.append(self.insert_arg_arm_inj_addr(stack_addr, "R10"))
        output.append("LDR R10, [R10, #{}]".format(x*self.details["capsize"]))
        output.append("PUSH {R10}")
 
    elif arch == "mips" :
      # We need 4 slot of stack pushed before the actual arguments.
      # No time right now to understand why that 
      addendum = 4
      self.increment_stack_to += addendum
      push_mips = lambda index : "sw $t0, {}($sp)".format((index+addendum) * self.details["capsize"])

      output.append("li $t0, 0x{:x}".format(sp_arg + (1*self.details["capsize"])))
      output.append("add $t0, $sp, $t0")
      output.append("sub $sp, $sp, {}".format(self.increment_stack_to * self.details["capsize"]))
      output.append(push_mips(5))
      #
      output.append(self.insert_arg_mips_inj_addr(stack_addr, "$t0"))
      output.append("lw $t0, {}($t0)".format(7*self.details["capsize"]))
      output.append(push_mips(4))
      #
      output.append("add $t0, $ra, 0")
      output.append(push_mips(3))
      #
      for x in range(6,3,-1) :
        output.append(self.insert_arg_mips_inj_addr(stack_addr, "$t0"))
        output.append("lw $t0, {}($t0)".format(x*self.details["capsize"]))
        output.append(push_mips(2-(6-x)))

    else :
      self.details["slog"].append(
        "[x] not supported!"
      )

    code = "; ".join(output).encode()
    return self.do_asm(code)


  def do_call_pre_func(self):
    return self.do_call_func(2)

  def do_call_post_func(self):
    return self.do_call_func(3)

  def do_call_func(self, index):
    arch = self.details["arch"]
    output = []
    stack_area = hook.mem_inj_area["stack"]
    stack_addr = stack_area["addr"]

    if arch == "x86-64" :
      output.append("MOV RAX, 0x{:x}".format(stack_addr))
      output.append("MOV RAX, [RAX+{}]".format(index*self.details["capsize"]))
      output.append("CALL RAX")
             
    elif arch == "arm" :
      output.append(self.insert_arg_arm_inj_addr(stack_addr, "R10"))
      output.append("LDR R10, [R10, #{}]".format(index*self.details["capsize"]))
      output.append("BLX R10")
     
    elif arch == "mips" :
      to_reg=special_regs["mips_gp"]
      output.append(self.insert_arg_mips_inj_addr(stack_addr, to_reg))
      output.append("lw {}, {}({})".format(to_reg, index*self.details["capsize"], to_reg))
      output.append("jalr {}".format(to_reg))

    else :
      self.details["slog"].append(
        "[x] not supported!"
      )

    code = "; ".join(output).encode()
    return self.do_asm(code)


  def jmp_to_inline(self) :
    stack_area = hook.mem_inj_area["stack"]
    stack_addr = stack_area["addr"]

    code = b""
    if self.details["arch"] == "x86-64" :
      code = "PUSH RAX"
      code += "; " + "MOV RAX, 0x{:x}".format(stack_addr)
      code += "; " + "MOV RAX, [RAX+{}]".format(6*self.details["capsize"])
      code += "; " + "MOV [RSP-0x8], RAX; POP RAX; JMP [RSP-0x10]"

    elif self.details["arch"] == "arm" :
      code = "PUSH {R10}; PUSH {R9}"
      code += "; " + self.insert_arg_arm_inj_addr(stack_addr, "R10")
      code += "; " + "POP {R9}"
      code += "; " + "LDR R10, [R10, #{}]".format(6*self.details["capsize"])
      code += "; " + "STR R10, [SP, #{}]".format(-self.details["capsize"])
      code += "; " + "POP {R10}"
      code += "; " + "LDR PC, [SP, #{}]".format((-self.details["capsize"])*2)
 
    elif self.details["arch"] == "mips" :
      to_reg=special_regs["mips_gp"]
      code = self.insert_arg_mips_inj_addr(stack_addr, to_reg)
      code += "; " + "lw {}, {}({})".format(to_reg, 6*self.details["capsize"], to_reg)
      code += "; " + "jr {}".format(to_reg)

    else :
      raise Exception("[x] Arch '{}' not supported".format(arch))

    code = code.encode()
    return self.do_asm(code)


#  def switch_stack(self, from_old_to_new=True):
#    """
#      Temporary regs used:
#        - R10 for arm and intel
#        - $t0 for mips
#    """
#    stack_area = hook.mem_inj_area["stack"]
#    stack_addr = stack_area["addr"]
#    arch = self.details["arch"]
#    output = []
#
#    if from_old_to_new :
#      if arch == "x86-64" :
#        output.append("MOV R10, 0x{:x}".format(stack_addr))
#        output.append("MOV [R10], RSP")
#        output.append("MOV RSP, [R10 + 8]")
#
#      elif arch == "arm" :
#        output.append(self.insert_arg_arm_inj_addr(stack_addr, "R10"))
#        output.append("STR SP, [R10]")
#        output.append("LDR SP, [R10, #{}]".format(self.details["capsize"]))
#       
#      elif arch == "mips" :
#        output.append(self.insert_arg_mips_inj_addr(stack_addr, "$t0"))
#        output.append("sw $sp, 0($t0)")
#        output.append("lw $sp, {}($t0)".format(self.details["capsize"]))
#
#    else :
#      if arch == "x86-64" :
#        output.append("MOV R10, 0x{:x}".format(stack_addr))
#        output.append("MOV RSP, [R10]")
#
#      elif arch == "arm" :
#        output.append(self.insert_arg_arm_inj_addr(stack_addr, "R10"))
#        output.append("LDR SP, [R10]")
#       
#      elif arch == "mips" :
#        output.append(self.insert_arg_mips_inj_addr(stack_addr, "$t0"))
#        output.append("lw $sp, 0($t0)")
#
#    code = "; ".join(output).encode()
#    return self.do_asm(code)


  def __inject_trampoline_1(self) :
    """
      ONLY_PRE_FUNC trampoline:
        - Save regs
        - Push new arguments
        - Call pre_func
        - Restore regs
        - Jmp to function-hooked
    """
    arch = self.details["arch"]

    buff = b""
    buff += self.regs_["pre_regs"].inject_code
    buff += self.inject_new_arguments()
    buff += self.do_call_pre_func()
    buff += self.realign_stack()
    buff += self.regs_["post_regs"].inject_code

    last_ins_jmp = self.jmp_to_inline()
    buff += last_ins_jmp

    if arch == "mips" :
      if self.details["endian"] == BIG_ENDIAN :
        output = b""
        for x in range(0,len(buff), self.details["capsize"]) :
          output += buff[x:x+self.details["capsize"]][::-1]
        buff = output

    rets = hook.inject_code(buff)
    self.trampoline_l.append((rets, len(buff)))


  #def __inject_gdbcov_data(self):
  #  # Because we are creating a bitmap instead of indexing it by all the space address 
  #  # we rebase it by substractng the first non-executable sections
  #  executable_offset = self.details_data["executable_offset"]    
  #  executable_size = self.details_data["executable_size"]    
  #  baddr = self.details_data["base_address"]

  #  branches = self.disasm.get_conditional_branches()
  #  branches_index = [x.offset_end - executable_offset for x in branches]

  #  output = []                             # 1. gdbcov_list_bitmap (default value)
  #  for i in range(executable_size) :
  #    if i in branches_index :
  #      output.append(b"\x01")
  #    else :
  #      output.append(b"\x00")
  #  # Note 1:
  #  # dynamically trampoline will get the index by doing: (return_address - base_address) - executable_offset
  #  # questo valore poi lo salvo e lo riuso nella dichotomic

  #  index_list = []                         # 2. gdbcov_list_indexes
  #  jump_list = []                          # 3. gdbcov_list_jump
  #  pack = "<L" if self.details["endian"] == LITTLE_ENDIAN else ">L"

  #  for branch in branches :
  #    index_list.append(struct.pack(pack, branch.offset_end))
  #    jump_list.append(struct.pack(pack, branch.jump))

  #  self.gdbcov_list_bitmap = b"".join(output)
  #  self.gdbcov_list_bitmap_size = len(self.gdbcov_list_bitmap)

  #  self.gdbcov_list_indexes = index_list
  #  self.gdbcov_list_bitmap_size = len(self.gdbcov_list_indexes)


  #  self.gdbcov_list_bitmap_addr = hook.inject_data(self.gdbcov_list_bitmap)


  #def __inject_gdbcov_trampoline(self):
  #  arch = self.details["arch"]
  #  buff = b""

  #  if arch == "x86-64" :
  #    buff += self.do_asm("PUSH R10")
  #    buff += self.do_asm("MOV R10, [RSP+8]")

  #  LEA 
  #    output.append("LEA RAX, [RSP+0x{:x}]".format(sp_arg + (1*self.details["capsize"])))

  #  buff += self.regs_["pre_regs"].inject_code
  #  buff += self.find_ret_addr




  #  buff += self.inject_new_arguments()
  #  buff += self.do_call_pre_func()
  #  buff += self.realign_stack()
  #  buff += self.regs_["post_regs"].inject_code








  def __inject_trampoline_2(self) :
    """
      TODO: to fix

      RET_PRE_FUNC trampoline:
        - Push new arguments
        - jmp pre_func
    """
    arch = self.details["arch"]

    buff = b""

    if arch == "x86-64" :
      buff += self.do_asm(b"PUSH R10")

    elif arch == "arm" :
      buff += self.do_asm(b"PUSH {LR}")
      buff += self.do_asm(b"PUSH {R10}")

    elif arch == "mips" :
      buff += self.do_asm("addiu $sp, $sp, {}".format(-self.details["capsize"]).encode())
      buff += self.do_asm(b"sw $ra, 0($sp)")

    buff += self.inject_new_arguments()
    buff += self.do_call_pre_func()
    buff += self.realign_stack()

    if arch == "x86-64" :
      buff += self.do_asm(b"POP R10")

    elif arch == "arm" :
      buff += self.do_asm(b"POP {R10}")
      buff += self.do_asm(b"POP {LR}")

    elif arch == "mips" :
      buff += self.do_asm(b"lw $ra, 0($sp)")
      buff += self.do_asm("addiu $sp, $sp, {}".format(self.details["capsize"]).encode())

    buff += self.do_return()

    if arch == "mips" :
      if self.details["endian"] == BIG_ENDIAN :
        output = b""
        for x in range(0,len(buff), self.details["capsize"]) :
          output += buff[x:x+self.details["capsize"]][::-1]
        buff = output

    rets = hook.inject_code(buff)
    self.trampoline_l.append((rets, len(buff)))


  def inject(self, func_hooking=None, func_hooked=None, extra=None, ret_func_hooked=True) :
    """
      Hook function 'func_hooked' with 'func_hooking' using pre_func strategy Trampoline-1
    """
    assert(func_hooking != None)
    assert(func_hooked != None)
    arch = self.details["arch"]
    output = []

    stack_area = hook.mem_inj_area["stack"]
    stack_addr = stack_area["addr"]

    details_mem = extra["details_mem"]
    fname = extra["fname"]
    fname_addr = self.find_function_name_address(fname, details_mem)
    fname_length = len(extra["fname"])
    num_arg = self.get_num_arg(fname, fname_addr)

    if fname == None :
      self.details["slog"].append(
        "can't find function name address '{}' ..quit".format(extra["fname"])
      )
      return False

    args = [
      (2, func_hooking) ,\
      (4, fname_length) ,\
      (5, fname_addr) ,\
      (6, func_hooked) ,\
      (7, num_arg)
    ]

    if ret_func_hooked :
      tramp_addr = self.trampoline_l[0][0]
    else :
      tramp_addr = self.trampoline_l[1][0]
  
    if arch == "x86-64" :
      output.append("PUSH R10")
      output.append("PUSH RAX")
      output.append("MOV R10, 0x{:x}".format(stack_addr))

      for index, x in args :
        output.append("MOV RAX, 0x{:x}".format(x))
        output.append("MOV [R10+{}], RAX".format(index*self.details["capsize"]))

      output.append("POP RAX")
      output.append("MOV R10, 0x{:x}".format(tramp_addr))
      output.append("MOV [RSP-0x8], R10")
      output.append("POP R10")
      output.append("JMP [RSP-0x10]")

    elif arch == "arm" :
      output.append("PUSH {R10}")
      output.append("PUSH {R9}")
      output.append("PUSH {R0}")

      output.append(self.insert_arg_arm_inj_addr(stack_addr, "R10"))

      for index, x in args :
        output.append(self.insert_arg_arm_inj_addr(x, "R0"))
        output.append("STR R0, [R10, #{}]".format(index*self.details["capsize"]))

      output.append(self.insert_arg_arm_inj_addr(tramp_addr, "R10"))
      output.append("POP {R0}")
      output.append("POP {R9}")
      output.append("STR R10, [SP, #{}]".format(-self.details["capsize"]))
      output.append("POP {R10}")
      output.append("LDR PC, [SP, #{}]".format((-self.details["capsize"])*2))

    elif arch == "mips" :

      output.append(self.insert_arg_mips_inj_addr(stack_addr, "$t0"))

      for index,x in args :
        output.append(self.insert_arg_mips_inj_addr(x, "$t1"))
        output.append("sw $t1, {}($t0)".format(index*self.details["capsize"]))

      to_reg=special_regs["mips_gp"]
      output.append(self.insert_arg_mips_inj_addr(tramp_addr, to_reg))
      output.append("jr {}".format(to_reg))

    else :
      self.details["slog"].append(
        "[x] not supported!"
      )

    code = "; ".join(output).encode()
    buff = self.do_asm(code)

    if arch == "mips" :
      if self.details["endian"] == BIG_ENDIAN :
        output = b""
        for x in range(0,len(buff), self.details["capsize"]) :
          output += buff[x:x+self.details["capsize"]][::-1]
        buff = output

    rets = hook.inject_code(buff)
    self.inj_point_l.append(InjPoint(rets, len(buff), func_hooked, [func_hooking], ONLY_PRE_FUNC))
    return rets


  def dichotomic_search_x64(self):
    """
      TODO: to move out on a custom class then create function with namespace "internal.*"

      This is the dichotmic search optimized for intel x86-64
      
      Arguments required:
        RDI := element to find
        RSI := size list
        RDX := pointer to list
    """
    start_point = [
      "MOV RCX, 0"
    ]
    search_loop = [
      "CMP RCX, RDX" ,\
      ("JG", 2, "not_found") ,\
    ]
    #
    calculate_point = [
      "MOV RAX, RSI" ,\
      "SUB RAX, RCX" ,\
      "SHR RAX, 1" ,\
      "ADD RAX, RCX" ,\
      "MOV R10, [RDX + RAX * 4]" ,\
      "CMP RDI, R10" ,\
      ("JE", 2, "found")
    ]
    #
    calculate_point_2 = [
      ("JL", 2, "lower_loop") ,\
    ]
    #
    upper_loop = [
      "MOV RCX, RAX" ,\
      "ADD RCX, 1" ,\
      ("JMP", 5, "search_loop") ,\
    ]
    #
    lower_loop = [
      "MOV RSI, RAX" ,\
      "SUB RSI, 1" ,\
      ("JMP", 5, "search_loop") ,\
    ]
    # 
    not_found = [
      "MOV RAX, -1"
    ]
    # 
    found = [
      "MOV RAX, 0"
    ]
    #
    assembly_code_list = [
      "search_loop" ,\
      "calculate_point" ,\
      "calculate_point_2" ,\
      "upper_loop" ,\
      "lower_loop" ,\
      "not_found" ,\
      "found" ,\
    ]
    #
    assembly_code_size = { }
    for x in assembly_code_list :
      l = locals()[x]
      size = 0
      for i in l :
        if isinstance(i, str) :
          size += len(self.assembler.asm(i)[0])
        else :
          size += i[1]
      assembly_code_size.update(
        {x : size}
      )
    #
    # solve relative jmps
    for x in assembly_code_list :
      l = locals()[x]
      for i, y in enumerate(l) :
        if not isinstance(y, str) :
          #
          if y[1] == 2 :
            size_list_keys = assembly_code_list[ \
              assembly_code_list.index(x) + 1 :\
              assembly_code_list.index(y[2]) \
            ]
            #print(
            #  x, y, [ (k,assembly_code_size[k]) for k in size_list_keys ]
            #)
            #
            relative_val = sum(
              [ assembly_code_size[k] for k in size_list_keys ]
            )
          #
          # negativa jmp near (occupies 5 bytes)
          else :
            size_list_keys = assembly_code_list[ \
              assembly_code_list.index(y[2]) :\
              assembly_code_list.index(x) \
            ]
            relative_val = 2**32 - sum(
              [ assembly_code_size[k] for k in size_list_keys ]
            )
          #
          l[i] = f"{y[0]} {hex(relative_val)}"
    #
    output = []
    for x in assembly_code_list :
      l = locals()[x]
      #print(x, l)
      output += l
    #
    data = self.assembler.asm(";".join(output))[0]
    output_b = b""
    for x in list(map(lambda x : x.to_bytes(1, byteorder='big'), data)) :
      output_b += x
    #
    #print(assembly_code_size)
    with open(f"{tmp_folder}/dichotomic_search.asm", "wb") as fp :
      fp.write(output_b)








