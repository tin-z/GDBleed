# -*- coding: utf-8 -*-

"""
Inline hooking
"""
import struct


import hook
from hook.default_hooks import *

from hook.inline_objects import InjPoint
from hook._constants import   ONLY_PRE_FUNC ,\
                              ONLY_POST_FUNC ,\
                              ALL_FUNC ,\
                              RET_PRE_FUNC ,\
                              RET_POST_FUNC

from core.constants import *
from utils.gdb_utils import search_string ,\
                            gdbapi_write

from core.disasm.disasm import WrapDisasm

from config import  tmp_folder ,\
                    LITTLE_ENDIAN ,\
                    BIG_ENDIAN


from core.parser.objects import TypePointer ,\
                                TypeLongLong ,\
                                TypeInt

from core.parser.wrap_parser import WrapParser
from core.parser.wrap_objects import InternalFunction


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
      output.append("MOV R10, 0x{:x}".format(stack_addr))
      for x in range(6,3,-1) :
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



######################
### Gdbcov part

  def __init_gdbcov(self, disasm_strategy):
    self.disasm = WrapDisasm(
      self.details, 
      self.details_data, 
      strategy=disasm_strategy
    )
    self.disasm.init()
    self.gdbcov_init_data = False
    self.gdbcov_init_trampoline = False
    self.gdbcov_trampoline_l = []
    self.gdbcov_inj_point_l = []


  def init_gdbcov_data(self, details_mem):
    arch = self.details["arch"]
    if self.gdbcov_init_data :
      return

    # Because we are creating a bitmap instead of indexing it by all the space address 
    # we rebase it by substractng the first non-executable sections
    executable_offset = self.details_data["executable_offset"]    
    executable_size = self.details_data["executable_size"]    
    baddr = self.details_data["base_address"]

    jump_types = JCC_types[arch]
    jump_types = [ (x,chr(i+1).encode()) for i,x in enumerate(jump_types) ]

    branches = self.disasm.get_conditional_branches()
    branches = [ 
      y[1] for y in sorted(
        [(x.arg_offset + x.arg_size, x) for x in branches], 
        key=lambda x: x[0]
      )
    ]

    # len_call_ax = len(b"\x66\xFF\xD0")  # wrong: even if you use call ax on 64 mode it will use all rax
    # solution: use the following stub
    # 0:  6a 00                   push   0x0
    # 2:  ff 14 24                call   QWORD PTR [rsp] 

    len_stub_instr = 5
    branches_index = {((x.arg_offset + len_stub_instr) - executable_offset):i for i,x in enumerate(branches)}

    output = [b"\x00" for _ in range(executable_size)]  # 1. gdbcov_list_bitmap (default value)

    for index_offset, index_branch in branches_index.items() :
      branch = branches[index_branch]
      jump_type = None
      #
      for k,v in jump_types :
        if branch.arg_jump_type in k :
          jump_type = v
          break
      #
      assert(jump_type != None)
      output[index_offset] = jump_type


    self.details["slog"].append(
      "[+] bitmap created"
    )
 
    # Note 1:
    # dynamically trampoline will get the index by doing: (return_address - base_address) - executable_offset
    # questo valore poi lo salvo e lo riuso nella dichotomic
    index_list = []                               # 2. gdbcov_list_indexes
    jump_list = []                                # 3. gdbcov_list_jump
    pack = "<L" if self.details["endian"] == LITTLE_ENDIAN else ">L"

    instr_max_bytes = 0
    instr_2_bytes = 0
    instr_2_bytes_counter = {'jmp':0, 'cjmp':0, 'call':0, 'rip':0, 'rsp':0}

    for branch in branches :

      # skip less than 5-bytes jcc
      if branch.arg_size < 5 :
        instr_2_bytes += 1

        if branch.arg_fail_type in ['jmp', 'cjmp', 'call'] :
          instr_2_bytes_counter[branch.arg_fail_type] += 1

        elif "rip" in branch.arg_fail_opcode or "rsp" in branch.arg_fail_opcode :
          if "rip" in branch.arg_fail_opcode :
            instr_2_bytes_counter["rip"] += 1
          elif "rsp" in branch.arg_fail_opcode :
            instr_2_bytes_counter["rsp"] += 1

        else :
          # print(branch)
          pass

      else :
        if branch.arg_size > instr_max_bytes :
          instr_max_bytes = branch.arg_size

        # update offsets
        branch.arg_fail = (branch.arg_offset + len_stub_instr) - executable_offset
        branch.arg_jump -= executable_offset
        #
        jump_list.append(struct.pack(pack, branch.arg_jump))
        index_list.append(struct.pack(pack, branch.arg_fail))

    instr_2_bytes_ok = instr_2_bytes - sum([v for v in instr_2_bytes_counter.values()])
    instr_2_bytes_ok_bytes = (instr_max_bytes * instr_2_bytes_ok) + (5 * instr_2_bytes_ok) # jmp rel32 5 bytes "\xe9<dw>"
    #
    print(
      "\n" +\
      "[+] Jcc status:\n" +\
      f" \---> Conditional branch instructions occupying 5 or more bytes: {len(branches) - instr_2_bytes}\n" +\
      f" \---> non-instrumentable 4-bytes branch instructions: {instr_2_bytes}\n"
    )
    #print(f" \---> Conditional branch instructions occupying 2 bytes: {instr_2_bytes}")
    #print(f" \---> Conditional branch instructions occupying 2 bytes that are instrumentable: {instr_2_bytes_ok}")
    #print(f" \---> Largest instruction in bytes to instrument after overwriting 2-bytes branch next instruction: {instr_max_bytes}")
    #print(f" \---> Required bytes to adjust overwritten opcodes in 2-bytes branch instrumentation: {instr_2_bytes_ok_bytes}")
    #print( " \---> Non-instrumentable 2-bytes branches detail: ", instr_2_bytes_counter)
    ##
    self.gdbcov_list_bitmap = b"".join(output)
    self.gdbcov_list_bitmap_size = len(self.gdbcov_list_bitmap)         # 1 byte per entry
    self.gdbcov_list_bitmap_addr = None
    self.gdbcov_list_indexes = b"".join(index_list)
    self.gdbcov_list_indexes_size = len(self.gdbcov_list_indexes)       # 4 byte per entry
    self.gdbcov_list_indexes_addr = None
    self.gdbcov_list_jump = b"".join(jump_list) 
    self.gdbcov_list_jump_size = len(self.gdbcov_list_jump)             # 4 byte per entry
    self.gdbcov_list_jump_addr = None
    #
    self.gdbcov_data_size = \
      self.gdbcov_list_bitmap_size +\
      4 - (self.gdbcov_list_bitmap_size % 4) +\
      self.gdbcov_list_indexes_size +\
      4 - (self.gdbcov_list_indexes_size % 4) +\
      self.gdbcov_list_jump_size +\
      4 - (self.gdbcov_list_jump_size % 4)
    #
    rets = hook.init_gdbcov_data(
      self.details ,\
      details_mem ,\
      self.details_data ,\
      self.gdbcov_data_size
    )
    #
    if rets == None :
      raise Exception("[X] Can't initialize gdbcov data section")
    #
    self.details["slog"].append(
      f"[+] gdbcov data size '0x{self.gdbcov_data_size:x}' allocated at '0x{rets:x}'"
    )
    #
    # Now allocate space for gdbcov data (bitmap + index table + return address  table)
    self.gdbcov_list_bitmap_addr = \
      hook.inject_gdbcov_data(self.gdbcov_list_bitmap)
    self.details["slog"].append(
      f"[+] self.gdbcov_list_bitmap_addr var declared at address '0x{self.gdbcov_list_bitmap_addr:x}'"
    )
    #
    self.gdbcov_list_indexes_addr = \
      hook.inject_gdbcov_data(self.gdbcov_list_indexes)
    self.details["slog"].append(
      f"[+] self.gdbcov_list_indexes_addr var declared at address '0x{self.gdbcov_list_indexes_addr:x}'"
    )
    #
    self.gdbcov_list_jump_addr = \
      hook.inject_gdbcov_data(self.gdbcov_list_jump)
    self.details["slog"].append(
      f"[+] self.gdbcov_list_jump_addr var declared at address '0x{self.gdbcov_list_jump_addr:x}'"
    )
    #
    for x in ["gdbcov_list_bitmap", "gdbcov_list_indexes", "gdbcov_list_jump"] :
      size = str(getattr(self, f"{x}_size"))
      addr = getattr(self, f"{x}_addr")
      var = TypePointer(
        x ,
        size ,
        0 ,
        f"blob {x} = {size};" ,
        addr
      )
      var.set_blob(size)
      self.details_data["parser"].update_globals(
        var,
        is_data=True
      )

    val = hex(baddr + executable_offset)
    var_name = "gdbcov_base_address"
    var = TypeLongLong(
      var_name ,\
      val ,\
      0 ,\
      f"unsigned long long {var_name} = {val};",\
      system_is64bit=True
    )
    #
    self.details_data["parser"].update_globals(
      var,
      is_data=True
    )
    #
    val = hex(executable_size)
    var_name = "gdbcov_shmem_size"
    var = TypeInt(
      var_name ,\
      val ,\
      0 ,\
      f"unsigned int {var_name} = {val};"
    )
    #
    self.details_data["parser"].update_globals(
      var,
      is_data=True
    )
    #
    val = hex(self.gdbcov_list_indexes_size)
    var_name = "gdbcov_list_indexes_size"
    var = TypeInt(
      var_name ,\
      val ,\
      0 ,\
      f"unsigned int {var_name} = {val};"
    )
    #
    self.details_data["parser"].update_globals(
      var,
      is_data=True
    )
    #
    self.init_gdbcov_data_2(details_mem)
    self.gdbcov_init_data = True


  def init_gdbcov_data_2(self, details_mem):
    wrap_parser = self.details_data["parser"]
    parser = wrap_parser.parser
    obj_factory = parser.fy.factory

    # 1. This value serves to know if agent and so shared memory were already initialized
    var1 = ("unsigned char", "gdbcov_init", "0")
    # 2. shared memory key, pointing to the status + code coverage map shared memory address
    var2 = ("unsigned short", "gdbcov_shmem_key", "0x7331")
    var3 = ("int", "gdbcov_shmem_id", "0")
    # 3. shm permissions
    var4 = ("int", "gdbcov_shmem_flg", "438") # 0666 
    # 4. Defines the size of each entry of the map coverage, default is 2^(8 * gdbcov_shmem_size_entry)
    # // Right now is not used, but in future we might need this because of the limitations on the cod coverage counter
    var5 = ("unsigned short", "gdbcov_shmem_size_entry",  "0x1")
    # 5. pid of the agent and the main process
    var6 = ("unsigned int", "gdbcov_pidagent", "0x0")
    var7 = ("unsigned int", "gdbcov_pidmain", "0x0")
    # 6. address-port agent listening to 
    var8 = ("unsigned short", "gdbcov_agent_port", "3134")
    var9 = ("unsigned int", "gdbcov_agent_ip",  "0")
    # 7. address-port server collecting coverages from agent listening to
    var10 = ("unsigned short", "gdbcov_server_port", "4313")
    var11 = ("unsigned int", "gdbcov_server_ip", "0")
    # 8. keep track of agent errors
    var12 = ("unsigned short", "gdbcov_agent_error", "0")
    # 9. time in seconds after which agent sends coverage to server
    var13 = ("unsigned short", "gdbcov_agent_timeout", "3")

    var_list = [
      var1 ,\
      var2 ,\
      var3 ,\
      var4 ,\
      var5 ,\
      var6 ,\
      var7 ,\
      var8 ,\
      var9 ,\
      var10 ,\
      var11 ,\
      var12 ,\
      var13 ,\
    ]

    for var in var_list :
      var_type, var_name, var_value = var
      var_line = f"{var_type} {var_name} = {var_value};"
      var_obj = obj_factory(var_type, var_name, var_value, line=var_line)
      self.details_data["parser"].update_globals(
        var_obj,
        is_data=True
      )
 

  def gdbcov_check_bitmap_jcc(self):
    """
      For intel 
        RAX : 0 if branch not taken
        R10 : bitmap index 

    """
    arch = self.details["arch"]
    jcc_type = JCC_types[arch]
    buff = b""

    if arch == "x86-64" :
      len_instr = 4
      relative_offset = sum([2 + len(self.do_asm(f"{jcc[0]} 129")) for jcc in jcc_type])

      # calc the right index
      buff += self.do_asm( "POPFQ")
      buff += self.do_asm( "PUSH RBX")
      buff += self.do_asm( "PUSHFQ")
      buff += self.do_asm(f"MOV RBX, {len_instr}")
      buff += self.do_asm( "MUL BL")
      buff += self.do_asm( "MOV BL, AL")
      buff += self.do_asm( "LEA RAX, [RIP+6]")
      buff += self.do_asm( "ADD RAX, RBX") # 3 bytes
      buff += self.do_asm( "POPFQ") # 1 byte
      buff += self.do_asm( "JMP RAX") # 2 bytes
      buff += b"\x90" * len_instr # first index is empty
      
      cumulative_offset = 0

      for i, jcc in enumerate(jcc_type) :
        jcc = jcc[0]

        jcc_offset = (relative_offset - cumulative_offset) + 3

        buff += self.do_asm(
          f"{jcc} {jcc_offset};\n"
        )
        buff_tmp = self.do_asm(f"{jcc} {jcc_offset}")
        cumulative_offset += len(buff_tmp)

        if i == len(jcc_type) - 1 :
          buff += b"\x90\x90"
        
        else :
          buff += b"\xEB" + bytes([(relative_offset - cumulative_offset) - 2])
        cumulative_offset += 2

      buff += self.do_asm(
        "XOR RAX, RAX;\n" +\
        "NOP;\n"
      )
    return buff


  def gdbcov_check_bitmap(self, got_target):
    """
      For intel 
        RAX : bitmap value
        R10 : bitmap index 

    """
    arch = self.details["arch"]
    executable_offset = self.details_data["executable_offset"]    
    baddr = self.details_data["base_address"]

    buff = b""
    buff2 = b""

    if arch == "x86-64" :
      buff2 = self.do_asm( \
        "POPFQ;\n" +\
        "POP RAX;\n" +\
        f"MOV R10, 0x{got_target:x};\n" +\
        "PUSH R10;\n" +\
        "POP R10;\n" +\
        "POP R10;\n" +\
        "JMP [RSP-0x10];\n"
      )

      buff += self.do_asm("MOV R10, [RSP+0x10]")
      buff += self.do_asm("MOV RAX, 0x{:x}".format(baddr + executable_offset))
      buff += self.do_asm("PUSHFQ") # save eflag before any arithmetic operation
      buff += self.do_asm("SUB R10, RAX") 
      buff += self.do_asm("MOV RAX, 0x{:x}".format(self.gdbcov_list_bitmap_addr))
      buff += self.do_asm("MOV RAX, [RAX+R10]")
      buff += self.do_asm("TEST AL, AL")

      buff_tmp = self.do_asm("JNZ 0x{:x}".format(len(buff2)))

      buff += self.do_asm("JNZ 0x{:x}".format(len(buff2)+len(buff_tmp)))
      buff += buff2

    return buff


  #def gdbcov_return_nearjcc(self, instr_bytes, max_bytes, j32_size=5):
  #  #
  #  #
  #  #
  #  # C'è un problema:   cioè, cosa succede se una call o jmp salta verso un basic block che però era di una near jcc e quindi
  #  # l'istruzione è sovrascritta ... :(
  #  # SOLUZIONE: con r2 guardo code reference, se istruzione dopo è referenziata skippo
  #  #   \---> Problema 2: jmp/call può essere con registro e quindi non viene vista... meglio lasciare stare jcc 2bytes ..
  #  #
  #  # SOLUZIONE FINALE: Per jcc 2-bytes prendo target basic block, guardo primi 5 byte istruzione, se non contengono RIP, RSP, CALL, e JMP allora instrumento direttamente basic block
  #  # ANZI faccio per tutti jcc, 
  #  # 
  #  # SOUZIONE FINALE: Creo due tipi di instrumentation per intel, il primo converto le jcc in call, il secondo call all'inizio di basic block
  #  #    per il problem di prima le istruzioni jcc dovranno essere supportate solo per basic block instrumentation type
  #  #
  #  #
  #  # jmp bb1
  #  # 
  #  # bb1: Basic block:
  #  #   call ax (3 bytes)
  #  #   nops (n bytes)
  #  #   instr i 
  #  #   ...

  #  relative_offset = len(instr_list) * (max_bytes + j32_size)
  #  buff = b""

  #  for i, instr in enumerate(instr_list) :
  #    # instr already in bytes format
  #    buff_tmp = instr
  #    buff += buff_tmp

  #    for _ in range(max_bytes - len(buff_tmp)) :
  #      buff += self.do_asm("NOP")

  #    buff_tmp = self.do_asm(
  #      "JMP $+{};\n".format((relative_offset - (i*(max_bytes+j32_size))))
  #    )
  #    buff += buff_tmp

  #    assert(len(buff_tmp) <= j32_size)

  #    for _ in range(j32_size - len(buff_tmp)) :
  #      buff += self.do_asm("NOP")

  #  buff += self.do_asm("RET")
  #  return buff



  def init_gdbcov_trampoline(self, details_mem, got_target):
    arch = self.details["arch"]
    if not self.gdbcov_init_data :
      raise Exception("gdbcov data section not initialized")
    if self.gdbcov_init_trampoline :
      return

    executable_offset = self.details_data["executable_offset"]    
    baddr = self.details_data["base_address"]

    buff = b""
    buff += self.gdbcov_check_bitmap(got_target)
    buff += self.gdbcov_check_bitmap_jcc()
    buff += self.gdbcov_inject_arguments()

    rets = hook.inject_code(buff)
    self.gdbcov_trampoline_l.append((rets, len(buff)))

    print(f"HEREEEEEEEE ADDR: 0x{rets:x}")

    self.init_gdbcov_trampoline_0address_x86(rets)
    self.gdbcov_dichotomic_search()
    self.gdbcov_init_trampoline = True


  def init_gdbcov_trampoline_0address_x86(self, addr_trampoline):
    buff = b""

    # Old solution:
    # Because of 'call ax' i thought that we will jmp in space address between 0-0xffff and so instead of wasting cpu cycles with NOPs
    # i used the idea of spamming short JMPs that have the opcode in the range [0x70:0x7F] and also giving as argumnent the same value of the operand
    # by doing so we assure that at least one of the jcc is true and so we'll speed up instead of executing 0xffff NOPs in the worst case scenario
    #
    #jcc_2bytes_opcode = b""
    #for x in range(0x7F, 0x6F, -1) :
    #  x = chr(x).encode() * 2
    #  jcc_2bytes_opcode += x
    #buff += jcc_2bytes_opcode * (2**16 // len(jcc_2bytes_opcode)) + b"\x90" # last instr could be a jump to negative offset, but it's fine
    #buff += b"\x90" * 0x81 # last 0x81 bytes are nops because of the conditional jumps that were put above

    buff += self.do_asm("PUSH R10")
    buff += self.do_asm("PUSH RAX")
    buff += self.do_asm(f"MOV RAX, {hex(addr_trampoline)}")
    buff += self.do_asm("JMP RAX")
    rets = hook.inject(buff, "0")


  def gdbcov_inject_arguments(self):
    stack_area = hook.mem_inj_area["stack"]
    stack_addr = stack_area["addr"]
    arch = self.details["arch"]
    sp_arg = self.regs_["pre_regs"].sp_pivot * self.details["capsize"]
    output = []
 
    if arch == "x86-64" :
      output.append("MOV RBX, 0x{:x}".format(stack_addr))

      # 2 :- save branch not taken flag
      index = 2
      output.append("MOV [RBX+{}], RAX".format(index*self.details["capsize"]))
      # 3 :- bitmap index
      index = 3
      output.append("MOV [RBX+{}], R10".format(index*self.details["capsize"]))
      # 4 :- struct registers saved on sp pointer
      index = 4
      delta = 3 # pop rbx, rax, r10
      output.append("LEA RAX, [RSP-0x{:x}]".format((sp_arg + (delta*self.details["capsize"]))))
      output.append("MOV [RBX+{}], RAX".format(index*self.details["capsize"]))
 
      # 5 :- branch to take after returning from hookng point
      #       as default we insert the branch not taken which is the return address, then the user
      #       can change this value
      index = 5
      delta = 3 # pop rbx, rax, r10
      output.append("MOV RAX, [RSP+0x{:x}]".format((delta*self.details["capsize"])))
      output.append("MOV [RBX+{}], RAX".format(index*self.details["capsize"]))

      # 6 :- gdbcov function hooking
      # SOLUZIONE: quì inserisco valore dummy su stack_addr[8] che rappresenta la funzione a cui saltiamo, però uso gdb non istruzioni assembly
      # per fare ciò ho aggiunto apposta una nuova entry sullo stack, quindi funzia
      # index = 8

      # adjust everything
      output.append(
        "POP RBX;" +\
        "POP RAX;" +\
        "POP R10;"
      )

    code = "; ".join(output).encode()
    buff = self.do_asm(code)
    buff += self.regs_["pre_regs"].inject_code
    output = []

    if arch == "x86-64" :
      # 1: rdi -> 'stack_addr'
      output.append("MOV RDI, 0x{:x}".format(stack_addr))
      # 2: rsi -> branch not taken flag
      index = 2
      output.append("MOV RSI, [RDI+{}]".format(index*self.details["capsize"]))
      # 3: rdx -> bitmap index
      index = 3
      output.append("MOV RDX, [RDI+{}]".format(index*self.details["capsize"]))
      # 4 :- struct registers saved on sp pointer
      index = 4
      output.append("MOV RCX, [RDI+{}]".format(index*self.details["capsize"]))
      # jmp to function instrumenting
      index = 8
      output.append("MOV R8, [RDI+{}]".format(index*self.details["capsize"]))
      output.append("CALL R8")

    code = "; ".join(output).encode()
    buff += self.do_asm(code)

    # jump to branch not taken if stack_addr[2] is 0
    # otherwise jump to branch taken which is saved on stack_addr[2]
    buff += self.regs_["post_regs"].inject_code
    output = []

    if arch == "x86-64" :
      output.append("PUSH RBX")
      output.append("MOV RBX, 0x{:x}".format(stack_addr))
      index = 5
      output.append("MOV RBX, [RBX+{}]".format(index*self.details["capsize"]))
      output.append("MOV [RSP+0x10], RBX")    # save return address where is located '0'
      output.append("POP RBX")
      output.append("LEA RSP, [RSP+0x8]")     # get rid of one extra push without using arithmetic instructions
      output.append("RET")

    code = "; ".join(output).encode()
    buff += self.do_asm(code)

    return buff


  def gdbcov_set_trace(self, addr):
    if not self.gdbcov_init_data :
      raise Exception("Gdbcov's data is not initialized")
    if not self.gdbcov_init_trampoline :
      raise Exception("Gdbcov's trampoline point is not initialized")

    arch = self.details["arch"]
    baddr = self.details_data["base_address"]
    endian = "little" if self.details["endian"] == LITTLE_ENDIAN else "big"
    capsize = self.details["capsize"]
    index = 8
    stack_addr = hook.mem_inj_area["stack"]["addr"] + (capsize*index)
    value_bytes = addr.to_bytes(capsize, byteorder=endian)

    gdbapi_write(stack_addr, value_bytes)

    print(f"[+] {hex(stack_addr)} == {hex(addr)}")

    branches = self.disasm.get_conditional_branches()

    if arch == "x86-64" :
      
      stub_instr = b"\x6a\x00\xff\x14\x24" # push 0x0; call QWORD PTR [rsp] 
      len_stub_instr = len(stub_instr)

      for branch in branches :
        if branch.arg_size == 2 :
          continue

        gdbapi_write(
          branch.arg_offset + baddr ,\
          stub_instr + (b"" if branch.arg_size <= len_stub_instr else b"\x90" * (branch.arg_size - len_stub_instr))
        )


  def gdbcov_dichotomic_search(self):
    """
      Unused for now, instead declare and use 'plugins/code_cov/gdbcov_dichotomic.c.bleed'
    """
    return
    arch = self.details["arch"]
    wrap_parser = self.details_data["parser"]
    parser = wrap_parser.parser
    obj_factory = parser.fy.factory

    buff = b""
    instr = ""

    if arch == "x86-64" :
      instr, buff = self.dichotomic_search_x64()

    addr_func = hook.inject_code(buff)

    func_Id = WrapParser.Id
    WrapParser.Id += 1
    namespace, func_name = "gdbcov", "dichotomic_search"
    description = "Optimized dichtomich search"
    decl = "unsigned long dichotomic_search(unsigned long find, unsigned long size, unsigned long * list) {"

    func_object = InternalFunction(
      func_Id, func_name,
      namespace, description,
      decl
    )

    func_object.update_declare_lists(
      [] ,
      [] ,
      [] ,
      "\n/*\n" + instr.replace(";", "\n    ") + "\n*/\n }"
    )

    func_object.update_addr_func(addr_func, buff)
    wrap_parser.update_globals(func_object)


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
      output += l
    #
    output = ";".join(output)
    data = self.assembler.asm(output)[0]
    output_b = b""
    for x in list(map(lambda x : x.to_bytes(1, byteorder='big'), data)) :
      output_b += x
    #
    return output, output_b
    #with open(f"{tmp_folder}/dichotomic_search.asm", "wb") as fp :
    #  fp.write(output_b)




