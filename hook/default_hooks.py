# -*- coding: utf-8 -*-
import keystone
import hook

from core.constants import *
from utils.gdb_utils import find_function_addr, search_string


class HookItAgain :
  """
    The child classes should change the method *_code
  """

  arch_keystone = {
    "arm" : (keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM) ,\
    "x86-64" : (keystone.KS_ARCH_X86, keystone.KS_MODE_64) ,\
    "mips" : (keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32)
  }

  mips_regs_to_save = \
  [
    "$t{}".format(x) for x in range(10) 
  ] + [
    "$a{}".format(x) for x in range(4)
  ] + [
    "$v{}".format(x) for x in range(2)
  ] + [
    "$ra" 
  ]

  def __init__(self, details) :
    self.details = details
    self.assembler = keystone.Ks(*HookItAgain.arch_keystone[self.details["arch"]])
    self.inject_arch = {"x86-64":self.x86_64_code, "arm":self.arm_code, "mips":self.mips_code}
    self.inject_code = self.inject_arch[self.details["arch"]]()

  def cast_bytes(self, data) :
    output = b""
    for x in list(map(lambda x : x.to_bytes(1, byteorder='big'), data)) :
      output += x
    return output

  def do_asm(self, code):
    encoding, count = self.assembler.asm(code)
    return self.cast_bytes(encoding)

  def x86_64_code(self) :
    pass

  def arm_code(self) :
    pass

  def mips_code(self) :
    pass


class Pre_regs(HookItAgain) :
  """
      Save registers before function calls 
  """

  def x86_64_code(self) :
    code = [
      "PUSHFQ" ,\
      "PUSH RAX" ,\
      "PUSH RCX" ,\
      "PUSH RDX" ,\
      "PUSH RBX" ,\
      "PUSH RBP" ,\
      "PUSH RSI" ,\
      "PUSH RDI" ,\
      "PUSH R8" ,\
      "PUSH R9" ,\
      "PUSH R10" ,\
      "PUSH R11" ,\
      "PUSH R12" ,\
      "PUSH R13" ,\
      "PUSH R14" ,\
      "PUSH R15"
    ]
    self.sp_pivot = len(code)
    code = "; ".join(code).encode()
    return self.do_asm(code)

  def arm_code(self) :
    code = b"STMDB SP!, {R0,R1,R2,R3,R4,R5,R6,R7,R8,R9,R10,R11,LR}"
    self.sp_pivot = len(code.split(b",")[1:]) + 1
    code += b"; " + b"PUSH {R12}"
    return self.do_asm(code)

  def mips_code(self) :
    code = [
      "sub $sp, $sp, {}".format(len(HookItAgain.mips_regs_to_save) * self.details["capsize"])
    ] + [
      "sw {}, {}($sp)".format(x, i*self.details["capsize"]) for i,x in enumerate(HookItAgain.mips_regs_to_save)
    ]
    self.sp_pivot = len(HookItAgain.mips_regs_to_save)
    code = "; ".join(code).encode()
    return self.do_asm(code)


class Post_regs(HookItAgain) :
  """
      Restore registers after function calls 
  """

  def x86_64_code(self) :
    code = [
      "POP R15" ,\
      "POP R14" ,\
      "POP R13" ,\
      "POP R12" ,\
      "POP R11" ,\
      "POP R10" ,\
      "POP R9" ,\
      "POP R8" ,\
      "POP RDI" ,\
      "POP RSI" ,\
      "POP RBP" ,\
      "POP RBX" ,\
      "POP RDX" ,\
      "POP RCX" ,\
      "POP RAX" ,\
      "POPFQ"
    ]
    code = "; ".join(code).encode()
    return self.do_asm(code)

  def arm_code(self) :
    code = b"POP {R12}"
    code += b"; " + b"LDMIA SP!, {R0,R1,R2,R3,R4,R5,R6,R7,R8,R9,R10,R11,LR}"
    return self.do_asm(code)

  def mips_code(self) :
    code = [
      "lw {}, {}($sp)".format(x, i*self.details["capsize"]) for i,x in enumerate(HookItAgain.mips_regs_to_save)
    ] + [
      "addi $sp, $sp, {}".format(len(HookItAgain.mips_regs_to_save) * self.details["capsize"])
    ]
    code = "; ".join(code).encode()
    return self.do_asm(code)


class GeneralHook (HookItAgain) :
  """
    Basic assembly blocks used to change the control flow

    This class implements the code injection template 
        (1.) save_registers
        (2.) Code that do stuff
        (3.) restore_registers
        (4.) jump to the hooked function and then return to caller

    (2.): this part must be implemented by the inhereted classes 
    (e.g Sleep class). Another option is to write by-hand 'self.inject_code'

    The basic idea is that we don't write excessive assembly code.
    Instead we re-use library functions 
  """

  def __init__(self, details, details_data, regs_, fname=None) :
    """
      fname : Name of the function which will hook the other functions
    """
    assert(fname != None)
    self.fname = fname.strip()

    # before calling super set 'addr'
    self.details = details
    self.__set_addr()

    super(GeneralHook, self).__init__(details)
    self.details_data = details_data
    self.regs_ = regs_

  def __set_addr(self):
    self.decl, self.addr = find_function_addr(self.fname, self.details)


  def insert_arg_arm_inj_addr(self, addr, register) :
    code, _ = self.arm_inj_addr(addr, to_reg=register)
    return code
  
  def do_call_x86_64(self, addr, to_reg="RAX") :
    """
      x86_64

      Perform call to 'addr' using register 'to_reg'
    """
    code = "MOV {1}, 0x{0:x}; CALL {1}".format(addr, to_reg)
    return code

  def do_call_arm_inj_addr(self, addr, to_reg="R10") :
    """
      arm

      Perform call to 'addr' using register 'to_reg'
    """
    code, _ = self.arm_inj_addr(addr, to_reg=to_reg)
    code += "; " + "BLX {}".format(to_reg)
    return code

  def do_jmp_arm_inj_addr(self, addr, to_reg="R10") :
    """
      arm

      Perform jmp to 'addr' using register 'to_reg' and restoring its initial value
    """
    code, tmp_regs = self.arm_inj_addr(addr, to_reg=to_reg)

    tmp_code = ""        
    for x in tmp_regs :
      tmp_code += "; " + "PUSH {" + x + "}"
    tmp_code = tmp_code[2:]

    code = tmp_code + "; " + code

    code += "; " + "STR {}, [SP, #{}]".format(to_reg, -self.details["capsize"])

    tmp_code = ""        
    for x in tmp_regs[::-1] :
      tmp_code += "; " + "POP {" + x + "}"
    tmp_code = tmp_code[2:]

    code += "; " + tmp_code
    code += "; " + "LDR PC, [SP, #{}]".format( (-self.details["capsize"])*(len(tmp_regs) + 1) )
    return code


  def arm_inj_addr(self, addr, from_reg="R10", to_reg="R10", tmp_reg="R9") :
    """
      arm

      Insert value 'addr' into register 'to_reg'

      Return text code and registers modified
    """
    data_addr = addr

    tmp_regs = [from_reg, to_reg, tmp_reg]
    code = ""
    code += "; " + "MOV {}, #0x{:x}".format(to_reg, (data_addr & 0xff))
    for x in [8, 16, 24] :
      code += "; " + "MOV {}, #0x{:x}".format(tmp_reg,  ((data_addr >> x) & 0xff))
      code += "; " + "ORR {}, {}, {}, LSL #{}".format(to_reg, to_reg, tmp_reg, x)

    code = code[2:] 
    return code, tmp_regs


  def insert_arg_mips_inj_addr(self, addr, register) :
    code, _ = self.mips_inj_addr(addr, to_reg=register)
    return code

  def do_call_mips_inj_addr(self, addr, to_reg=special_regs["mips_gp"]) :
    """
      mips

      Perform call to 'addr' using register 'to_reg'
    """
    code, _ = self.mips_inj_addr(addr, to_reg=to_reg)
    code += "; " + "jalr {}".format(to_reg)
    return code

  def do_jmp_mips_inj_addr(self, addr, to_reg=special_regs["mips_gp"]) :
    """
      mips

      Perform jmp to 'addr' using register 'to_reg'
    """
    code, _ = self.mips_inj_addr(addr, to_reg=to_reg)
    code += "; " + "jr {}".format(to_reg)
    return code

  def mips_inj_addr(self, addr, to_reg="$t0") :
    """
      mips

      Insert value 'addr' into register 'to_reg'

      Return text code and registers modified
    """
    tmp_regs = [to_reg]
    code = ""
    code += "; " + "lui {}, 0x{:x}".format(to_reg, (addr >> 16) & 0xffff)
    code += "; " + "addiu {}, {}, 0x{:x}".format(to_reg, to_reg, addr & 0xffff)
    code = code[2:] 
    return code, tmp_regs

  def mips_code(self) :
    code = self.do_call_mips_inj_addr(self.addr).encode()
    return self.do_asm(code)

  def arm_code(self) :
    code = self.do_call_arm_inj_addr(self.addr).encode()
    return self.do_asm(code)

  def x86_64_code(self) :
    code = self.do_call_x86_64(self.addr).encode()
    return self.do_asm(code)

  def insert_arg(self, args) :
    """
      Simulate the calling to a function using the right calling convention

      #TODO :
        - support arguments given by stack
    """
    code = b""
    arch = self.details["arch"]
    if arch == "x86-64" :
      for i,v in enumerate(args) :
        code += "; MOV {}, 0x{:x}".format(CALL_CONVENTION[arch][i], v).encode()

    elif arch == "arm" :
      for i,v in enumerate(args) :
        if v > 0xffff :
          code += ("; " + self.insert_arg_arm_inj_addr(v, CALL_CONVENTION[arch][i])).encode()
        else :
          code += "; MOV {}, #0x{:x}".format(CALL_CONVENTION[arch][i], v).encode()

    elif arch == "mips" :
      for i,v in enumerate(args) :
        if v > 0xffff :
          code += ("; " + self.insert_arg_mips_inj_addr(v, CALL_CONVENTION[arch][i])).encode()
        else :
          code += "; li {}, 0x{:x}".format(CALL_CONVENTION[arch][i], v).encode()

    else :
      raise Exception("[x] Arch '{}' not supported".format(arch))

    code = code[2:]
    return self.do_asm(code)


  def jmp_to(self, jj) :
    """
      Return jmp block code
    """
    code = b""
    if self.details["arch"] == "x86-64" :
      code ="PUSH RAX; MOV RAX, 0x{:x}; MOV [RSP-0x8], RAX; POP RAX; JMP [RSP-0x10]".format(jj).encode()

    elif self.details["arch"] == "arm" :
      code = self.do_jmp_arm_inj_addr(jj, to_reg="R10").encode()

    elif self.details["arch"] == "mips" :
      code = self.do_jmp_mips_inj_addr(jj).encode()

    else :
      raise Exception("[x] Arch '{}' not supported".format(arch))

    return self.do_asm(code)


  def do_return(self):
    arch = self.details["arch"]
    output = []
    if arch == "x86-64" :
      output.append("RET")

    elif arch == "arm" :
      output.append("BX LR")

    elif arch == "mips" :
      output.append("jr $ra")
      output.append(NOP_ins["mips"])

    else :
      raise Exception("[x] Arch '{}' not supported".format(arch))

    code = "; ".join(output).encode()
    return self.do_asm(code)


  def inject(self, args=None, return_point=None, extra=None) :
    """
      #TODO :
        - regs stuff
        - support struct argument or at least char *
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
    """
      Save registers before going further
    """

    if args :
      buff += self.insert_arg(args)

    buff += self.inject_code
    buff += self.regs_["post_regs"].inject_code
    """
      Restore registers
    """

    buff += self.jmp_to(return_point)
    """
      Jump to hooked function
    """

    if arch == "mips" :
      if self.details["endian"] == BIG_ENDIAN :
        output = b""
        for x in range(0,len(buff), self.details["capsize"]) :
          output += buff[x:x+self.details["capsize"]][::-1]
        buff = output

    rets = hook.inject_code(buff)
    return rets 



