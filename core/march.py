# -*- coding: utf-8 -*-

"""
Retrieve CPU architectural values and specific process values
"""

import gdb
import re
from core.constants import *

import config


ARCH_supported = config.ARCH_supported


x86_64_convention = { 
        "args"      : ["$rdi","$rsi","$rdx","$rcx","$r8","$r9","@@ $rsp+"] ,\
        "ret_val"   : ["$rax"] ,\
        "ret"       : ["@@ $rbp+"]
}

mips_convetion = {
        "args"      : ["$a0","$a1","$a2","$a3", "@@ $sp+"] ,\
        "ret_val"   : ["$v0","$v1"] ,\
        "ret"       : ["$ra","@@ $sp+"]
}

arm_convention = {
        "args"      : ["$r0","$r1","$r2","$r3","@@ $r13+"] ,\
        "ret_val"   : ["$r0"] ,\
        "ret"       : ["$r14","@@ $r13+"]
}

ppc_convention = {
        "args"      : ["$r3", "$r4", "$r5", "$r6", "$r7", "$r8", "$r9", "$r10", "@@ $r1+"] ,\
        "ret_val"   : ["$r3", "$r4"] ,\
        "ret"       : ["$lr", "$ctr", "@@ $r1+"]
}



archs = { 
  "mips"    : mips_convetion ,\
  "x86-64"  : x86_64_convention ,\
  "arm"     : arm_convention ,\
  "powerpc" : ppc_convention ,\
}



## Notes:

"""
Number          Name            Purpose
$0              $0              Always 0
$1              $at             The Assembler Temporary used by the assembler in expanding pseudo-ops.
$2-$3           $v0-$v1         These registers contain the Returned Value of a subroutine; if the value is 1 word only $v0 is significant.
$4-$7           $a0-$a3         The Argument registers, these registers contain the first 4 argument values for a subroutine call.
$8-$15,$24,$25  $t0-$t9         The Temporary Registers.
$16-$23         $s0-$s7         The Saved Registers.
$26-$27         $k0-$k1         The Kernel Reserved registers. DO NOT USE.
$28             $gp             The Globals Pointer used for addressing static global variables. For now, ignore this.
$29             $sp             The Stack Pointer.

$30             $fp (or $s8)    The Frame Pointer, if needed (this was discussed briefly in lecture). Programs that do not use an explicit frame pointer
                                    (e.g., everything assigned in ECE314) can use register $30 as another saved register. Not recommended however.

$31             $ra             The Return Address in a subroutine call.


- ref, https://courses.cs.washington.edu/courses/cse378/10sp/lectures/lec05-new.pdf
The caller is responsible for saving and restoring any of the following caller-saved registers that it cares about.
$t0-t9 $a0-$a3 $v0-$v1

The callee is responsible for saving and restoring any of the following callee-saved registers that it uses 
$s0-$s7 $ra (in our case we'll save also $ra)

----

## mips calling conventions, refs:
# -  https://courses.cs.washington.edu/courses/cse410/09sp/examples/MIPSCallingConventionsSummary.pdf
#
## arm calling convention, refs:
# - https://www.ele.uva.es/~jesus/hardware_empotrado/ARM_calling.pdf
# - https://azeria-labs.com/arm-data-types-and-registers-part-2/
"""


## ppc notes
# arrivato a sezione "The Stack Frame" di https://web.archive.org/web/20101223125240/http://refspecs.freestandards.org/elf/elfspec_ppc.pdf
#  - https://jimkatz.github.io/powerpc_for_dummies
"""
The PowerPC Architecture provides 32 general purpose registers, each 32 bits wide. 
In addition, the architecture provides 32 floating-point registers, each 64 bits wide, and several special purpose registers. 
 - All of the integer, special purpose, and floating-point registers are global to all functions in a running program. 
 - Registers r0, r3 through r12, f0 through f13, and the special purpose registers CTR and XER are volatile.
 - Register r2 is reserved for system use and should not be changed by application code
 - Register r13 is the small data area pointer... 16-bit offset relative address to r13 
 - The stack pointer shall maintain 16-byte alignment.
 - The first word of the stack frame shall always point to the previously allocated stack frame (toward higher addresses), 
    * except for the first stack frame, which shall have a back chain of 0 (NULL).

Register Name   Usage
r0              Volatile register which may be modified during function linkage
r1              Stack frame pointer, always valid [non-volatile]
r2              System-reserved register [non-volatile]
r3-r4           Volatile registers used for parameter passing and return values
r5-r10          Volatile registers used for parameter passing
r11-r12         Volatile registers which may be modified during function linkage
r13             Small data area pointer register [non-volatile]
r14-r30         Registers used for local variables [non-volatile]
r31             Used for local variables or "environment pointers" [non-volatile]

f0              Volatile register
f1              Volatile register used for parameter passing and return values
f2-f8           Volatile registers used for parameter passing
f9-f13          Volatile registers
f14-f31         Registers used for local variables [non-volatile]

CR0-CR7         Condition Register Fields, each 4 bits wide [non-volatile]
LR              Link Register
CTR             Count Register
XER             Fixed-Point Exception Register
FPSCR           Floating-Point Status and Control Register

## extra ppc ISA notes
 - copy the contents of the LR to register Rx: mflr Rx (equivalent to: mfspr Rx,8)
 - Copy the contents of register Rx to the CTR: mtctr Rx (equivalent to: mtspr 9,Rx)
 - stwu or stu (Store Word with Update): Stores a word of data from a general-purpose register into a specified location in memory and possibly places the address in another general-purpose register.

## ppc ISA
# - https://web.archive.org/web/20101223125240/http://refspecs.freestandards.org/elf/elfspec_ppc.pdf
# - https://wiki.raptorcs.com/w/images/f/f1/PowerISA_V2.03_Final_Public.pdf
# - https://www.ibm.com/docs/en/aix/7.2?topic=set-stwu-stu-store-word-update-instruction
# - https://web.archive.org/web/20210414024518/http://www.0x04.net/doc/elf/psABI-ppc64.pdf
"""



class GDBExceptionBase(Exception) :
    pass

class UnsupportedArch(GDBExceptionBase) :
    def __init__(self, msg):
        super().__init__("Unsupported arch: '{}'".format(msg))



def getarch(details):
  """
    Mostly copied and pasted from:
      - https://www.programcreek.com/python/?code=scwuaptx%2FPwngdb%2FPwngdb-master%2Fangelheap%2Fangelheap.py
  """
  value_to_set = ["capsize", "word", "arch", "isa"]
  capsize = None
  word = None
  arch = None 
  isa = None

  rets = None

  data = gdb.execute('show arch',to_string = True)
  tmp =  re.search("currently.*",data)
  if tmp :
    info = tmp.group()
    if "x86-64" in info:
      capsize = 8
      word = "gx "
      arch = "x86-64"
      rets = "x86-64"

    elif "mips" in info and "isa64" not in info :
      capsize = 4
      word = "wx "
      arch = "mips"
      isa = info.split(":")[1]
      rets = "mips"

    elif "arm" in info :
      capsize = 4
      word = "wx "
      arch = "arm"
      isa = "armv7" if "v7" in info else "arm"
      rets = "arm"

    elif "powerpc" in info :
      capsize = 4
      word = "wx "
      arch = "powerpc"
      isa = info.split(":")[1].strip()
      if isa.endswith(")") :
          isa = isa[:-1]
      rets = "powerpc"

    else :
      raise UnsupportedArch(info)

    #elif "aarch64" in info :
    #    capsize = 8
    #    word = "gx "
    #    arch = "aarch64"
    #    return "aarch64"

    #else :
    #    word = "wx "
    #    capsize = 4
    #    arch = "i386"
    #    return  "i386"
  else :
    pass

  for x in value_to_set :
    details[x] = locals()[x]

  return rets


def getendianess(details):
  data = gdb.execute('show endian',to_string = True)
  if "little endian" in data :
    details["endian"] = LITTLE_ENDIAN
  elif "big endian" in data :
    details["endian"] = BIG_ENDIAN
  else :
    return False
  return True


def infoprocmap():
    """ Use gdb command 'info proc map' to get the memory mapping """
    """ Notice: No permission info """
    resp = gdb.execute("info proc map", to_string=True).split("\n")
    resp = '\n'.join(resp[i] for i  in range(4, len(resp))).strip().split("\n")
    infomap = ""
    for l in resp:
        line = ""
        first = True
        for sep in l.split(" "):
            if len(sep) != 0:
                if first: # start address
                    line += sep + "-"
                    first = False
                else:
                    line += sep + " "
        line = line.strip() + "\n"
        infomap += line
    return infomap


def procmap():
    data = gdb.execute('info proc exe',to_string = True)
    pid = re.search('process.*',data)
    if pid :
        pid = pid.group()
        pid = pid.split()[1]
        fpath = "/proc/" + pid + "/maps"
        if os.path.isfile(fpath): # if file exist, read memory mapping directly from file
            maps = open(fpath)
            infomap = maps.read()
            maps.close()
            return infomap
        else: # if file doesn't exist, use 'info proc map' to get the memory mapping
            return infoprocmap()
    else :
        return None


def libcbase():
    infomap = procmap()
    data = re.search(".*libc.*\.so",infomap)
    if data :
        libcaddr = data.group().split("-")[0]
        libcbaddr = int(libcaddr,16)
        return libcbaddr
    else :
        return None


def getoff(sym):
    libcbaddr = libcbase()
    if type(sym) is int :
        return sym-libcbaddr
    else :
        try :
            data = gdb.execute("x/x " + sym ,to_string=True)
            if "No symbol" in data:
                return None

            else :
                data = re.search("0x.*[0-9a-f] ",data)
                data = data.group()
                symaddr = int(data[:-1] ,16)
                return symaddr-libcbaddr

        except :
            return None




