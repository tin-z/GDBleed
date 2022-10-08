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

archs = { "mips":mips_convetion, "x86-64":x86_64_convention, "arm":arm_convention }


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




