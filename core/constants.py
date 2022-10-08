"""
    CPU Architectural Constants
"""
import config



LITTLE_ENDIAN=config.LITTLE_ENDIAN
BIG_ENDIAN=config.BIG_ENDIAN


CALL_CONVENTION = {
        "arm"       : ["R0", "R1", "R2", "R3", "@@ R13"] ,\
        "x86-64"    : ["RDI", "RSI", "RDX", "RCX", "R8", "R9", "@@ RSP"] ,\
        "mips"      : ["$a0","$a1","$a2","$a3", "@@ $sp"] 
}
"""
Calling convention supported
"""


NOP_ins = {
        "arm"       : "NOP" ,\
        "x86-64"    : "NOP" ,\
        "mips"      : "add $t0, $t0, 0"
}



CALL_ins = {
  "arm" : ["blx", "bl"] ,\
  "x86-64" : ["call", "callq"] ,\
  "mips"  : ["jal"]
}


special_regs = {
        "mips_gp" : "$t9"
}




