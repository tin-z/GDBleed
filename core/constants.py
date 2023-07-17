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





# ref https://ablconnect.harvard.edu/files/ablconnect/files/mips_instruction_set.pdf
mips_branch_type = [
    "beq" ,\
    "bne" ,\
    "blez" ,\
    "bgtz" ,\
    "bltz" ,\
    "bgez" ,\
    "bltzal" ,\
    "bgezal" ,\
]


# ref https://www.slideserve.com/elina/68000-addressing-modes
#     https://www.intel.com/content/www/us/en/docs/programmable/683620/current/bgtu.html
arm32_branch_type = [
    "beq" ,\
    "bne" ,\
    "bpl" ,\
    "bmi" ,\
    "bcc" ,\
    "blo" ,\
    "bcs" ,\
    "bhs" ,\
    "bvc" ,\
    "bvs" ,\
    "bge" ,\
    "bgt" ,\
    "ble" ,\
    "blt" ,\
    "bhi" ,\
    "bls" ,\
    "bgtu" ,\
    "bltu" ,\
    "bgeu" ,\
    "bleu" ,\
    "beqz" ,\
    "bnez" ,\
    "blez" ,\
    "bgez" ,\
    "bltz" ,\
    "bgtz" ,\
]

# https://www.felixcloutier.com/x86/jcc
x86_64_branch_type = [
    'jnz' ,\
    'jpo' ,\
    'jnl' ,\
    'jpe' ,\
    'jnle' ,\
    'jb' ,\
    'jng' ,\
    'jcxz' ,\
    'jz' ,\
    'jc' ,\
    'jecxz' ,\
    'js' ,\
    'jle' ,\
    'jrcxz' ,\
    'je' ,\
    'jo' ,\
    'jnge' ,\
    'jno' ,\
    'jge' ,\
    'ja' ,\
    'jnae' ,\
    'jnbe' ,\
    'jna' ,\
    'jl' ,\
    'jne' ,\
    'jns' ,\
    'jnp' ,\
    'jae' ,\
    'jp' ,\
    'jnc' ,\
    'jbe' ,\
    'jg' ,\
    'jnb' ,\
]

JCC_types = {
  "arm" : arm32_branch_type ,\
  "x86-64" : x86_64_branch_type ,\
  "mips" : mips_branch_type ,\
}

