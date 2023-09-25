
## Fb types
TYP_FUNC = 0
TYP_FUNC_IMP = 1  # function inside plt or mips stub section

## Bb types
TYP_END_FUNCTION = 0
TYP_RETURN = 1
TYP_BRANCH = 2
TYP_CONDITIONAL_BRANCH = 4
TYP_UNKNOWN_TYPE_BRANCH = 8

type_blocks = [ 
  TYP_END_FUNCTION ,\
  TYP_RETURN ,\
  TYP_BRANCH ,\
  TYP_CONDITIONAL_BRANCH ,\
  TYP_UNKNOWN_TYPE_BRANCH ,\
]


## Cb types
TYP_CALL = 0
TYP_CALL_IMP = 1  # call to imported section (plt, or mips stub section)

