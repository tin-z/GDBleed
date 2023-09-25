# -*- coding: utf-8 -*-

types_list = ["t_FUNC", "t_BYTE", "t_SHORT", "t_INT", "t_LONG", "t_LONG_2", "t_POINTER", "t_STRING", "t_STRUCT"]
types_dict = { i:x for i,x in enumerate(types_list) }

for i,x in enumerate(types_list) :
  locals()[x]=i
#
#

default_size = {
  "hw" : [8] ,\
  "w" : [16] ,\
  "dw" : [32] ,\
  "qw" : [64]
}


default_types_size = {
  t_BYTE : default_size["hw"] ,\
  t_SHORT : default_size["w"] ,\
  t_INT : default_size["dw"] ,\
  t_LONG : default_size["dw"] ,\
  t_LONG_2 : default_size["qw"] ,\
  t_POINTER : default_size["qw"] ,\
}



########################################
### parse sections .bleed script
## Match declaration
re_match_declare        = r"^[ ]*([A-z][A-z0-9]*)[ ]+([A-z_][A-z0-9_]*)[ ]*[=]*[ ]*(.*);$"
re_match_declare_global = r"^[ ]*__static__[ ]+([A-z_][A-z0-9_]*)[ ]*[=]*[ ]*(.*);$"


### particular types
re_match_long_long          = r"^[ ]*(long[ ]+long)[ ]+([A-z_][A-z0-9_]*)[ ]*[=]*[ ]*(.*);$"
re_match_long_long_unsigned = r"^[ ]*(unsigned[ ]+long[ ]+long)[ ]+([A-z_][A-z0-9_]*)[ ]*[=]*[ ]*(.*);$"

re_match_unsigned_declare = r"^[ ]*(unsigned[ ]+[A-z][A-z0-9]*)[ ]+([A-z_][A-z0-9_]*)[ ]*[=]*[ ]*(.*);$"
re_match_string_declare = r"^[ ]*(char \*)[ ]+([A-z_][A-z0-9_]*)[ ]*[=]*[ ]*(.*);$"
re_match_pointer_declare = r"^[ ]*(void \*)[ ]+([A-z_][A-z0-9_]*)[ ]*[=]*[ ]*(.*);$"
re_match_create_struct = r"^[ ]*struct ([A-z_][A-z0-9_]+)[ ]*{$"


## Match external-functions
re_match_ext_function = r"^[ ]*([A-z][A-z0-9]+)\(([012])\)[ ]*;$"
# match (namespace).(name)
re_match_ext_internal_function = r"^[ ]*__static__[ ]+([A-z][A-z0-9]+)\.([A-z][A-z0-9]+)\(([012])\)[ ]*;$"



## Match code section
re_match_function_ret_val = r"^[ ]*([A-z][A-z0-9]+)[ ]*=[ ]*([A-z][A-z0-9]+)\((.*)\)[ ]*;$"
re_match_function = r"^[ ]*([A-z][A-z0-9]+)\((.*)\)[ ]*;$"
re_match_function_return = r"^[ ]*(return|RETURN)[ ]+(.*);$"


## internal_func settings
re_match_internal_func_decl = "^[ ]*(.*)[ ](.*)\(.*"



## Match other
re_match_comment = r"^[ ]*(//)(.*)$"
re_match_empty = r"^[ \t]*$"




########################################
### .bleed file parsing constants
sep_section = "--"
sep_sub_section = "@@"
sep_special_char = "__"

sect_skip_id = "{0}skip{0}".format(sep_section)
sect_declare_id = "{0}declare{0}".format(sep_section)
sect_code_id = "{0}code{0}".format(sep_section)


tags = { 
    sect_skip_id    : [] ,\
    sect_declare_id : ["{0}{1}{0}".format(sep_sub_section, x) for x in ["types", "vars", "external-functions"]] ,\
    sect_code_id    : ["{0}{1}{0}".format(sep_sub_section, x) for x in ["function", "pre_func", "post_func"]]
}

# this array also represents the order in which pre_func/post_func should declare them as the function arguments
special_symbols = [
  # arguments till 4th argument for now
  "{0}arg1{0}".format(sep_special_char)  ,\
  "{0}arg2{0}".format(sep_special_char)  ,\
  "{0}arg3{0}".format(sep_special_char)  ,\
  "{0}arg4{0}".format(sep_special_char)  ,\
  "{0}arg5{0}".format(sep_special_char)  ,\
  "{0}arg6{0}".format(sep_special_char)  ,\
  # name, name length, address of the hooked function
  "{0}fname_length{0}".format(sep_special_char) ,\
  "{0}fname{0}".format(sep_special_char) ,\
  "{0}fname_addr{0}".format(sep_special_char) ,\
  "{0}ret_addr{0}".format(sep_special_char) ,\
  "{0}num_arg{0}".format(sep_special_char) ,\
  "{0}sp_arg{0}".format(sep_special_char) ,\
  # return value of the hooked function (only available in post_func function)
  "{0}rets{0}".format(sep_special_char)
]


special_symbols_default_type = "void *"
special_symbols_types = { x:special_symbols_default_type for x in special_symbols }

special_symbols_types["{0}fname_length{0}".format(sep_special_char)] = "unsigned long"
special_symbols_types["{0}fname{0}".format(sep_special_char)] = "char *"
special_symbols_types["{0}num_arg{0}".format(sep_special_char)] = "unsigned long"



## pre_func settings

### pre_func decl
pre_func_decl = "void * pre_func("
pre_func_return = "return 0;\n}"
pre_func_decl += ", ".join("{} {}".format(special_symbols_types[x],x) for x in special_symbols[:4])

pre_func_space = " " * 4

pre_func_decl_x86_64 = pre_func_decl 
pre_func_decl_x86_64 += ", " + ", ".join("{} {}".format(special_symbols_types[x],x) for x in special_symbols[4:-1]) + ")"

pre_func_decl += ", " + ", ".join("{} {}".format(special_symbols_types[x],x) for x in special_symbols[6:-1]) + ")"

pre_func_decl += "{"
pre_func_decl_x86_64 += "{"


## function type enum 
PRE_FUNC = 1
POST_FUNC = 2
INTERNAL_FUNC = 4



