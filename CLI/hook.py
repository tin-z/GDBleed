# -*- coding: utf-8 -*-

"""
  Instrumentation of GOT hijacking/poisoning API

  This module is a continuos work in progress.
  It is not clear still how to separate functionalities,
  maybe more classes might be added in future.
"""

import gdb
import re
import lief

from CLI.memory import MemCommand

from core.parser.wrap_parser import WrapParser
from core.parser import objects as obj_parser

from core.parser._constants import special_symbols, pre_func_decl, pre_func_decl_x86_64, pre_func_return

from core.parser._constants import  PRE_FUNC ,\
                                    POST_FUNC ,\
                                    INTERNAL_FUNC

from core.compiler import Compiler


import hook



black_list = []
"""
Functions present in got and to avoid
"""


class HookGOT(MemCommand):
  """
    GOT hijacking API
  """

  cmd_default = "hook-got"

  def __init__(self, name, details, details_mem, details_data):
    super(HookGOT, self).__init__(name, details, details_mem)
    self.details_data = details_data


  def do_reset(self, argv, reset_all=False):
    """
      Clear hijacked GOTs
    """
    entries = self.details_data["got_entries"]
    if not reset_all :
      syscall = argv[0].strip()
      entries = { syscall:entries[syscall] }

    for wrap_pltgot in entries.values() :
      wrap_pltgot.address_hooking = -1
      gdb.execute("set {void *} " + "0x{:x}=0x{:x}".format(
        wrap_pltgot.address_dyn, 
        wrap_pltgot.address_resolv
        )
      )

    print(1)


  def invoke(self, argv, from_tty):
    """
      Usage: <cmd-default> [--trace|--trace-all|--reset|--reset-all] <function-hooked> <function-hooking> [arg1 ...]
            function-hooked     : this is the function to be hooked, that should be present in the PLT.GOT, e.g. 'execve'
            function-hooking    : address or default hook functions implemented into 'hook' folder
            arg1 ...            : arguments given
            --trace             : do the ltrace similar function to <function-hooked>
            --trace-all         : do the ltrace similar function to each function imported by binary
            --reset             : restore <function-hooked> GOT original value
            --reset-all         : restore GOT original values
            --help              : this message
    """
    argv = [x.strip() for x in argv.split(" ") if x.strip() != "" ]

    try:
      hook_addr_mode = False
      syscall = argv[0].strip()
      arg_next = []

      if syscall == "--help" :
        raise Exception("help invoked")

      elif syscall == "--reset" :
        return self.do_reset(argv[1:])

      elif syscall == "--reset-all" :
        return self.do_reset(argv[1:], reset_all=True)

      if len(argv) > 1 :
        hook_with = argv[1].strip()
        if len(argv) > 2 :
          arg_next = argv[2:]

      if not syscall.startswith("--") :
        if hook_with.startswith("0x") :
          hook_addr_mode = True
          self.details["slog"].append("[-] You are doing hook directly to an address.. before doing that you should debug that assembly code")

        elif hook_with not in hook.default_list :
          self.details["slog"].append("[x] Invalid hook address given: '{}'  ...ignoring command".format(hook_with))
          return

        if syscall not in self.details_data["got_entries"] :
          self.details["slog"].append("[x] Can't hook '{}' maybe is not imported by the binary ...ignoring command".format(syscall))
          return

        if hook_addr_mode :
          self.manage_addr_mode(syscall, hook_with, arg_next)
        else :
          self.manage_default_mode(syscall, hook_with, arg_next)
      
        self.details["slog"].append("[+] '{}' hooked".format(syscall))

      else :
        if syscall == "--trace" :
          syscall = hook_with 
          self.hook_trace(syscall, arg_next)

        elif syscall == "--trace-all" :
          for k,v in self.details_data["got_entries"].items() :
            # avoid function inside the black_list 
            if v.fname not in black_list :
              self.hook_trace(v.fname, [])

        else :
          self.details["slog"].append("Parameter '{}' unsupported".format(syscall))


    except Exception as ex :
      self.details["slog"].append(str(ex))
      self.details["slog"].append(
        "Usage: {} [--trace|--trace-all] <function-hooked> <function-hooking> [arg1 ...]".format(HookGOT.cmd_default) + "\n" +\
        "     function-hooked     : this is the function to be hooked, that should be present in the PLT.GOT, e.g. 'execve'\n" +\
        "     function-hooking    : address or default hook functions implemented into 'hook' folder\n" +\
        "     arg1 ...            : arguments given\n" +\
        "     --trace             : do the ltrace similar function to <function-hooked> \n" +\
        "     --trace-all         : do the ltrace similar function to each function imported by binary\n" +\
        "     --reset             : restore <function-hooked> GOT original value\n" +\
        "     --reset-all         : restore GOT original values\n"
        "     --help              : this message\n"
      )

  def manage_addr_mode(self, syscall, hook_with, arg_next) :
    self.details["slog"].append("TODO")
    pass

  def manage_default_mode(self, syscall, hook_with, arg_next) :
    wrap_pltgot = self.details_data["got_entries"][syscall]
    wrap_hook = hook.default_list[hook_with]
    addr = wrap_hook.inject(args=arg_next, return_point=wrap_pltgot.address_resolv)
    gdb.execute("set {void *} " + "0x{:x}=0x{:x}".format(wrap_pltgot.address_dyn, addr))
    wrap_pltgot.address_hooking = addr
  
  def hook_trace(self, syscall, arg_next) :
    wrap_pltgot = self.details_data["got_entries"][syscall]
    addr = hook.hook_trace.inject(
      args=arg_next ,\
      return_point=wrap_pltgot.address_resolv ,\
      extra={"fname":syscall, "details_mem":self.details_mem}
    )
    if addr != None :
      gdb.execute("set {void *} " + "0x{:x}=0x{:x}".format(wrap_pltgot.address_dyn, addr))
      wrap_pltgot.address_hooking = addr



class HookGOTInline(MemCommand):
  cmd_default = "hook-got-inline"

  def __init__(self, name, details, details_mem, details_data):
    super(HookGOTInline, self).__init__(name, details, details_mem)
    self.details_data = details_data
    self.parser = WrapParser(details, details_mem, details_data)
    self.compiler = Compiler(details, details_mem, details_data)
    self.details_data["parser"] = self.parser
    self.details_data["compiler"] = self.compiler


  def do_list(self, argv) :
    """
      Usage: <cmd-default> --list [<function_name>]
            <function_name>     : Print also information regarding that function, fullname (namespace+name) is used
    """
    try:
      hdr = ["Id","namespace","full_name","addr"]
      hdr_extra = ["description", "declaration", "used_by_function", "hooking_function"]
      l1 = self.parser.glb_func
      if argv :
        fname = argv[0]
        l1 = [self.parser.find_func(fname)]
      
      output_maxlen = [0 for _ in range(len(hdr))]
      output = [] 
      for func in l1 :
        output.append([])
        for i, x in enumerate(hdr) :
          tmp_obj = getattr(func,x)
          
          if x in ["Id", "addr"]:
            if tmp_obj != None :
              tmp_obj = hex(tmp_obj)
            else :
              tmp_obj = "None"

          output[-1].append(tmp_obj)
          if len(tmp_obj) > output_maxlen[i] :
            output_maxlen[i] = len(tmp_obj)
      
      output_maxlen = [ x+4 for x in output_maxlen]

      self.details["slog"].append(
        "".join([x.ljust(output_maxlen[i], " ") for i,x in enumerate(hdr)])
      )

      for x in output :
        self.details["slog"].append(
          "".join([y.ljust(output_maxlen[i], " ") for i,y in enumerate(x)])
        )

      if argv :
        for y in hdr_extra :
          self.details["slog"].append(
            " \---> {}:".format(y)
          )
          self.details["slog"].append(
            getattr(func,y)
          )
          self.details["slog"].append(
            ""
          )

      self.details["slog"].append(
        "\n"
      )

    except Exception as ex :
      self.details["slog"].append(str(ex))
      self.details["slog"].append(
        "Usage: {} --list [<function_name>]\n" .format(HookGOTInline.cmd_default) +\
        "     <function_name>     : Print also information regarding that function, fullname (namespace+name) is used\n"
      )


  def do_print_source_code(self, argv) :
    fname = argv[0].strip()
    source_code = self.parser.get_source_code(fname)
    self.details["slog"].append(
      "'{}' source code:\n".format(fname) +\
      source_code + "\n" +\
      "\n"
    )


  def do_remove(self, argv) :
    print("Not supported")
    return
    #fname = argv[0]
		#function_declared = self.details_data["functions_declared"][fname]
    #if function_declared.is_hooking() :
    #  self.details["slog"].append(
    #    "[x] Can't remove '{}' function because it is hooking some GOT entries\n".format(fname)
    #  )
    #else :
    #  del self.details_data["functions_declared"][fname]


  def invoke(self, argv, from_tty):
    """
      Usage: <cmd-default> [options] <function_name>

        Options:
            --help              : This message
            --create            : insert gdbleed script from STDIN or by file <file_path>
            --list              : print declared functions nformation
            --source-code       : print function's source code
            --remove            : delete function <function_name>
            --compile           : Compile function
            --inject            : inject mode
            --inject-ret        : inject-ret mode
            --inject-post       : inject-post mode
            --inject-post-ret   : inject-post-ret mode
            --inject-full       : inject-full mode

            --data              : Define or list global/static vars menu
            --gdbcov            : gdbcov menu
    """
    argv = [x.strip() for x in argv.split(" ") if x.strip() != "" ]
    arg0 = argv[0]

    try :

      if "--create" == arg0 :
        return self.do_create(argv[1:])

      elif "--data" == arg0 :
        return self.do_manage_var(argv[1:])

      elif "--list" == arg0 :
        return self.do_list(argv[1:])

      elif "--source-code" == arg0 :
        return self.do_print_source_code(argv[1:])

      elif "--remove" == arg0 :
        return self.do_remove(argv[1:])

      elif "--help" == arg0 :
        raise Exception("Help")

      elif "--inject" == arg0 :
        return self.do_inject(argv[1:])

      elif "--inject-ret" == arg0 :
        return self.do_inject(argv[1:], ret_func_hooked=False)

      elif "--inject-post" == arg0 :
        return print("#TODO")

      elif "--inject-post-ret" == arg0 :
        return print("#TODO")

      elif "--inject-full" == arg0 :
        return print("#TODO")

      elif "--compile" == arg0 :
        return self.do_compile(argv[1:])

      elif "--gdbcov" == arg0 :
        return self.do_gdbcov(argv[1:])

      else :
        raise Exception("Invalid argument given '{}'".format(argv))

    except Exception as ex :
      self.details["slog"].append(str(ex))
      self.details["slog"].append(
				"Usage: {} [options] <function_name>\n".format(HookGOTInline.cmd_default) +\
        "\n" +\
        "   Options:\n" +\
				"       --help              : This message\n" +\
				"       --create            : insert gdbleed script from STDIN or by file <file_path>\n" +\
        "       --data              : Define or list global/static vars\n" +\
				"       --list              : print declared functions nformation\n" +\
				"       --source-code       : print function's source code\n" +\
				"       --remove            : delete function <function_name>\n" +\
				"       --compile           : Compile function\n" +\
        "       --inject            : inject mode\n" +\
        "       --inject-ret        : inject-ret mode\n" +\
        "       --inject-post       : inject-post mode\n" +\
        "       --inject-post-ret   : inject-post-ret mode\n" +\
        "       --inject-full       : inject-full mode\n" +\
        "\n" +\
        "       --gdbcov            : gdbcov menu\n" +\
        "\n" +\
        " Notes:\n" +\
        "   --inject                : call pre_func, jump to function-hooked\n" +\
        "   --inject-ret            : jump directly to pre_func and return its return value\n" +\
        "   --inject-post           : call function-hooked, post_func, then return function-hooked's return values\n" +\
        "   --inject-post-ret       : call function-hooked, post_func and return ist return value\n" +\
        "   --inject-full           : call pre_func, function-hooked, post_func, then return function-hooked's return value\n"
      )


  def do_compile_internal_funcs(self):
    try :
      while self.parser.order_to_compile :
        func_obj = self.parser.update_next_internal_func()
        fname = func_obj.full_name
        rets = self.do_compile([fname], raise_exceptions=True)
    except Exception as ex :
      self.details["slog"].append(
        "Error during internal function compilation"
      )
      self.details["slog"].append(str(ex))
      self.parser.update_next_internal_func(remove=True)



  def do_compile(self, argv, raise_exceptions=False) :
    """
      Usage: <cmd-default> --compile <function_name>
            <function_name>     : Compile <function_name>
    """
    try : 
      fname = argv[0]
      func_obj = self.parser.find_func(fname)
      source_code = func_obj.get_source_code()

      output_file_path = self.compiler.compile(fname+".c", source_code)
      binary = lief.parse(output_file_path)
      sections = {x.name:x for x in binary.sections}

      condition = False
      for x in [".data", ".rodata"] :
        if x in sections :
          if sections[x].content.tobytes() != b"" :
            condition = True
            break
       
      if condition :
        raise Exception(
          "[x] .data and alike sections are not empty, that means your code is dependet on data sections, and relocation should be applied, which gdbleed does not support"
        )
      
      func_name = fname.split(".")[1]

      offset_func = binary.get_function_address(func_name)
      size_func = {x.name:x for x in binary.symbols}[func_name].size
      text_code = sections[".text"].content.tobytes()
      code_func = text_code[offset_func : offset_func + size_func]

      addr_func = hook.hook_trampoline.inject_function(code_func)
      self.parser.update_addr_func(fname, addr_func, code_func)

    except Exception as ex :
      if raise_exceptions :
        raise ex

      self.details["slog"].append(str(ex))
      self.details["slog"].append(
	      "Usage: {} --compile <function_name>\n".format(HookGOTInline.cmd_default) +\
        "     <function_name>     : Compile <function_name>\n"
      )


  def do_manage_var(self, argv) :
    """
	    Usage: <cmd-default> --data [--list|--create]
            --help              : this message
            --list              : list global vars
            --create            : create new global vars
            <file_name>         : optional filename where variables are declared, otherwise STDIN is used
    """
    try : 

      if "--help" in argv[0] :
        raise Exception("Help invoked")

      elif "--create" in argv[0] :
        argv = argv[1:]
        file_path = None if not argv else argv[0]
        rets = self.parser.invoke(file_path, is_data=True)

      elif "--list" in argv[0] :
        space = 16
        print("Id".ljust(space, " ") + "declaration".ljust(space, " "))
        for i, x in enumerate(self.parser.glb_vars) :
          print(str(i).ljust(space, " ") + str(x).ljust(space, " "))
        print("")


    except Exception as ex :
      self.details["slog"].append(str(ex))
      self.details["slog"].append(
	      "Usage: {} --data [--list <var_name>|--create]\n".format(HookGOTInline.cmd_default) +\
        "    --help              : this message\n" +\
        "    --list              : list global vars\n" +\
        "    --create            : create new global vars\n" +\
        "    <var_name>          : list only variable <var_name>\n"
      )


  def do_create(self, argv) :
    compile_flg = False
    if argv :
      if "--compile" in argv[0] :
        compile_flg = True
        argv = argv[1:]

    file_path = None if not argv else argv[0]
    rets = self.parser.invoke(file_path=file_path)

    if self.parser.last_error :
      self.details["slog"].append(self.parser.last_error)
      return

    # TODO:
    # - Tabella variabili static/global : StaticVar (id, var_type, addr, name, namespace, description, used_by_function)
    #
    # - infine gestire thumb mode in futuro ... bisogna capire se sto per saltare su thumb mode instruction, e.g. printf=0x... come so se si aspetta di essere chiamata in thumb mode??
    #  \---> magari può essere che se controllo l'address che c'è già dentro GOT lo capisco da quello.
    #   \----> rimane cmq il problema di chiamare funzioni che non stanno dentro la GOT del processo
    #
    
    func_type, filename, _ = rets

    if func_type != INTERNAL_FUNC :
      if not compile_flg :
        return
      
      return self.do_compile([filename])

    else :
      return self.do_compile_internal_funcs()



  def do_inject(self, argv, ret_func_hooked=True) :
    try :
   
      entries = self.details_data["got_entries"]
      fname = argv[1]
      if "--trace-all" != argv[0] :
        fname = argv[0]
        syscall = argv[1]
        entries = {syscall:entries[syscall]}

      func_obj = self.parser.find_func(fname)
      if not func_obj.is_ready():
        raise Exception("[x] Function '{}' is not compiled".format(fname))

      addr_func = func_obj.addr
 
      for k, wrap_pltgot in entries.items() :
        addr = hook.hook_trampoline.inject(
          func_hooking=addr_func ,\
          func_hooked=wrap_pltgot.address_resolv ,\
          extra={"fname":k, "details_mem":self.details_mem} ,\
          ret_func_hooked=ret_func_hooked
        )

        if addr != None :
          gdb.execute("set {void *} " + "0x{:x}=0x{:x}".format(wrap_pltgot.address_dyn, addr))
          wrap_pltgot.address_hooking = addr

    except Exception as ex :
      self.details["slog"].append(str(ex))
      self.details["slog"].append(
        "Usage: {} [--inject|--inject-ret] -- [--trace-all] <function-hooking> <function-hooked>".format(HookGOTInline.cmd_default) + "\n" +\
        "     function-hooking    : the fullname (name.namespace) of a function we created and compiled before\n" +\
        "     function-hooked     : this is the function to be hooked, that should be present in the PLT.GOT, e.g. 'execve'\n" +\
        "     --trace-all         : hijack each GOT entry\n"
      )


  def do_gdbcov(self, argv) :
    """
	    Usage: <cmd-default> --gdbcov [--list|--trace]
            --help              : this message
            --list              : list conditional branches
            --trace             : Trace conditional branches
    """
    try : 

      if "--help" in argv[0] :
        raise Exception("Help invoked")

      elif "--trace" in argv[0] :
        print("#TODO")

      elif "--list" in argv[0] :

        argv = argv[1:]
        jump_offset = None if argv == [] else int(argv[0], 16 if argv[0].startswith("0x") else 10)

        conditional_branches = hook.hook_trampoline.disasm.get_conditional_branches(
          jump_offset = jump_offset
        )

        print("# Conditional branches:")
        for branch in conditional_branches :
          print("{}: {}".format(
            "0x" + hex(branch.arg_offset).split("0x")[1].rjust(
              self.details["capsize"] * 2, "0"
            ) ,\
            branch.arg_opcode
          ))

    except Exception as ex :
      self.details["slog"].append(str(ex))
      self.details["slog"].append(
	      "Usage: {} --gdbcov [--list|--trace]\n".format(HookGOTInline.cmd_default) +\
        "    --help              : this message\n" +\
        "    --list              : list conditional branches\n" +\
        "    --trace             : Trace conditional branches\n"
      )



class ManageMemoryHooks(MemCommand):
  """
    Reset/remove 'hook' injected memory area
  """

  cmd_default = "hook-memory_mng"

  def __init__(self, name, details, details_mem, details_data):
    super(ManageMemoryHooks, self).__init__(name, details, details_mem)
    self.details_data = details_data

  def invoke(self, argv, from_tty):
    """
      Usage: <cmd-default> [--reset|--remove]
            --reset             : Reset 'hook' injected memory area
            --remove            : Remove 'hook' injected memory area
    """
    argv = [x.strip() for x in argv.split(" ") if x.strip() != "" ]
 
    try :
      if argv[0] == "--remove" :
        rets = hook.remove(self.details, self.details_mem, self.details_data)
       
      elif argv[0] == "--reset" :
        rets = hook.reset(self.details, self.details_mem, self.details_data)

      else :
        raise Exception("Argument '{}' is not a valid one".format(argv[0]))

      if rets != 1 :
        raise Exception("Can't reset/remove 'hook' injected memory")

    except Exception as ex :
      self.details["slog"].append(str(ex))
      self.details["slog"].append(
        "Usage: <cmd-default> [--reset|--remove]\n" +\
        "    --reset             : Reset 'hook' injected memory area\n" +\
        "    --remove            : Remove 'hook' injected memory area\n"
      )




def init(details, details_mem, details_data, extra=dict()) :
  """
    Initialize hook CLI methods
  """
  HookGOT(HookGOT.cmd_default, details, details_mem, details_data)
  HookGOTInline(HookGOTInline.cmd_default, details, details_mem, details_data)
  ManageMemoryHooks(ManageMemoryHooks.cmd_default, details, details_mem, details_data)


