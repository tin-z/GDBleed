# -*- coding: utf-8 -*-

import r2pipe

from core.constants import CALL_ins
from core.disasm.r2_wrap import r2_wrap



class WrapDisasm :
  
  supported_strategy = {"r2":r2_wrap}

  def __init__(self, details, details_mem, details_data, strategy="r2"):
    self.details = details
    self.details_mem = details_mem
    self.details_data = details_data

    assert(strategy in WrapDisasm.supported_strategy)

    self.disasm = WrapDisasm.supported_strategy[strategy](
      self.details["binary_path"],
      self.details["is_pie"],
      self.details
    )

    # init
    self._init_globals()

    # set
    self.baddr = self.disasm.baddr
    self._find_funcs()
    self._find_calls()
    self._find_jmps()
  


  def _init_globals(self):
    # lists
    self.glb_ins_calls = []
    self.glb_ins_jmps = []
    self.glb_funcs = []
    # hashmaps
    self.hs_glb_ins_calls = {}
    self.hs_glb_ins_jmps = {}
    self.hs_glb_funcs = {}

  def _find_calls(self):
    print("#TODO")
    pass

  def _find_jmps(self):
    print("#TODO")
    pass
 




  def update_globals(self, obj, is_data=False):
    if not is_data :
      l1 = self.glb_func
      t1 = self.glb_typ_func
      h1 = self.hs_glb_func
      func_type = obj.func_type

      if obj.full_name in h1 :
        raise Exception("Function '{}' already defined".format(obj.full_name))

      l1.append(obj)
      t1.append(func_type)
      h1.update({obj.full_name : len(l1)-1})

    else :
      l1 = self.glb_vars
      h1 = self.hs_glb_vars

      if obj.var_name in h1 :
        raise Exception("Var '{}' already defined".format(obj.var_name))

      l1.append(obj)
      h1.update({obj.var_name : len(l1)-1})


  def resolve_ext_func(self) :
    for k,v in self.parser.hs_ext_func.items() :
      if k not in self.hs_glb_ext_func :
        _, addr = find_function_addr(k, self.details)
        if addr == None :
          raise Exception("Can't find the address of function '{}'".format(k))
        v.addr = addr
        self.glb_ext_func.append(v)
        self.hs_glb_ext_func.update({k:len(self.glb_ext_func)-1})

      self.parser.hs_ext_func[k] = self.glb_ext_func[self.hs_glb_ext_func[k]]


  def resolve_vars(self, arguments, vars_dict, vars_list, is_data=False):
    for arg in arguments :
      if isinstance(arg, obj_parser.TypeBase) :
        var_name = arg.var_name

        if arg.is_internal() :
          arg = self.find_var(var_name)

        if var_name not in vars_dict :
          vars_dict[var_name] = 1
          vars_list.append(arg)

        # resolve string
        if isinstance(arg, obj_parser.TypeString) :
          if arg.addr == None :
            addr = hook.inject_data(arg.var_value)
            arg.addr = addr

        # if we're declaring global/static vars
        if is_data :

          # resolve blob
          if isinstance(arg, obj_parser.TypePointer) :
            if arg.is_blob() and arg.addr == None :
              addr = hook.inject_data(arg.size_ref_to * "\x00")
              arg.addr = addr



  def resolve_internal_func(self):
    func_name_l = []
    func_decl_l = []
    func_body_l = []

    func_object = InternalFunction
    func_return = pre_func_return

    namespace = self.parser.func_name
    description = self.parser.func_desc

    ## QUI
    ## QUI
    ## QUI
    ## QUI
    ## 
    ## aggiungere codice simile a resolve_func alla fine
    ##

    for i, func_name in enumerate(func_name_l) :

      body_now = func_body_l[i]
      decl_now = func_decl_l[i]
      func_name_ext_l = set([ "{}.{}".format(namespace,x) for x in func_name_l if re.search("(?<![A-z0-9_.])({})\(".format(x), body_now) ]) - set([func_name])


      ,lol).groups()



      func_Id = WrapParser.Id
      WrapParser.Id += 1
      addr = None

      func_obj = InternalFunction(
        func_Id, func_name,
        namespace, description, 
        func_decl, using_function=func_name_ext_l
      ) 

      // fix get_source_code
      // fix used_by_function list
      // fix addr ----------------------> compilation is not optional







  def resolve_func(self):
    """
      Construct AST-similar struct and resolve types
    """
    func_declare_list = []
    func_declare_dict = {}
    vars_list = []
    vars_dict = {}
        
    if self.parser.func_type & INTERNAL_FUNC :
      return self.resolve_internal_func()

    if self.parser.func_type & PRE_FUNC :
      declaration = pre_func_decl_x86_64 if self.details["arch"]  == "x86-64" else pre_func_decl
      func_now = self.parser.pre_func

    elif self.parser.func_type & POST_FUNC :
      declaration = "post_func #TODO"
      func_now = self.parser.post_func

    for entry in func_now :
      func_object = entry.func_object
      fname = func_object.func_name
      assign_to = entry.assign_to

      if fname not in func_declare_dict :
        func_declare_list.append(func_object)
        func_declare_dict[fname] = 1

      if assign_to != None :
        if assign_to.var_name not in vars_dict :
          vars_dict[assign_to.var_name] = 1
          vars_list.append(assign_to)

      # for each function call resolve its arguments
      self.resolve_vars(entry.arguments, vars_dict, vars_list)

    func_Id = WrapParser.Id
    WrapParser.Id += 1
    func_type = self.parser.func_type
    namespace = self.parser.func_name
    description = self.parser.func_desc
    addr = None

    # da sistemare _constants pre_func_return etc.
    if func_type == PRE_FUNC :
      func_object = PreFunction
    elif func_type == POST_FUNC :
      func_object = PostFunction

    func_object = func_object(
      func_Id, namespace, description,\
      declaration, addr
    )

    func_object.update_declare_lists(
      func_declare_list,
      vars_list,
      self.parser.pre_func,
      func_return
    )

    source_code = func_object.get_source_code()
    self.update_globals(func_object)
    
    return func_object.full_name, source_code


  def reset(self) :
    self.parser.reset()
    self.last_error = None


  def invoke(self, file_path=None, do_reset=True, is_data=False) :
    if do_reset :
      self.reset()

    self.parser.invoke(file_path, is_data=is_data)
    self.last_error = self.parser.last_error

    if self.last_error :
      raise self.last_error

    return self.loader(is_data=is_data)


  def loader(self, is_data=False):
    if not is_data :
      self.resolve_ext_func()
      return self.resolve_func()

    else :
      vars_list = []
      vars_dict = {}
      l1 = list(self.parser.hs_vars.values())
      self.resolve_vars(l1, vars_dict, vars_list, is_data=is_data)

      for obj in vars_list :
        self.update_globals(obj, is_data=True)


  def find_var(self, vname):
    h1 = self.hs_glb_vars
    if not vname in h1 :
      raise Exception("Can't find var '{}'".format(vname))
    var_object = self.glb_vars[h1[vname]]
    return var_object


  def find_func(self, fname):
    h1 = self.hs_glb_func
    if not fname in h1 :
      raise Exception("Can't find function '{}'".format(fname))
    func_object = self.glb_func[h1[fname]]
    return func_object

  def get_source_code(self, fname) :
    func_object = self.find_func(fname)
    return func_object.get_source_code()

  def update_addr_func(self, fname, addr_func, code_func):
    func_object = self.find_func(fname)
    func_object.update_addr_func(addr_func, code_func)



