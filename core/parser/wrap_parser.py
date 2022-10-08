# -*- coding: utf-8 -*-
import re

from core.parser.parser import Parser
from core.parser import objects as obj_parser 
from core.parser._constants import special_symbols, pre_func_decl, pre_func_decl_x86_64, pre_func_return

from core.parser.wrap_objects import *

from utils.gdb_utils import find_function_addr

from core.parser._constants import  PRE_FUNC ,\
                                    POST_FUNC ,\
                                    INTERNAL_FUNC

import hook

from core.parser.graph import Node



class WrapParser :
  
  Id = 0
  Id_v = 0

  def __init__(self, details, details_mem, details_data):
    self.details = details
    self.details_mem = details_mem
    self.details_data = details_data
    self.parser = Parser(details, details_mem, details_data)
    self._init_globals()
    self.reset()
  
  def _init_globals(self):
    # lists
    self.glb_ext_func = []
    self.glb_func = []
    self.glb_typ_func = []
    self.glb_vars = []
    # hashmaps
    self.hs_glb_ext_func = {}
    self.hs_glb_func = {}
    self.hs_glb_vars = {}

    # here we save internal function that requires compilation
    self.order_to_compile = []


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

      if isinstance(v, obj_parser.TypeInternalFunction) :
        full_name = v.full_name
        if full_name not in self.hs_glb_func :
          raise Exception(
            "Internal function '{}' was not declared".format(full_name)
          )

        func_obj = self.glb_func[self.hs_glb_func[full_name]]
        v.addr = func_obj.addr
        v.decl = func_obj.decl_as_ptr

        if v.addr == None :
          raise Exception(
            "Internal function '{}' was not compiled".format(full_name)
          )

      else :

        if k not in self.hs_glb_ext_func :
          _, addr = find_function_addr(k, self.details)

          if addr == None :
            raise Exception("Can't find the address of function '{}'".format(k))
          v.addr = addr
          self.glb_ext_func.append(v)
          self.hs_glb_ext_func.update({k:len(self.glb_ext_func)-1})

        addr = self.glb_ext_func[self.hs_glb_ext_func[k]].addr
        v.addr = addr


  def resolve_vars(self, arguments, vars_dict, vars_list, is_data=False, is_internal=False):
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

        if is_internal and not is_data:
          if not (isinstance(arg, obj_parser.TypeString) or \
            isinstance(arg, obj_parser.TypePointer)):
            raise Exception(
              "Variable type of '{}' not supported in internal functions".format(var_name)
            )


  def make_order_to_compile_internal_func(self):
    """
      Make order on which to compile internal functions

    """
    func_name_l = []

    nodes = { }
    nodes_hs = { }
    for i, (func_name, func_decl, func_body) in enumerate(self.parser.internal_func[1:]) :
      nodes.update({ i:Node(i, func_name, func_decl, func_body) })
      nodes_hs.update({ func_name:i })
      func_name_l.append(func_name)

    for i, node in nodes.items() :
      body_now = node.body
      func_name = node.val
      edges_out = set([nodes_hs[x] for x in func_name_l if re.search("(?<![A-z0-9_.])({})(?![A-z0-9_.])".format(x), body_now) ]) - set([nodes_hs[func_name]])

      for node_i in edges_out :
        node_i = nodes[node_i]
        node.add_out(node_i)
        node_i.add_in(node)

    self.order_to_compile = []
    while nodes != {} :
      node_fine = None
      for i, node in nodes.items() :
        if node.is_fine() :
          node_fine = node
          break

      if node_fine == None :
        raise Exception(
          "Can't compile internal functions because of circular dependencies found which are not supported yet"
        )

      for i, node in node_fine.edge_in.items() :
        node.mov_out(node_fine)

      del nodes[node_fine.Id]

      self.order_to_compile.append(node_fine)

    self.order_to_compile = self.order_to_compile[::-1]


  def resolve_internal_func(self):
    namespace = self.parser.func_name
    description = self.parser.func_desc

    vars_list = []
    vars_dict = {}
    l1 = list(self.parser.hs_vars.values())
    self.resolve_vars(l1, vars_dict, vars_list, is_internal=True)

    func_declare_list = [ v for k,v in self.parser.hs_ext_func.items() ]

    # expand data
    define_section_data = self.parser.internal_func[0]

    self.make_order_to_compile_internal_func()


    for node in self.order_to_compile :
      i = node.Id
      func_name = node.val
      body_now = node.body
      decl_now = node.decl

      func_name_ext_l = set([ "{}.{}".format(namespace, x.val) for x in node.edge_out_fine.values() ])

      func_Id = WrapParser.Id
      WrapParser.Id += 1
      addr = None

      func_object = InternalFunction(
        func_Id, func_name,
        namespace, description, 
        decl_now, using_function=func_name_ext_l
      ) 

      func_object.update_declare_lists(
        func_declare_list,
        vars_list,
        [],
        body_now
      )

      func_object.update_header([define_section_data])

      node.set_f_object(func_object)
      self.update_globals(func_object)

    return INTERNAL_FUNC, [], []


  def update_next_internal_func(self, remove=False):
    if remove :
      for node in self.order_to_compile :
        func_obj = node.get_f_object()

        l1 = self.glb_func
        t1 = self.glb_typ_func
        h1 = self.hs_glb_func

        idx = h1[func_obj.full_name]

        h1[idx] = None
        l1[idx] = None
        t1[idx] = None
      
      self.order_to_compile = []

    else :
      if not self.order_to_compile :
        return None

      node = self.order_to_compile[-1]
      func_obj = node.get_f_object()

      func_kind = "function_internal"
      func_internal_objects = []

      for node_i in node.edge_out_fine.values() :
        func_obj_i = node_i.get_f_object()
        func_obj_i = self.find_func(func_obj_i.full_name)
        func_name = func_obj_i.name

        decl_as_ptr = func_obj_i.decl_as_ptr
        addr = func_obj_i.addr
        namespace = func_obj_i.namespace
        
        if addr == None :
          raise Exception(
            "Function '{}' was not compiled".format(func_obj_i.full_name)
          )

        func_internal_ext_call = self.parser.fy.factory(
          func_kind, func_name,
          0, "", 0, extra={"namespace":namespace}
        )

        func_internal_ext_call.addr = addr
        func_internal_ext_call.decl = decl_as_ptr
        func_internal_objects.append(
          func_internal_ext_call
        )

      func_obj.func_declare_list += func_internal_objects
      _ = self.order_to_compile.pop()

      return func_obj


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
      func_return = pre_func_return

    elif self.parser.func_type & POST_FUNC :
      declaration = "post_func #TODO"
      func_now = self.parser.post_func
      # da cambiare questa
      func_return = pre_func_return

    for entry in func_now :

      if isinstance(entry, obj_parser.TypeFunctionReturn) :
        continue

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
    
    return func_type, func_object.full_name, source_code


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



