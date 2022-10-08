# -*- coding: utf-8 -*-
import re

from core.parser._constants import  PRE_FUNC ,\
                                    POST_FUNC ,\
                                    INTERNAL_FUNC


class WrapFunction:

  def __init__( 
      self, Id, func_type,
      name, namespace, description, 
      declaration, 
      addr=None, used_by_function=[], hooking_function=[]
    ): 

    self.Id = Id
    self.func_type = func_type
    self.name = name
    self.namespace = namespace
    self.description = description
    self.declaration = declaration
    self.addr = addr 
    self.used_by_function = used_by_function
    self.hooking_function = hooking_function
    self.source_code = None
    self.full_name = "{}.{}".format(self.namespace, self.name)
    self.code = []
    self.header = []
   

  def update_declare_lists(
      self, func_declare_list,\
      vars_list, function_calls_list,\
      func_return
    ):
    
    self.func_declare_list = func_declare_list
    self.vars_list = vars_list
    self.function_calls_list = function_calls_list
    self.func_return = func_return


  def update_header(self, define_section_data):
    self.header = define_section_data


  def update_addr_func(self, addr, code):
    self.addr = addr
    self.code = code


  def is_ready(self):
    return self.addr != None and self.code != []

         
  def _make_source_code(self):
    output = []
    if self.header :
      output.append("\n".join(self.header))
    output.append(self.declaration)
    output.append("\n".join( [ str(x) for x in self.func_declare_list ]))
    output.append("\n".join( [ str(x) for x in self.vars_list ]))
    output.append("// ## code starts from here:")
    output.append("\n".join( [ str(x) for x in self.function_calls_list ]))
    output.append(self.func_return)
    self.source_code = "\n".join(output)


  def get_source_code(self, repeat=False):
    if repeat or self.source_code == None :
      self._make_source_code()
    return self.source_code


class PreFunction(WrapFunction):
  def __init__( 
      self, Id, namespace, description, 
      declaration, 
      addr=None, used_by_function=[], hooking_function=[]
    ): 

    super(PreFunction, self).__init__(
      Id, PRE_FUNC,
      "pre_func", namespace, description, 
      declaration, 
      addr, used_by_function, hooking_function
    )
     
class PostFunction(WrapFunction):
  def __init__( 
      self, Id, namespace, description, 
      declaration, 
      addr=None, used_by_function=[], hooking_function=[]
    ): 

    super(PostFunction, self).__init__(
      Id, POST_FUNC,
      "post_func", namespace, description, 
      declaration, 
      addr, used_by_function, hooking_function
    )
 
class InternalFunction(WrapFunction):
  def __init__( 
      self, Id, func_name, namespace, description, 
      declaration, 
      addr=None, used_by_function=[], using_function=[]
    ): 
    """
      used_by_function  : var used by pre_func and post_func functions to declare 
                          if they use this internal function
      using_function    : var used to declare only internal functions used by this function
    """
    super(InternalFunction, self).__init__(
      Id, INTERNAL_FUNC,
      func_name, namespace, description, 
      declaration, 
      addr, used_by_function, using_function
    )
    self.decl_as_ptr = None
    self.declaration_as_pointer()
 

  def declaration_as_pointer(self):
    if not self.decl_as_ptr :
    
      rets = re.split(
        "(?<![A-z0-9_.])({})(?![A-z0-9_.])".format(self.name), 
        self.declaration
      )

      self.decl_as_ptr = "{} * (*{}) {}".format(rets[0].strip(), self.name, rets[2])
      self.decl_as_ptr = self.decl_as_ptr.strip()[:-1].strip()


