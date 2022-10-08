from ast import literal_eval

from core.parser._exception import ParserException, WrongDeclarationParser
from core.parser._constants import *



class FactoryTypes :
  def __init__(self) :
    self.map = {
      "char" : TypeByte_s ,\
      "short" : TypeShort_s ,\
      "int" : TypeInt_s ,\
      "long" : TypeLong_s ,\
      "unsigned char" : TypeByte ,\
      "unsigned short" : TypeShort ,\
      "unsigned int" : TypeInt ,\
      "unsigned long" : TypeLong ,\
      "char *" : TypeString ,\
      "void *" : TypePointer ,\
      "blob" : TypePointer ,\
      "__static__" : TypePointer ,\
      "function" : TypeExtFunction ,\
      "function_internal" : TypeInternalFunction ,\
      "function_call" : TypeFunctionCall ,\
      "return" : TypeFunctionReturn
    }

  def factory(self, var_type, var_name, var_value=None, line_num=0, line=0, extra={}) :
    #hack
    if 0 :
      print("Factory: ")
      print("var_type: ", var_type)
      print("var_name: ", var_name)
      print("var_value: ", var_value)
      print("line_num: ", line_num)
      print("line: ", line)
      print()
    #hack
    if var_type not in self.map :
      raise WrongDeclarationParser("Invalid type declaration", line_num, line)

    if var_type == "return" :
      return self.map[var_type](line_num, line)

    if var_type != "function_call" :

      if var_type == "function_internal" :
        tmp_obj = self.map[var_type](extra["namespace"], var_name, var_value, line_num, line)
        return tmp_obj

      elif var_type == "__static__" :
        return self.map[var_type](var_name, var_value, line_num, line, internal=True)
      
      elif var_type == "blob" :
        tmp_obj = self.map[var_type](var_name, var_value, line_num, line)
        tmp_obj.set_blob(var_value)
        return tmp_obj

      else :
        return self.map[var_type](var_name, var_value, line_num, line)

    else :
      func_object = var_name
      num_arguments = var_value
      arguments = extra["arguments"]
      assign_to = extra["assign_to"]
      return TypeFunctionCall(func_object, num_arguments, line_num, line, arguments, assign_to)



class TypeFunctionCall :

  def __init__(self, func_object, num_arguments, line_num, line, arguments=[], assign_to=None) :
    self.func_object    = func_object
    self.num_arguments  = num_arguments
    self.line_num       = line_num
    self.line           = line
    self.arguments      = arguments
    self.assign_to      = assign_to
    self.line_num       = line_num
    self.line           = line

  def __str__(self) :
    return self.line


class TypeFunctionReturn :

  def __init__(self, line_num, line) :
    self.line_num       = line_num
    self.line           = line

  def __str__(self) :
    return self.line



class TypeExtFunction :

  decl = [ "void * (*{})()", "void * (*{})(void *)", "void * (*{})(void *, ...)" ]

  def __init__(self, func_name, num_of_args, line_num, line, addr=None) :
    if num_of_args < 0 or num_of_args > 2 :
      raise WrongDeclarationParser("Invalid 'num_of_args' argument (valid range [0..2])", line_num, line)

    self.func_name = func_name
    self.num_of_args = num_of_args
    self.line_num = line_num
    self.line = line
    self.addr = addr

  def get_decl(self) :
    return TypeExtFunction.decl[self.num_of_args].format(self.func_name)

  def __str__(self) :
    if self.addr :
      return "{} = 0x{:x};".format(self.get_decl(), self.addr)
    else :
      return "{} = <NONE>;".format(self.get_decl())


class TypeInternalFunction :

  def __init__(self, namespace, func_name, num_of_args, line_num, line, addr=None, decl=None) :
    if num_of_args < 0 or num_of_args > 2 :
      raise WrongDeclarationParser("Invalid 'num_of_args' argument (valid range [0..2])", line_num, line)

    self.namespace = namespace
    self.func_name = func_name
    self.num_of_args = num_of_args
    self.line_num = line_num
    self.line = line
    self.addr = addr
    self.decl = decl
    self.full_name = "{}.{}".format(self.namespace, self.func_name)

  def get_decl(self) :
    return self.decl

  def __str__(self) :
    if self.addr :
      return "{} = 0x{:x};".format(self.get_decl(), self.addr)



class TypeBase :
  def __init__(self, var_type, var_name, var_value, line_num, line, size=None, addr=None) :
    self.var_type = var_type
    self.var_name = var_name
    self.var_value = var_value
    self.line_num = line_num
    self.line = line
    self.size = size
    self.addr = addr

  def addr_is_none(self) :
    return not self.addr

  def __str__(self):
    return self.line

  def is_internal(self):
    if "internal" in dir(self) :
      return self.internal
    else :
      return False


class TypeNumerical(TypeBase) :

  def __init__(self, var_type, var_name, var_value, line_num, line, size=None, addr=None, signed=False) :
    self.size = size
    self.signed = signed
    try :
      # default value if non-initialized numerical type
      if var_value == "" :
        var_value = 0
      else :
        var_value = self.repr_number(var_value)
    except :
      raise WrongDeclarationParser("Invalid {} Numerical variable declaration".format(types_list[var_type]), line_num, line)

    try :
      self.check_number(var_value)
    except :
      raise WrongDeclarationParser("Invalid {} Numerical variable size/check".format(types_list[var_type]), line_num, line)

    super(TypeNumerical, self).__init__(var_type, var_name, var_value, line_num, line, size, addr)

  def check_number(self, var_value):
    if self.signed :
      if var_value < -(2**(self.size-1)) or var_value > (2**(self.size-1) - 1) :
        raise Exception()
    else :
      if var_value > 2**self.size - 1 :
        raise Exception()
    self.check_number_post(var_value)

  def check_number_post(self, var_value):
    pass

  def repr_number(self, var_value):
    if var_value.startswith("0x") :
      var_value = int(var_value, 16)
    else :
      var_value = int(var_value)
    return var_value


class TypeByte (TypeNumerical) :
  def __init__(self, var_name, var_value, line_num, line, addr=None, signed=False) :
    var_type=t_BYTE
    size = default_types_size[var_type][0]
    super(TypeByte, self).__init__(var_type, var_name, var_value, line_num, line, addr=addr, size=size, signed=signed)

class TypeByte_s (TypeByte) :
  def __init__(self, var_name, var_value, line_num, line, addr=None) :
    var_type=t_BYTE
    size = default_types_size[var_type][0]
    signed = True
    super(TypeByte_s, self).__init__(var_name, var_value, line_num, line, addr=addr, signed=signed)


class TypeShort (TypeNumerical) :
  def __init__(self, var_name, var_value, line_num, line, addr=None, signed=False) :
    var_type=t_SHORT
    size = default_types_size[var_type][0]
    super(TypeShort, self).__init__(var_type, var_name, var_value, line_num, line, addr=addr, size=size, signed=signed)

class TypeShort_s (TypeShort) :
  def __init__(self, var_name, var_value, line_num, line, addr=None) :
    var_type=t_SHORT
    size = default_types_size[var_type][0]
    signed = True
    super(TypeShort_s, self).__init__(var_name, var_value, line_num, line, addr=addr, signed=signed)


class TypeInt (TypeNumerical) :
  def __init__(self, var_name, var_value, line_num, line, addr=None, signed=False) :
    var_type=t_INT
    size = default_types_size[var_type][0]
    super(TypeInt, self).__init__(var_type, var_name, var_value, line_num, line, addr=addr, size=size, signed=signed)

class TypeInt_s (TypeInt) :
  def __init__(self, var_name, var_value, line_num, line, addr=None) :
    var_type=t_INT
    size = default_types_size[var_type][0]
    signed = True
    super(TypeInt_s, self).__init__(var_name, var_value, line_num, line, addr=addr, signed=signed)


class TypeLong (TypeNumerical) :
  def __init__(self, var_name, var_value, line_num, line, addr=None, signed=False) :
    var_type=t_LONG
    size = default_types_size[var_type][0]
    super(TypeLong, self).__init__(var_type, var_name, var_value, line_num, line, addr=addr, size=size, signed=signed)

class TypeLong_s (TypeLong) :
  def __init__(self, var_name, var_value, line_num, line, addr=None) :
    var_type=t_LONG
    size = default_types_size[var_type][0]
    signed = True
    super(TypeLong_s, self).__init__(var_name, var_value, line_num, line, addr=addr, signed=signed)


class TypePointer (TypeNumerical) :
  def __init__(self, var_name, var_value, line_num, line, addr=None, signed=False, internal=False) :
    var_type=t_POINTER
    size = default_types_size[var_type][0]
    self.internal = internal
    super(TypePointer, self).__init__(var_type, var_name, var_value, line_num, line, addr=addr, size=size, signed=signed)

  def set_blob(self, size):
    base = 16 if size.startswith("0x") else 10
    self.size_ref_to = int(size, base)

  def is_blob(self):
    return "size_ref_to" in dir(self)

  def __str__(self):
    output = "void * {}".format(self.var_name)
    if self.addr :
      output += " = 0x{:x}".format(self.addr)
    output += ";"
    if self.is_blob() :
      output += " // size=0x{:x}".format(self.size_ref_to)
    return output


class TypeString (TypeBase) :
  def __init__(self, var_name, var_value, line_num, line, addr=None, append_null=True) :
    if not ( var_value.startswith("\"") and var_value.endswith("\"") ) :
      raise WrongDeclarationParser("Invalid STRING variable declaration", line_num, line)
    var_value = literal_eval(var_value)
    if append_null :
      var_value += "\0"
    var_type= t_STRING
    size = len(var_value) + 1
    super(TypeString, self).__init__(var_type, var_name, var_value, line_num, line, size=size, addr=addr)

  def __str__(self):
    output = "char * {} = 0x{:x};".format(self.var_name, self.addr)
    if self.size :
      output += " // size=0x{:x}".format(self.size)
    return output


class Section :
  def __init__(self, name, start_line_number, data=None) :
    self.name = name
    self.data = data
    self.start_line_number = start_line_number
    self.end_line_number = 0
    self.tags = []
    self.tags_dict = {}

  def add_tag(self, tag_class) :
    self.tags.append(tag_class)
    self.tags_dict[tag_class.name] = tag_class

  def set_start(self, number) :
    self.start_line_number = number

  def set_end(self, number) :
    self.end_line_number = number
    self.set_end_prev_tag(number)

  def set_end_prev_tag(self, number) :
    if self.tags :
      self.tags[-1].set_end(number)
  
  def set_data(self, data) :
    self.data = data[self.start_line_number : self.end_line_number]
    for tag in self.tags :
      tag.data = data[tag.start_line_number : tag.end_line_number]

  def update_line_number(self) :
    """
      increment by one line numbers
    """
    self.start_line_number += 2
    for tag in self.tags :
      tag.start_line_number += 2


class Tag:
  def __init__(self, name, start_line_number, data=None) :
    self.name = name
    self.data = data
    self.start_line_number = start_line_number
    self.end_line_number = 0

  def set_start(self, number) :
    self.start_line_number = number

  def set_end(self, number) :
    self.end_line_number = number


