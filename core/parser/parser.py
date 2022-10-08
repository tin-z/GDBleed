# -*- coding: utf-8 -*-
import re

from core.parser._exception import ParserException, WrongDeclarationParser
from core.parser.parse_file import parse_blade
from core.parser.objects import FactoryTypes

from core.parser._constants import  re_match_declare ,\
                                    re_match_create_struct, re_match_comment,\
                                    re_match_unsigned_declare, re_match_string_declare,\
                                    re_match_empty, re_match_ext_function ,\
                                    re_match_function_ret_val, re_match_function ,\
                                    re_match_ext_internal_function ,\
                                    re_match_declare_global ,\
                                    re_match_pointer_declare ,\
                                    re_match_internal_func_decl ,\
                                    re_match_function_return ,\
                                    special_symbols ,\
                                    PRE_FUNC , POST_FUNC , INTERNAL_FUNC


class Parser :

  metadata_list = [
    "#+Function_name:" ,\
    "#+Description:"
  ]

  internal_func_metadata_list = [
    "#+define:" ,\
    "#+function:"
  ]

  def __init__(self, details, details_mem, details_data):
    self.details = details
    self.details_mem = details_mem
    self.details_data = details_data
    self.fy = FactoryTypes()
    self.reset()

  
  def reset(self) :
    self.hs_vars = dict()
    self.hs_ext_func = dict()
    self.hs_structs = dict()
    self.last_error = None
    self.pre_func = []
    self.post_func = []
    self.internal_func = []
    self.line_num = 0
    self.line = ""
    self.func_type = None
    self.func_name = None
    self.func_desc = None


  def _update_line(self, line_num, line) :
    self.line_num = line_num
    self.line = line


  def resolve_struct(self, v):
    """
      #TODO:
        - for each element do tree walk, leaf are base-types
    """
    raise ParserException("#TODO: resolve_struct method", self.line_num, self.line)


  def parse_types(self, data) :
    #TODO
    pass


  def parse_empty_line(self):
    for match_now in [re_match_comment, re_match_empty] :
      reg_now = re.search(match_now, self.line)
      if reg_now :
        return True
    return False

  def parse_declaration(self):
    for match_now in [
        re_match_unsigned_declare,\
        re_match_declare,\
        re_match_string_declare,\
        re_match_pointer_declare
      ]:

      reg_now = re.search(match_now, self.line)

      if reg_now :
        var_type, var_name, var_value = reg_now.groups()
        var_type = re.sub("[ ]+", " ", var_type)

        if var_name in self.hs_vars :
          raise ParserException("Variable name already defined", self.line_num, self.line)

        self.hs_vars[var_name] = self.fy.factory(var_type, var_name, var_value, self.line_num, self.line)
        return self.hs_vars[var_name]

    match_now = re_match_declare_global
    reg_now = re.search(match_now, self.line)
    if reg_now :
      var_name, var_value = reg_now.groups()
      var_type = "void *"
      self.hs_vars[var_name] = self.fy.factory(var_type, var_name, var_value, self.line_num, self.line)

    else :
      return None


  def parse_vars(self, vars_declare) :
    """
      Parse vars declarations
    """
    data = vars_declare.data[1:]
    start_line = vars_declare.start_line_number

    for line_num, line in enumerate(data) :
      line_num += start_line
      self._update_line(line_num, line)

      rets = self.parse_declaration()
      if rets is None :
        rets = self.parse_empty_line()
        if not rets :
          raise ParserException("Can't find declaration symbol", self.line_num, self.line)


  def parse_external_func(self, vars_external_func) :
    """
      Parse external-functions declarations
    """
    data = vars_external_func.data[1:]
    start_line = vars_external_func.start_line_number

    for line_num, line in enumerate(data) :
      line_num += start_line
      self._update_line(line_num, line)

      reg_now = re.search(re_match_ext_function, self.line)
      func_kind = "function"
      h1 = self.hs_ext_func
      if not reg_now :
        reg_now = re.search(re_match_ext_internal_function, self.line)
        func_kind = "function_internal"

      if reg_now :
        if func_kind != "function_internal" :
          func_name, num_arg = reg_now.groups()
          num_arg = int(num_arg)
          h1[func_name] = self.fy.factory(func_kind, func_name, num_arg, self.line_num, self.line)

        else :
          namespace, func_name, num_arg = reg_now.groups()
          num_arg = int(num_arg)
          h1[func_name] = self.fy.factory(func_kind, func_name, num_arg, self.line_num, self.line, extra={"namespace":namespace})

      else :
        rets = self.parse_empty_line()
        if not rets :
          raise ParserException("Can't find external-function declaration symbol", self.line_num, self.line)


  def find_var(self, var_name, check_special_char=False) :
    if var_name :
      if var_name not in self.hs_vars :
        if check_special_char and var_name in special_symbols :
          return var_name
        else :
          raise ParserException("Variable '{}' was not defined on declare section. Invalid assignment".format(var_name), self.line_num, self.line)
      else :
        return self.hs_vars[var_name]
    return var_name


  def parse_function_call(self, fname):
    output = None
    if fname in self.hs_ext_func :
      output = self.hs_ext_func[fname]
    else :
      raise ParserException("Can't find '{}' function declaration".format(fname), self.line_num, self.line)
    return output

  def parse_function_call_arguments(self, raw_args):
    output = []
    for x in raw_args.split(",") :
      x = x.strip()

      if x in [str(x) for x in range(10)] :
        if x.startswith("0x") :
          x = int(x, 16)
        else :
          x = int(x)
      else :
        x = self.find_var(x, check_special_char=True)

      output.append(x)

    return len(output), output


  def parse_code_section(self, code_sec):
    """
      Parse code section, which could be one fo the following type:
        - internal function : can't hook stuff, but is called by "hooking" functions
        - pre_func function : called before the function hooked
        - post_func function : called after the function hooked returns
    """
    # TODO: better solution here

    self.func_type = PRE_FUNC
    self.parse_code_section_pre_func(code_sec)

    if self.pre_func == [] :
      self.func_type = POST_FUNC
      self.parse_code_section_post_func(code_sec)

      if self.post_func == [] :
        self.func_type = INTERNAL_FUNC
        self.parse_code_section_function(code_sec)

        if self.internal_func == [] :
          raise ParserException(
            "Can't find the function declaration inside the code section"
          )


  def parse_code_section_function(self, code_sec):
    functions = code_sec.tags_dict["function"]
    data = functions.data[1:]

    define_section = Parser.internal_func_metadata_list[0]
    func_section = Parser.internal_func_metadata_list[1]

    data = "\n".join(data)
    data = data.split(define_section)
    if len(data) < 2 :
      raise ParserException(
        "Can't find '{}' internal function tag".format(define_section),
        0, ""
      )

    data = data[1] 
    data = data.split(func_section)
    if len(data) < 2 :
      raise ParserException(
        "Can't find '{}' internal function tag".format(func_section), 
        0, ""
      )

    define_section_data = [data[0]]
    func_section_data = []

    for x in data[1:] :
      data = x.split("\n")
      decl_index = None
      end_decl_index = None
      body_index = None
      func_name = None

      for i,line in enumerate(data) :
        self._update_line(i, line)
        reg_now = self.parse_empty_line()
        
        if decl_index == None :

          if not reg_now :
            match_now = re_match_internal_func_decl
            reg_now = re.search(match_now, self.line)

            if not reg_now :
              raise ParserException(
                "Can't find decl internal function",
                i, line
              )
           
            _, func_name = reg_now.groups()
            decl_index = i
            if self.line.strip().endswith("{") :
              end_decl_index = i

        elif end_decl_index == None :

          if not reg_now :
            if not self.line.strip().startswith("{") :
              raise ParserException(
                "Can't find decl '{' internal function",
                i, line
              )

            else :
              end_decl_index = i

        else :
          body_index = i
          break

      func_section_data.append(
        (func_name, "\n".join(data[decl_index:end_decl_index+1]), "\n".join(data[body_index:]))
      )
 
    self.internal_func = define_section_data + func_section_data



  def parse_code_section_post_func(self, code_sec):
    return self.parse_code_section_pre_or_post_func(code_sec, pre_func_flg=False)

  def parse_code_section_pre_func(self, code_sec):
    return self.parse_code_section_pre_or_post_func(code_sec)

  def parse_code_section_pre_or_post_func(self, code_sec, pre_func_flg=True):
    select = "pre_func" if pre_func_flg else "post_func"

    func_now = code_sec.tags_dict[select]
    data = func_now.data[1:]
    start_line = code_sec.start_line_number

    for line_num, line in enumerate(data) :
      line_num += start_line
      self._update_line(line_num, line)

      extra = {
        "arguments" : [] ,\
        "assign_to" : None
      }
      var_name = None

      match_now = re_match_function_ret_val
      reg_now = re.search(match_now, self.line)
      if reg_now :
        var_name, func_name, args = reg_now.groups()
      else :
        match_now = re_match_function
        reg_now = re.search(match_now, self.line)
        if reg_now :
          func_name, args = reg_now.groups()

      if not reg_now :
        match_now = re_match_function_return
        reg_now = re.search(match_now, self.line)

        if not reg_now :
          rets = self.parse_empty_line()
          if rets is None :
            raise ParserException("Can't parse/find function call symbol", self.line_num, self.line)
          continue

        func_call_object = self.fy.factory("return", "", 0, self.line_num, self.line, extra=extra)

      else :
        extra["assign_to"] = self.find_var(var_name)
        func_name = self.parse_function_call(func_name)
        num_args, arguments = self.parse_function_call_arguments(args)
        extra["arguments"] = arguments
        func_call_object = self.fy.factory("function_call", func_name, num_args, self.line_num, self.line, extra=extra)

      if pre_func_flg :
        self.pre_func.append(func_call_object)
      else :
        self.post_func.append(func_call_object)

  
  def parse_header(self):
    output = {k:None for k in Parser.metadata_list}
    data = self.sections["skip"].data
    for x in data:
      for k in output :
        if x.startswith(k) :
          output[k] = x.split(k)[1].strip()
          break
    self.func_name = output[Parser.metadata_list[0]]
    self.func_desc = output[Parser.metadata_list[1]]
    if not (self.func_name and self.func_name) :
      raise ParserException("Metadata missing on skip section.")


  def parse(self):
    self.parse_header()
    declare_sec = self.sections["declare"]
    self.parse_vars(declare_sec.tags_dict["vars"])
    self.parse_external_func(declare_sec.tags_dict["external-functions"])
    self.parse_code_section(self.sections["code"])


  def invoke(self, file_path=None, is_data=False) :

    output = []

    if not file_path :
      self.details["slog"].append(
        "Insert gdbleed script (Insert 'EOF' line to terminate reading input)"
      )

      rets = ""
      while True :
        rets = input().strip()
        if rets == "EOF" :
          break
        output.append(rets)

    else :
      fp = open(file_path, "r")
      output += fp.read().split("\n")

    try :
      if not is_data :
        skip_section, declare_section, code_section = parse_blade(output)
        self.sections = { "skip":skip_section, "declare":declare_section, "code":code_section }
        self.parse()

      else :
        #
        class FakeObj_tmp:
          def __init__(self, data, start_line_number=0):
            self.data = ["ignore"] + data
            self.start_line_number = start_line_number
        #
        self.parse_vars(FakeObj_tmp(output))

    except ParserException as ex :
      self.last_error = ex



