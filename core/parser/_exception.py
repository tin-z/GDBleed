

class ParserException(Exception) :
  def __init__(self, msg, line_num, line) :
    super(ParserException, self).__init__(msg)
    self.pre_msg = "[X] [parser]"
    self.msg = msg
    self.line_num = line_num
    self.line = line
  
  def __str__(self) :
    return "{} - {} at line '{}:{}'".format(self.pre_msg, self.msg, self.line_num, self.line)
  
  def __repr__(self) :
    return "{}('{}','{}','{}')".format(self.__class__.__name__, self.msg, self.line_num, self.line)


class WrongDeclarationParser(ParserException) :
  def __init__(self, msg, line_num, line) :
    super(WrongDeclarationParser, self).__init__(msg, line_num, line)
    self.pre_msg += " [declaration]"
 



