# -*- coding: utf-8 -*-

from utils.colorsX import *
from utils.utilsX import *



class lambdaRule :
  """
      Check function's arguments/state during execution
  """
  def __init__(self, flambda, fname, desc):
    self.flambda = flambda
    self.fname = fname
    self.desc = desc

  def check(self, args, ret_value):
    self.last_args = args
    self.last_ret_value = ret_value
    return self.flambda(args, ret_value)

  def report(self):
    return WARNING("[!]") + PTR['L'](" Warning") + ": {}\n {}({}) -> {}\n".format(
            self.desc, PTR['H2'](self.fname), ",".join([hex(x) for x in self.last_args]), self.last_ret_value
    )

  def skel_eval_a_lambdaRule(args, ret_value):
    pass


class alertRules :
  """
      lambdaRule sets
  """
  def __init__(self) :
    self.rules = {}
  
  def add(self, lambda_rule) :
    fname = lambda_rule.fname
    if fname not in self.rules :
        self.rules[fname] = []
    self.rules[fname].append(lambda_rule)

  def check(self, fname, args=None, ret_value=None) :
    if fname not in self.rules :
        self.rules[fname] = []
    for check_i in self.rules[fname] :
        if check_i.check(args, ret_value) :
            slog.append(check_i.report())


