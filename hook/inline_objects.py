
from hook._constants import   ONLY_PRE_FUNC ,\
                              ONLY_POST_FUNC ,\
                              ALL_FUNC ,\
                              RET_PRE_FUNC ,\
                              RET_POST_FUNC



class InjPoint :

  def __init__(self, addr, size, called_from=None, calling=[], inj_typ=ONLY_PRE_FUNC):
    self.addr = addr
    self.size = size
    self.called_from = called_from
    self.calling = calling
    self.inj_typ = inj_typ





