# -*- coding: utf-8 -*-
from hook.default_hooks import GeneralHook




class Sleep (GeneralHook) :
    fname = "sleep"

    """
      Simple example of GOT hijacking using sleep function
    """

    def __init__(self, details, details_data, regs_) :
        super(Sleep, self).__init__(details, details_data, regs_, Sleep.fname)


default_list = {Sleep.fname : Sleep}

