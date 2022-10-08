# -*- coding: utf-8 -*-

"""
Color stuff
"""

EC = '\x1b[0m'
BOLD = '\x1b[1m'
INIT = {'f':30,'b':40,'hf':90,'hb':100}
COLORS = ("BLACK",0),("RED",1),("GREEN",2),("YELLOW",3),("BLUE",4),("CYAN",6)
for x,y in COLORS :
  globals()[x] = {k:"\x1b[{}m".format(v+y) for k,v in INIT.items()}

FAIL = lambda x : BOLD + RED['f'] + x + EC
WARNING = lambda x : BOLD + YELLOW['b'] + BLACK['f'] + x + EC
PTR = {"H":lambda x : BLUE['f'] + x + EC, "S": lambda x : YELLOW['hf'] + x + EC, "L" : lambda x : RED['f'] + x + EC }
PTR.update( { "HEAP":PTR["H"], "STACK":PTR["S"], "LIBC":PTR["L"] } )
PTR.update( { "H1":lambda x : BLUE['hf'] + x + EC, "H2":lambda x : CYAN['f'] + x + EC, "H3":lambda x : CYAN['hf'] + x + EC })
PTR.update( { "F1":lambda x : BOLD + RED['f'] + BLACK['b'] + "|{}|".format(x) + EC } )
PTR.update( { "F2":lambda x : BOLD + GREEN['f'] + BLACK['b'] + "|{}|".format(x) + EC } )


