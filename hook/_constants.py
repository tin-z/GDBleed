

ONLY_PRE_FUNC = 0x1
"""
Call pre_func, then jump to function-hooked
"""

RET_PRE_FUNC = 0x2
"""
Don't call function-hooked, call pre_func and return its return value
"""

ONLY_POST_FUNC = 0x4
"""
Call function-hooked, post_func, then return function-hooked's return value
"""

RET_POST_FUNC = 0x8
"""
Call function-hooked, then return post_func return value
"""

ALL_FUNC = 0x10
"""
Do pre_func and post_func both
"""



