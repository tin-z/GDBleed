# Strategy #

The following doc illustrates the logic behind `hook-got-inline` set of commands. Which for now does only hooking and basic instrumentation, but in future it will be true binary instrumentation stuff.


### Terms

 - function-hooked : function to be hooked
 - function-hooking : new generated code hooking/instrumenting the function-hooked
 - shadow memory : new memory region added from gdbleed


### General ideas
 - We map three new region of memory called shadow memory
    * text : where new generated assembly code and trampoline points are saved
    * data : data
    * stack : here we save transitory data (no pthread support)

 - To hook/instrument functions we have only 2 type of function:
    * pre_func : observe a function-hooked before executing it
    * post_func : observe a function-hooked after executing it

 - pre_func is declared as:
```
# for intel x64
void * pre_func(void * __arg1__, void * __arg2__, void * __arg3__, void * __arg4__, void * __arg5__, void * __arg6__, unsigned long __fname_length__, char * __fname__, void * __fname_addr__, void * __ret_addr__, unsigned long __num_arg__, void * __sp_arg__);

# for the other archs
void * pre_func(void * __arg1__, void * __arg2__, void * __arg3__, void * __arg4__, unsigned long __fname_length__, char * __fname__, void * __fname_addr__, void * __ret_addr__, unsigned long __num_arg__, void * __sp_arg__);
```

 - post_func is declared as:

```
# for intel x64
void * pre_func(void * __arg1__, void * __arg2__, void * __arg3__, void * __arg4__, void * __arg5__, void * __arg6__, void * __rets__, unsigned long __fname_length__, char * __fname__, void * __fname_addr__, void * __ret_addr__, unsigned long __num_arg__, void * __sp_arg__);

# for the other archs
void * pre_func(void * __arg1__, void * __arg2__, void * __arg3__, void * __arg4__, void * __rets__, unsigned long __fname_length__, char * __fname__, void * __fname_addr__, void * __ret_addr__, unsigned long __num_arg__, void * __sp_arg__);
```


 - Based on these two functions, gdbleed builds 5 fixed types of trampoline points:
    * ONLY_PRE_FUNC : Call pre_func, then jump to function-hooked
    * RET_PRE_FUNC : Don't call function-hooked, call pre_func and return its return value
    * ONLY_POST_FUNC : Call function-hooked, post_func, then return function-hooked's return value
    * RET_POST_FUNC : Call function-hooked, then return post_func return value
    * ALL_FUNC : Call pre_func, function-hooked, post_func and then return function-hooked's return value


 - Before calling a trampoline point, the user needs to create its pre_func function, then gdbleed will create an injection point. The injection point is assembly code which will save function-hooked's arguments and stuff into stack shadow-memory, then will call the right trampoline point. Injection points are univoke for each function-hooked. Instead, trampoline points are saved in fixed memory areas.

    * The trampoline point will prepare the stack before calling the custom pre_func/function-hooked/post_func function.



#### The trampoline points approaches

 - `ONLY_PRE_FUNC` trampoline control flow: 
```
: caller
 0:'<function>'@GOT 
     \---> 1: Injection-point
            | 1.1: Prepare stack shadow memory
            \
             \---> 2: trampoline_point_<i> with i in [1..5]
                    | 2.1: save registers
                    | 2.2: prepare new stack frame and arguments
                    \
                     \---> 
                           3: CALL `pre_func` code 
                         /
                    <---/
                   2: trampoline_point_<i> (2)
                    | 2.3: restore registers and old stack frame
                    \
                     \---> 
                          4: JMP to `<function>` 
                         /
: caller            <---/
```


 - `RET_PRE_FUNC` control flow: 
```
: caller
 0:'<function>'@GOT 
     \---> 1: Injection-point
            | 1.1: Prepare stack shadow memory
            \
             \---> 2: trampoline_point_<i> with i in [1..5]
                    | 2.1: save registers
                    | 2.2: prepare new stack frame and arguments
                    \
                     \---> 
                           3: CALL `pre_func` code 
                         /
                    <---/
                   2: trampoline_point_<i> (2)
                    | 2.3: restore registers and old stack frame
                    | 2.4: set `pre_func`'s return value
                    \
                     \---> 
                          4: jump to return address
                         /
: caller            <---/
```


 - `ONLY_POST_FUNC` control flow :
```
: caller
 0:'<function>'@GOT 
     \---> 1: Injection-point
            | 1.1: Prepare stack shadow memory
            \
             \---> 2: trampoline_point_<i> with i in [1..5]
                    | 2.1: save registers
                    | 2.2: set return address as trampoline_point_<i>(2)
                    \
                     \---> 
                           3: jump <function>
                         /
                    <---/
                   2: trampoline_point_<i> (2)
                    | 2.3: save <function>'s return value
                    | 2.4: prepare new stack frame and arguments
                    \
                     \---> 
                          4: CALL `post_func` code
                         /
                    <---/
                   2: trampoline_point_<i> (3)
                    | 2.5: restore registers and old stack frame
                    | 2.6: set <function>'s return value
                    \
                     \---> 
                          5: jump to return address
                         /
: caller            <---/
```


 - `RET_POST_FUNC` control flow :
```
: caller
 0:'<function>'@GOT 
     \---> 1: Injection-point
            | 1.1: Prepare stack shadow memory
            \
             \---> 2: trampoline_point_<i> with i in [1..5]
                    | 2.1: save registers
                    | 2.2: set return address as trampoline_point_<i>(2)
                    \
                     \---> 
                           3: jump <function>
                         /
                    <---/
                   2: trampoline_point_<i> (2)
                    | 2.3: save <function>'s return value
                    | 2.4: prepare new stack frame and arguments
                    \
                     \---> 
                          4: CALL `post_func` code
                         /
                    <---/
                   2: trampoline_point_<i> (3)
                    | 2.5: restore registers and old stack frame
                    | 2.6: set `post_func`'s return value
                    \
                     \---> 
                          5: jump to return address
                         /
: caller            <---/
```

 - `ALL_FUNC` control flow:

    * Do `ONLY_PRE_FUNC` and `ONLY_POST_FUNC` both



### .c.bleed "scripting" ###

An user can inject pre_func and post_func functions as .bleed scripts, by invoking the command :

```
gef> hook-got-inline --create <path-to-example.c.bleed>
```

We can't declare variables that will be put on data-type ELF sections, so instead we should keep pre_func and post_func functions as simple as possible. Gdbleed supports a limited type of variable types. To overcome this limitation, before declaring pre_func and post_func, we declare internal functions. We don't link the source code but just compile it in object code. If we need to call a library function we need to declare it in `@@external-functions@@` sections, then gdbleed will resolve the address and save it into source code before making it into object file.


For more information read the following doc:

 - Declaring static data, https://github.com/tin-z/GDBleed/blob/main/example/bleed_example/declare_static_data.c.bleed

 - Declaring internal functions, https://github.com/tin-z/GDBleed/blob/main/example/bleed_example/internal_func.c.bleed

 - Declaring pre_func, https://github.com/tin-z/GDBleed/blob/main/example/bleed_example/readme.c.bleed


</br>

**Steps during a .c.bleed file parsing**

1. Parse sections, a section does start with `--`

</br>

2. Parse `--declare--` section first. Here we declare variables and functions (externals and locals)

 - `@@types@@` : define types (TODO, for now declare them using internal functions)

 - `@@vars@@` : key-value mapping, for now supporting numerical types, `void *` and `char *` also

 - `@@external-functions@@` : external functions (libc, but not limited to that) which our script depends on

</br>

3. Parse `--code--` section. Here we write down the local functions and the functions pre_func and post_func. Because of some constraints only one type of function would be compiled.

 - `@@functions@@` : static functions

 - `@@pre_func@@` : code executed before calling the hooked function

 - `@@post_func@@` : code executed after the hooked function returns (#TODO)

</br>

4. `pre_func` notes
 
  - function declaration:
```
void * pre_func(
  void * __arg1__, 
  void * __arg2__, 
  void * __arg3__, 
  void * __arg4__, 
#ifdef IS_x86_64
  void * __arg5__, 
  void * __arg6__, 
#endif
  unsigned long __fname_length__, 
  char * __fname__, 
  void * __fname_addr__, 
  void * __ret_addr__,
  unsigned long __num_arg__, 
  void * __sp_arg__
);
```

 - argument of the hooked function meaning:
    * `__arg1__` : 1st arg
    * `__arg2__` : 2nd arg
    * `__arg3__` : 3rd arg
    * `__arg4__` : 4th arg
    * `__arg5__` : 5th arg (only available for x86_64 arch) 
    * `__arg6__` : 6th arg (only available for x86_64 arch)
    * `__fname_length__`  : name length of the function-hooked 
    * `__fname__`         : address of the function-hooked name
    * `__fname_addr__`    : address of the function-hooked function
    * `__ret_addr__`      : original return address
    * `__num_arg__`       : the number of arguments given to the hooked function (TODO)
    * `__sp_arg__`        : stack pointer where the other arguments of the hooked function were saved
    * `__rets__`          : return value after calling the hooked function (only available in post_func function)




