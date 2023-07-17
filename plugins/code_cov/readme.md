

 - From gdb

```
hook-got-inline --data --create ./plugins/code_cov/gdbcov_data.c.bleed

hook-got-inline --create ./plugins/code_cov/gdbcov_init.c.bleed

hook-got-inline --create ./plugins/code_cov/gdbcov_entrypoint[x86_64].c.bleed

hook-got-inline --compile gdbcov.pre_func

hook-got-inline --inject gdbcov.pre_func fork

```


 - On traced process

```
$ ls

Main finishing gdbcov_setup's init routine
...
Agent spawned
...
```



