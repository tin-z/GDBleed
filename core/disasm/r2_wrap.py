

// per ogni funzione voglio addr, type "fcn", calltype, bits, datarefs, callrefs, signature etc... tutto quello che può essere usato anche per thumb mode
[{"offset":85216,"name":"entry0","size":44,"is-pure":"false","realsz":44,"noreturn":false,"stackframe":0,"calltype":"arm32","cost":33,"cc":1,"bits":32,"type":"fcn","nbbs":1,"edges":0,"ebbs":1,"signature":"entry0 (int32_t arg1, int argc);","minbound":85216,"maxbound":85260,"callrefs":[{"addr":82540,"type":"CALL","at":85256}],"datarefs":[85264,85268,85272],"indegree":0,"outdegree":1,"nlocals":0,"nargs":2,"bpvars":[],"spvars":[],"regvars":[{"name":"arg1","kind":"reg","type":"int32_t","ref":"r0"},{"name":"argc","kind":"reg","type":"int","ref":"r1"}],"difftype":"new"},

{"offset":82540,"name":"sym.imp.__libc_start_main","size":12,"is-pure":"true","realsz":12,"noreturn":false,"stackframe":0,"calltype":"arm32","cost":6,"cc":1,"bits":32,"type":"sym","nbbs":1,"edges":0,"ebbs":1,"signature":"int sym.imp.__libc_start_main (func main, int argc, char **ubp_av, func init, func fini, func rtld_fini, void *stack_end);","minbound":82540,"maxbound":82552,"codexrefs":[{"addr":85256,"type":"CALL","at":82540}],"dataxrefs":[],"indegree":1,"outdegree":0,"nlocals":0,"nargs":0,"bpvars":[],"spvars":[],"regvars":[],"difftype":"new"}

,{"offset":394216,"name":"sym._fini","size":8,"is-pure":"true","realsz":8,"noreturn":false,"stackframe":8,"calltype":"arm32","cost":3,"cc":1,"bits":32,"type":"sym","nbbs":1,"edges":0,"ebbs":1,"signature":"sym._fini ();","minbound":394216,"maxbound":394224,"indegree":0,"outdegree":0,"nlocals":0,"nargs":0,"bpvars":[],"spvars":[],"regvars":[],"difftype":"new"}