
void write_memory(unsigned int pid, unsigned long long offset, unsigned int length, char * buf, int * retcode);
char * read_memory(int ptrace_mode, unsigned int pid, unsigned long long offset, unsigned int length, int * retcode);

