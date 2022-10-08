#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ptrace.h>

#include "proc_dump.h"


/* author: tin-z
 * some inspiration from https://unix.stackexchange.com/questions/6301/how-do-i-read-from-proc-pid-mem-under-linux
 *
 * */

ssize_t read(int fd, void *buf, size_t count);
off_t lseek(int fd, off_t offset, int whence);
pid_t waitpid(pid_t pid, int *wstatus, int options);
int strcmp(const char *s1, const char *s2);
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
int fclose(FILE *stream);
int close(int fd);



int main(int argc, char *argv[]){

  int ptrace_mode = 0;

  if(argc<4) {
    printf("Usage %s <pid> <offset> <length> [--ptrace]\n", argv[0]);
    return 255;
  } else if(argc==5) {
    if(!strcmp(argv[4], "--ptrace")){
      ptrace_mode = 1;
    }
  }

  unsigned int pid = atoi(argv[1]);
  unsigned long long offset = atoll(argv[2]);
  unsigned int length = atoll(argv[3]);
  int retcode = 0;

  printf("[-] Inserted pid:%d, offset:%llu, length:%d  -- ptrace_mode:%d\n", pid, offset, length, ptrace_mode);

  char * data_readen = read_memory(ptrace_mode, pid, offset, length, &retcode);

  if (!retcode){
    puts("[+] Done!\n");
    return 0;
  }

  puts("[x] Error\n");
  return 255;
}



void write_memory(unsigned int pid, unsigned long long offset, unsigned int length, char * buf, int * retcode) {
  char out_mem_file_name[256] = {0};
  snprintf(out_mem_file_name, 255, "%d_%llx_%llx", pid, offset, offset+length);
  FILE * write_fd = fopen(out_mem_file_name, "wb");
  int rets = 0;
  *retcode = -1;

  if (rets = fwrite(buf, 1, length, write_fd), rets >= 0) {
    printf("[+] Success, copy-write %d bytes to file %s !\n", rets, out_mem_file_name);
    fclose(write_fd);
    *retcode = 0;

  } else {
    printf("[x] Can't write %d bytes to file %s\n", rets, out_mem_file_name);
  }
}



char * read_memory(int ptrace_mode, unsigned int pid, unsigned long long offset, unsigned int length, int * retcode) {

  char mem_file_name[256] = {0};
  char * buf = (char *)malloc(length + 4 + 1);
  int rets = 0;
    
  *retcode = -1;

  if (!buf){
    printf("[x] Fail on malloc %d\n", length);
    return NULL;
  }

  snprintf(mem_file_name, 255, "/proc/%d/mem", pid);
  int mem_fd = open(mem_file_name, O_RDONLY);

  if (mem_fd > 0) {

    if (ptrace_mode) {
      ptrace(PTRACE_ATTACH, pid, NULL, NULL);
      waitpid(pid, NULL, 0);
    }
    
    if ( rets = lseek(mem_fd, offset, SEEK_SET), rets >= 0) {

      if ( rets = read(mem_fd, buf, length), rets >= 0) {
        printf("[+] Success, read %d bytes!\n", rets);
        *retcode = 0;

      } else {
        printf("[x] Fail on read %d bytes\n", length);
      }
    } else {
      printf("[x] Fail on lseek to %llu\n", offset);
    }
   
    if (ptrace_mode) {
      ptrace(PTRACE_DETACH, pid, NULL, NULL);
    }

    close(mem_fd);

  }  else {
    printf("[x] Fail on open %s\n", mem_file_name);
  }

  return buf;
} 




