#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/net.h>
#include "defs.h"
#include "process_list.h"
#include "request_handler.h"
#include "util.h"
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/reg.h>

int flagForReady = 1;
int attachReadyFlag = 0;

void syscallNext(void);

void deleteSyscallList(){
      /*for(int i=0;i<sList.length;i++){
        free(sList.array[i].regs);
        if(sList.array[i].data){
          free(sList.array[i].data);
        }
        sList.array[i].regs = NULL;
        sList.array[i].data = NULL;
      }
      free(sList.array);
      sList.array = NULL;
      sList.length = 0; */
}

void* ptraceAttach(void *ptr){
    pid_t *traced = ptr;
    traced_process = *traced;
    int in_call = 0;
    long orig_eax;
    struct AJAXList* sysCallNode = NULL;
    int status;
    struct timespec ts;
    ts.tv_sec=0;
    ts.tv_nsec=10000000; // 10 milliseconds
    if(ptrace(PTRACE_ATTACH,traced_process,NULL,NULL)){
        perror("PTRACE_ATTACH: ");
        exit(0);
    }
    syscallNext();
    isStartedPtrace = 0;
}


void* ptraceFork(void *ptr){
  char* path = ptr;
  char* pch;
  int status;
  int insyscall = 0;
  int sizeOfArray = execvArraySize(path);
  char* execvArray[sizeOfArray];
  long orig_eax;
  struct timespec ts;
  ts.tv_sec=0;
  ts.tv_nsec=10000000; // 10 milliseconds
  int i=0;
  execvArray[sizeOfArray-1] = NULL;
  pch = strtok (path," ");
  while (pch != NULL)
  {
    execvArray[i++] = pch;
    pch = strtok (NULL, " ");
  }
  traced_process = fork();
  if(traced_process == 0) {
      if(ptrace(PTRACE_TRACEME, 0, NULL, NULL)){
		        perror("TRACEME ERROR: ");
		        exit(0);
	        }
      execvp(execvArray[0],execvArray);
    }
  else {
      syscallNext();
   }
   isStartedPtrace = 0;
}

void syscallNext(){
  int in_call = 0;
  long orig_eax;
  int insyscall =0;
  int syscallwritein = 0;
  int firstTime = 1;
  int status;
  unsigned char buffer[BUFFER_SIZE];
  struct timespec ts;
  struct iovec local ;
  struct iovec remote ;
  ts.tv_sec=0;
  ts.tv_nsec=10000000; // 10 milliseconds
  sList.array = malloc(sizeof(struct syscallRegs));
  //sList.length++;
  while(1) {
        wait(&status);
        if(WIFEXITED(status)){
            break;
          }
        orig_eax = ptrace(PTRACE_PEEKUSER, traced_process, sizeof(long) * ORIG_RAX, NULL);
        if(orig_eax == SYS_write){
          if(insyscall == 0) {
           /* Syscall entry */
                insyscall = 1;
                if(!firstTime){
                  sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
                }
                firstTime =0;
                sList.array[sList.length].regs = malloc(sizeof(struct user_regs_struct));
                sList.array[sList.length].entry_exit_flag = 0;
                ptrace(PTRACE_GETREGS,traced_process,NULL,sList.array[sList.length].regs);
                sList.array[sList.length].data = malloc(sizeof(char)*sList.array[sList.length].regs->rdx+1);
                if(sList.array[sList.length].regs->rdx){
                  local.iov_base = sList.array[sList.length].data;
                  local.iov_len = sList.array[sList.length].regs->rdx;
                  remote.iov_base = (void *) sList.array[sList.length].regs->rsi;
                  remote.iov_len = sList.array[sList.length].regs->rdx;
                  process_vm_readv(traced_process, &local, 1, &remote, 1, 0);
                  //sList.array[sList.length ].data = malloc(sizeof(char)*sList.array[sList.length].regs->rdx);
                //  for(int i=0;i<sList.array[sList.length].regs->rdx;i++){
                //    sList.array[sList.length].data[i] = buffer[i];
                //  }
                  sList.array[sList.length].data[sList.array[sList.length].regs->rdx] = '\0';
                }
              }
              else { /* Syscall exit */
                insyscall = 0;
                if(!firstTime){
                  sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
                }
                firstTime = 0;
                sList.array[sList.length].regs = malloc(sizeof(struct user_regs_struct));
                sList.array[sList.length].entry_exit_flag = 1;
                ptrace(PTRACE_GETREGS,traced_process,NULL,sList.array[sList.length].regs);
                sList.array[sList.length].data = malloc(sizeof(char)*sList.array[sList.length].regs->rdx+1);
                if(sList.array[sList.length].regs->rdx){
                  local.iov_base = sList.array[sList.length].data;
                  local.iov_len = sList.array[sList.length].regs->rdx;
                  remote.iov_base = (void *) sList.array[sList.length].regs->rsi;
                  remote.iov_len = sList.array[sList.length].regs->rdx;
                  process_vm_readv(traced_process, &local, 1, &remote, 1, 0);
              /*    sList.array[sList.length].data = malloc(sizeof(char)*sList.array[sList.length].regs->rdx+1);
                  for(int i=0;i<sList.array[sList.length].regs->rdx;i++){
                    sList.array[sList.length].data[i] = buffer[i];
                  } */
                  sList.array[sList.length].data[sList.array[sList.length].regs->rdx] = '\0';
                }
            }
          sList.length++;
          while(1){
            nanosleep(&ts, NULL);
            if(flagForNext == 1){
              flagForNext = 0;
              break;
            }
          }
        }
        if(orig_eax == SYS_read){
          if(syscallwritein == 0) {
           /* Syscall entry */
                syscallwritein = 1;
                if(!firstTime){
                  sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
                }
                firstTime =0;
                sList.array[sList.length].regs = malloc(sizeof(struct user_regs_struct));
                sList.array[sList.length].entry_exit_flag = 0;
                ptrace(PTRACE_GETREGS,traced_process,NULL,sList.array[sList.length].regs);
                sList.array[sList.length].data = malloc(sizeof(char)*sList.array[sList.length].regs->rax+1);
                if(sList.array[sList.length].regs->rax && sList.array[sList.length].regs->rax < BUFFER_SIZE){
                  local.iov_base = sList.array[sList.length].data;
                  local.iov_len = sList.array[sList.length].regs->rax;
                  remote.iov_base = (void *) sList.array[sList.length].regs->rsi;
                  remote.iov_len = sList.array[sList.length].regs->rax;
                  process_vm_readv(traced_process, &local, 1, &remote, 1, 0);
                  //sList.array[sList.length ].data = malloc(sizeof(char)*sList.array[sList.length].regs->rdx);
                //  for(int i=0;i<sList.array[sList.length].regs->rdx;i++){
                //    sList.array[sList.length].data[i] = buffer[i];
                //  }
                  sList.array[sList.length].data[sList.array[sList.length].regs->rax] = '\0';
                }
                
              }
              else { /* Syscall exit */
                syscallwritein = 0;
                if(!firstTime){
                  sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
                }
                firstTime = 0;
                sList.array[sList.length].regs = malloc(sizeof(struct user_regs_struct));
                sList.array[sList.length].entry_exit_flag = 1;
                ptrace(PTRACE_GETREGS,traced_process,NULL,sList.array[sList.length].regs);
                sList.array[sList.length].data = malloc(sizeof(char)*sList.array[sList.length].regs->rax+1);
                if(sList.array[sList.length].regs->rax){
                  local.iov_base = sList.array[sList.length].data;
                  local.iov_len = sList.array[sList.length].regs->rax;
                  remote.iov_base = (void *) sList.array[sList.length].regs->rsi;
                  remote.iov_len = sList.array[sList.length].regs->rax;
                  process_vm_readv(traced_process, &local, 1, &remote, 1, 0);
              /*    sList.array[sList.length].data = malloc(sizeof(char)*sList.array[sList.length].regs->rdx+1);
                  for(int i=0;i<sList.array[sList.length].regs->rdx;i++){
                    sList.array[sList.length].data[i] = buffer[i];
                  } */
                  sList.array[sList.length].data[sList.array[sList.length].regs->rax] = '\0';
                }
            }
          sList.length++;
          while(1){
            nanosleep(&ts, NULL);
            if(flagForNext == 1){
              flagForNext = 0;
              break;
            }
          }
        }
    ptrace(PTRACE_SYSCALL, traced_process,NULL, NULL);
  }
  deleteSyscallList();

}
/*
geldi

register orig_eax: 162 geldi bu sleep

register orig_eax: 0 geldi

register orig_eax: 0 geldi

register orig_eax: 197 geldi

register orig_eax: 197 geldi

register orig_eax: 45 geldi

register orig_eax: 45 geldi

register orig_eax: 45 geldi

register orig_eax: 45 geldi

register orig_eax: 45 geldi

register orig_eax: 45 geldioldu

register orig_eax: 4 geldioldu

register orig_eax: 4 geldi

register orig_eax: 252 */
