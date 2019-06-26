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
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include "defs.h"
#include "process_list.h"
#include "request_handler.h"
#include "util.h"
#include "sys_write.h"
#include "sys_open.h"
#include "sys_read.h"
#include "sys_close.h"

int flagForReady = 1;
int attachReadyFlag = 0;

void syscallNext(void);

void deleteSyscallList(){
      for(int i=0;i<sList.length;i++){
        free(sList.array[i].regs);
        if(sList.array[i].data){
          free(sList.array[i].data);
        }
        sList.array[i].regs = NULL;
        sList.array[i].data = NULL;
      }
      free(sList.array);
      sList.array = NULL;
      sList.length = 0;
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
    deleteSyscallList();
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
   deleteSyscallList();
   isStartedPtrace = 0;
}

void syscallNext(){
  int in_call = 0;
  long orig_eax;
  int writeEntryExitFlag =0;
  int readEntryExitFlag = 0;
  int openEntryExitFlag =0;
  int closeEntryExitFlag =0;
  int firstTime = 1;
  int status;
  struct sys_writeReturn writeReturn;
  struct sys_readReturn readReturn;
  struct sys_openReturn openReturn;
  struct sys_closeReturn closeReturn;
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
          if(!firstTime){
            sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
          }
          firstTime =0;
          sList.array[sList.length].regs = malloc(sizeof(struct user_regs_struct));
          ptrace(PTRACE_GETREGS,traced_process,NULL,sList.array[sList.length].regs);
          sys_write(traced_process,sList.array[sList.length].regs,&writeReturn);
          if(writeReturn.length){
            sList.array[sList.length].data=malloc(sizeof(char)*writeReturn.length+1);
            for(int i=0;i<writeReturn.length;i++){
              sList.array[sList.length].data[i] = writeReturn.data[i];
            }
            sList.array[sList.length].data[writeReturn.length] = '\0';
          }
          if(writeEntryExitFlag == 0) {
                // Syscall entry
                writeEntryExitFlag = 1;
                sList.array[sList.length].entry_exit_flag = 0;
              }
          else {
                // Syscall exit
                writeEntryExitFlag = 0;
                sList.array[sList.length].entry_exit_flag = 1;
            }
          writeReturn.length = 0;
          free(writeReturn.data);
          writeReturn.data = NULL;
          sList.length++;
          while(1){
            nanosleep(&ts, NULL);
            if(flagForNext == 1){
              flagForNext = 0;
              break;
            }
          }
        }
        else if(orig_eax == SYS_openat){
          if(!firstTime){
            sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
          }
          firstTime =0;
          sList.array[sList.length].regs = malloc(sizeof(struct user_regs_struct));
          ptrace(PTRACE_GETREGS,traced_process,NULL,sList.array[sList.length].regs);
          sys_open(traced_process,sList.array[sList.length].regs,&openReturn);
          if(openReturn.length){
            sList.array[sList.length].data = malloc(sizeof(char)*openReturn.length+1);
            for(int i=0;i<openReturn.length;i++){
                sList.array[sList.length].data[i] = openReturn.fileName[i];
            }
            sList.array[sList.length].data[openReturn.length] = '\0';
          }
          if(openEntryExitFlag == 0) {
           // Syscall entry
                openEntryExitFlag = 1;
                sList.array[sList.length].entry_exit_flag = 0;
          }
          else { // Syscall exit
                openEntryExitFlag = 0;
                sList.array[sList.length].entry_exit_flag = 1;
          }
          openReturn.length = 0;
          free(openReturn.fileName);
          openReturn.fileName = NULL;
          sList.length++;
          while(1){
            nanosleep(&ts, NULL);
            if(flagForNext == 1){
              flagForNext = 0;
              break;
            }
          }
        }
        else if(orig_eax == SYS_close){
            if(!firstTime){
              sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
            }
            firstTime = 0;
            sList.array[sList.length].regs = malloc(sizeof(struct user_regs_struct));
            ptrace(PTRACE_GETREGS,traced_process,NULL,sList.array[sList.length].regs);
            sys_close(traced_process,sList.array[sList.length].regs,&closeReturn);
            sList.array[sList.length].data = NULL;
          if(closeEntryExitFlag == 0) {
           /* Syscall entry */
                closeEntryExitFlag = 1;
                sList.array[sList.length].entry_exit_flag = 0;
              }
              else { /* Syscall exit */
                closeEntryExitFlag = 0;
                sList.array[sList.length].entry_exit_flag = 1;
            }
          closeReturn.fileDescriptor = 0;
          sList.length++;
          while(1){
            nanosleep(&ts, NULL);
            if(flagForNext == 1){
              flagForNext = 0;
              break;
            }
          }
        }
        else if(orig_eax == SYS_read){
          if(!firstTime){
            sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
          }
          firstTime = 0;
          sList.array[sList.length].regs = malloc(sizeof(struct user_regs_struct));
          ptrace(PTRACE_GETREGS,traced_process,NULL,sList.array[sList.length].regs);
          sys_read(traced_process,sList.array[sList.length].regs,&readReturn);
            sList.array[sList.length].data=malloc(sizeof(char)*readReturn.length+1);
            for(int i=0;i<readReturn.length;i++){
              sList.array[sList.length].data[i] = readReturn.data[i];
            }
            sList.array[sList.length].data[readReturn.length] = '\0';
          if(readEntryExitFlag == 0) {
           /* Syscall entry */
                readEntryExitFlag = 1;
                sList.array[sList.length].entry_exit_flag = 0;
          }
          else { /* Syscall exit */
                readEntryExitFlag = 0;
                sList.array[sList.length].entry_exit_flag = 1;
              }
          readReturn.length = 0;
          free(readReturn.data);
          readReturn.data = NULL;
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
}
