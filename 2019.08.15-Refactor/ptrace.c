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
#include "sys_sendto.h"
#include "sys_recvfrom.h"
#include "sys_connect.h"
#include "sys_accept.h"
#include "sys_read_modify.h"
#include "sys_write_modify.h"

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
    long orig_eax;
    struct AJAXList* sysCallNode = NULL;
    int status;
    struct timespec ts;
    ts.tv_sec=0;
    ts.tv_nsec=10000000; // 10 milliseconds
    unsigned int ptrace_setoptions = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;
    if(ptrace(PTRACE_SEIZE, traced_process, 0L, (unsigned long) ptrace_setoptions)){
      perror("PTRACE_SEIZE: ");
      exit(0);
    }
    if(ptrace(PTRACE_INTERRUPT, traced_process, 0L, 0L)){
      perror("PTRACE_INTERRUPT: ");
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
  unsigned int ptrace_setoptions = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;
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
    kill(getpid(), SIGSTOP);
    execvp(execvArray[0],execvArray);
    }
  else {
      if(ptrace(PTRACE_SEIZE, traced_process, 0L, (unsigned long) ptrace_setoptions)){
        perror("PTRACE_SEIZE: ");
        exit(0);
      }
      if(ptrace(PTRACE_INTERRUPT, traced_process, 0L, 0L)){
        perror("PTRACE_INTERRUPT: ");
        exit(0);
      }
      kill(traced_process, SIGCONT);
      syscallNext();
      deleteSyscallList();
      isStartedPtrace = 0;
      free(path);
   }
}

void syscallWriteHandler(struct sys_writeReturn* writeReturn){
  sList.array[sList.length].regs = malloc(sizeof(struct user_regs_struct));
  ptrace(PTRACE_GETREGS,traced_process,NULL,sList.array[sList.length].regs);
  sys_write(traced_process,sList.array[sList.length].regs,writeReturn);
  if(writeReturn->length){
    sList.array[sList.length].data=malloc(sizeof(char)*writeReturn->length+1);
    for(int i=0;i<writeReturn->length;i++){
      sList.array[sList.length].data[i] = writeReturn->data[i];
    }
    sList.array[sList.length].data[writeReturn->length] = '\0';
  }
}

void syscallOpenHandler(struct sys_openReturn* openReturn){
  sList.array[sList.length].regs = malloc(sizeof(struct user_regs_struct));
  ptrace(PTRACE_GETREGS,traced_process,NULL,sList.array[sList.length].regs);
  sys_open(traced_process,sList.array[sList.length].regs,openReturn);
  if(openReturn->length){
    sList.array[sList.length].data = malloc(sizeof(char)*openReturn->length+1);
    for(int i=0;i<openReturn->length;i++){
        sList.array[sList.length].data[i] = openReturn->fileName[i];
    }
    sList.array[sList.length].data[openReturn->length] = '\0';
  }
}

void syscallAccept4Handler(struct sys_acceptReturn* acceptReturn){
  sList.array[sList.length].regs = malloc(sizeof(struct user_regs_struct));
  ptrace(PTRACE_GETREGS,traced_process,NULL,sList.array[sList.length].regs);
  sys_accept(traced_process,sList.array[sList.length].regs,acceptReturn);
  if(acceptReturn->length){
    sList.array[sList.length].data=malloc(sizeof(char)*acceptReturn->length+1);
    for(int i=0;i<acceptReturn->length;i++){
      sList.array[sList.length].data[i] = acceptReturn->data[i];
    }
    sList.array[sList.length].data[acceptReturn->length] = '\0';
  }
}

void syscallConnectHandler(struct sys_connectReturn* connectReturn){
  sList.array[sList.length].regs = malloc(sizeof(struct user_regs_struct));
  ptrace(PTRACE_GETREGS,traced_process,NULL,sList.array[sList.length].regs);
  sys_connect(traced_process,sList.array[sList.length].regs,connectReturn);
  if(connectReturn->length){
    sList.array[sList.length].data=malloc(sizeof(char)*connectReturn->length+1);
    for(int i=0;i<connectReturn->length;i++){
      sList.array[sList.length].data[i] = connectReturn->data[i];
    }
    sList.array[sList.length].data[connectReturn->length] = '\0';
  }
}

void syscallCloseHandler(struct sys_closeReturn* closeReturn){
  sList.array[sList.length].regs = malloc(sizeof(struct user_regs_struct));
  ptrace(PTRACE_GETREGS,traced_process,NULL,sList.array[sList.length].regs);
  sys_close(traced_process,sList.array[sList.length].regs,closeReturn);
  sList.array[sList.length].data = NULL;
}

void syscallSendtoHandler(struct sys_sendtoReturn* sendtoReturn){
  sList.array[sList.length].regs = malloc(sizeof(struct user_regs_struct));
  ptrace(PTRACE_GETREGS,traced_process,NULL,sList.array[sList.length].regs);
  sys_sendto(traced_process,sList.array[sList.length].regs,sendtoReturn);
  if(sendtoReturn->length){
    sList.array[sList.length].data=malloc(sizeof(char)*sendtoReturn->length+1);
    for(int i=0;i<sendtoReturn->length;i++){
      sList.array[sList.length].data[i] = sendtoReturn->data[i];
    }
    sList.array[sList.length].data[sendtoReturn->length] = '\0';
  }
}

void syscallRecvfromHandler(struct sys_recvfromReturn* recvfromReturn){
  sList.array[sList.length].regs = malloc(sizeof(struct user_regs_struct));
  ptrace(PTRACE_GETREGS,traced_process,NULL,sList.array[sList.length].regs);
  sys_recvfrom(traced_process,sList.array[sList.length].regs,recvfromReturn);
  if(recvfromReturn->length){
    sList.array[sList.length].data=malloc(sizeof(char)*recvfromReturn->length+1);
    for(int i=0;i<recvfromReturn->length;i++){
      sList.array[sList.length].data[i] = recvfromReturn->data[i];
    }
    sList.array[sList.length].data[recvfromReturn->length] = '\0';
  }
}

void syscallReadHandler(struct sys_readReturn* readReturn){
  sList.array[sList.length].regs = malloc(sizeof(struct user_regs_struct));
  ptrace(PTRACE_GETREGS,traced_process,NULL,sList.array[sList.length].regs);
  sys_read(traced_process,sList.array[sList.length].regs,readReturn);
    sList.array[sList.length].data=malloc(sizeof(char)*readReturn->length+1);
    for(int i=0;i<readReturn->length;i++){
      sList.array[sList.length].data[i] = readReturn->data[i];
    }
    sList.array[sList.length].data[readReturn->length] = '\0';
}

void syscall_read_modifyHandler(){
  struct sys_readModify readModify;
  modify = 0;
  readModify.data = modifiedValue;
  readModify.length = strlen(modifiedValue);
  sys_readModify(traced_process,sList.array[sList.length-1].regs,&readModify);
  sList.array[sList.length-1].data = realloc(sList.array[sList.length-1].data,sizeof(char)*readModify.length+1);
  for(int i=0;i<readModify.length;i++){
    sList.array[sList.length-1].data[i] = readModify.data[i];
  }
  sList.array[sList.length-1].data[readModify.length] = '\0';
  readModify.length = 0;
  free(readModify.data);
  readModify.data = NULL;
  modifiedValue = NULL;
}

void waitForNextButton(){
  struct timespec ts;
  struct iovec local,remote;
  ts.tv_sec=0;
  ts.tv_nsec=10000000; // 10 milliseconds
  while(1){
    nanosleep(&ts, NULL);
    if(flagForNext == 1){
      flagForNext = 0;
      break;
    }
  }
}

void syscallNext(){
  int entryExitFlag = 0;
  int firstTime = 1;
  int status;
  long orig_eax;
  struct sys_readReturn readReturn;
  struct sys_openReturn openReturn;
  struct sys_closeReturn closeReturn;
  struct sys_sendtoReturn sendtoReturn;
  struct sys_recvfromReturn recvfromReturn;
  struct sys_connectReturn connectReturn;
  struct sys_acceptReturn acceptReturn;
  struct sys_writeReturn writeReturn;
  unsigned char buffer[BUFFER_SIZE];
  unsigned int event,sig;
  const unsigned int syscall_trap_sig = SIGTRAP | 0x80;
  sList.array = malloc(sizeof(struct syscallRegs));
  while(1) {
        wait(&status);
        if(WIFEXITED(status)){
            break;
          }
        event = (unsigned int) status >> 16;
        sig = WSTOPSIG(status);
        if(event == 0 && sig == syscall_trap_sig){
        orig_eax = ptrace(PTRACE_PEEKUSER, traced_process, sizeof(long) * ORIG_RAX, NULL);
        if(orig_eax == SYS_write){
          if(!firstTime){
            sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
          }
          firstTime =0;
          syscallWriteHandler(&writeReturn);
          if(entryExitFlag == 0) {
                // Syscall entry
                entryExitFlag = 1;
                sList.array[sList.length].entry_exit_flag = 0;
                sList.length++;
                waitForNextButton();
              }
          else {
                // Syscall exit
                entryExitFlag = 0;
                sList.array[sList.length].entry_exit_flag = 1;
                sList.length++;
                waitForNextButton();
            }
          writeReturn.length = 0;
          free(writeReturn.data);
          writeReturn.data = NULL;
        }
        else if(orig_eax == SYS_accept4){
          if(!firstTime){
            sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
          }
          firstTime =0;
          syscallAccept4Handler(&acceptReturn);
          if(entryExitFlag == 0) {
                // Syscall entry
                entryExitFlag = 1;
                sList.array[sList.length].entry_exit_flag = 0;
                sList.length++;
                waitForNextButton();
              }
          else {
                // Syscall exit
                entryExitFlag = 0;
                sList.array[sList.length].entry_exit_flag = 1;
                sList.length++;
                waitForNextButton();
            }
          acceptReturn.length = 0;
          free(sendtoReturn.data);
          acceptReturn.data = NULL;
        }
        else if(orig_eax == SYS_sendto){
          if(!firstTime){
            sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
          }
          firstTime =0;
          syscallSendtoHandler(&sendtoReturn);
          if(entryExitFlag == 0) {
                // Syscall entry
                entryExitFlag = 1;
                sList.array[sList.length].entry_exit_flag = 0;
                sList.length++;
                waitForNextButton();
              }
          else {
                // Syscall exit
                entryExitFlag = 0;
                sList.array[sList.length].entry_exit_flag = 1;
                sList.length++;
                waitForNextButton();
            }
          sendtoReturn.length = 0;
          free(sendtoReturn.data);
          sendtoReturn.data = NULL;
        }
        else if(orig_eax == SYS_connect){
          if(!firstTime){
            sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
          }
          firstTime =0;
          syscallConnectHandler(&connectReturn);
          if(entryExitFlag == 0) {
                // Syscall entry
                entryExitFlag = 1;
                sList.array[sList.length].entry_exit_flag = 0;
                sList.length++;
                waitForNextButton();
              }
          else {
                // Syscall exit
                entryExitFlag = 0;
                sList.array[sList.length].entry_exit_flag = 1;
                sList.length++;
                waitForNextButton();
            }
          connectReturn.length = 0;
          free(connectReturn.data);
          connectReturn.data = NULL;
        }
        else if(orig_eax == SYS_recvfrom){
          if(!firstTime){
            sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
          }
          firstTime =0;
          syscallRecvfromHandler(&recvfromReturn);
          if(entryExitFlag == 0) {
                // Syscall entry
                entryExitFlag = 1;
                sList.array[sList.length].entry_exit_flag = 0;
                sList.length++;
                waitForNextButton();
              }
          else {
                // Syscall exit
                entryExitFlag = 0;
                sList.array[sList.length].entry_exit_flag = 1;
                sList.length++;
                waitForNextButton();
            }
          recvfromReturn.length = 0;
          free(recvfromReturn.data);
          recvfromReturn.data = NULL;
        }
        else if(orig_eax == SYS_openat){
          if(!firstTime){
            sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
          }
          firstTime =0;
          syscallOpenHandler(&openReturn);
          if(entryExitFlag == 0) {
           // Syscall entry
                entryExitFlag = 1;
                sList.array[sList.length].entry_exit_flag = 0;
                sList.length++;
                waitForNextButton();
          }
          else { // Syscall exit
                entryExitFlag = 0;
                sList.array[sList.length].entry_exit_flag = 1;
                sList.length++;
                waitForNextButton();
          }
          openReturn.length = 0;
          free(openReturn.fileName);
          openReturn.fileName = NULL;
        }
        else if(orig_eax == SYS_close){
          if(!firstTime){
            sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
          }
          firstTime = 0;
          syscallCloseHandler(&closeReturn);
          if(entryExitFlag == 0) {
          /* Syscall entry */
              entryExitFlag = 1;
              sList.array[sList.length].entry_exit_flag = 0;
              sList.length++;
              waitForNextButton();
            }
            else { /* Syscall exit */
              entryExitFlag = 0;
              sList.array[sList.length].entry_exit_flag = 1;
              sList.length++;
              waitForNextButton();
          }
          closeReturn.fileDescriptor = 0;
        }
        else if(orig_eax == SYS_read){
          if(!firstTime){
            sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
          }
          firstTime = 0;
          syscallReadHandler(&readReturn);
          if(entryExitFlag == 0) {
           /* Syscall entry */
                entryExitFlag = 1;
                sList.array[sList.length].entry_exit_flag = 0;
                sList.length++;
                waitForNextButton();
          }
          else { /* Syscall exit */
                struct timespec ts;
                struct iovec local,remote;
                ts.tv_sec=0;
                ts.tv_nsec=10000000; // 10 milliseconds
                entryExitFlag = 0;
                sList.array[sList.length].entry_exit_flag = 1;
                sList.length++;
                while(1){
                  nanosleep(&ts, NULL);
                  if(flagForNext == 1){
                    if(modify){
                        struct sys_readModify readModify;
                        modify = 0;
                        readModify.data = modifiedValue;
                        readModify.length = strlen(modifiedValue);
                        sys_readModify(traced_process,sList.array[sList.length-1].regs,&readModify);
                        sList.array[sList.length-1].data = realloc(sList.array[sList.length-1].data,sizeof(char)*readModify.length+1);
                        for(int i=0;i<readModify.length;i++){
                          sList.array[sList.length-1].data[i] = readModify.data[i];
                        }
                        sList.array[sList.length-1].data[readModify.length] = '\0';
                        readModify.length = 0;
                        free(readModify.data);
                        readModify.data = NULL;
                        modifiedValue = NULL;
                    }
                    flagForNext = 0;
                    break;
                  }
                }
              }
          readReturn.length = 0;
          free(readReturn.data);
          readReturn.data = NULL;
          }
      }
    ptrace(PTRACE_SYSCALL, traced_process,NULL, NULL);
  }
}

/*
int writeEntryExitFlag =0;
int readEntryExitFlag = 0;
int openEntryExitFlag =0;
int closeEntryExitFlag =0;
int sendtoEntryExitFlag=0;
int recvfromEntryExitFlag=0;
int connectEntryExitFlag = 0;
int acceptEntryExitFlag = 0;
int firstTime = 1;
int status;
long orig_eax;
struct sys_readReturn readReturn;
struct sys_openReturn openReturn;
struct sys_closeReturn closeReturn;
struct sys_sendtoReturn sendtoReturn;
struct sys_recvfromReturn recvfromReturn;
struct sys_connectReturn connectReturn;
struct sys_acceptReturn acceptReturn;
struct sys_writeReturn writeReturn;
unsigned char buffer[BUFFER_SIZE];
unsigned int event,sig;
const unsigned int syscall_trap_sig = SIGTRAP | 0x80;
sList.array = malloc(sizeof(struct syscallRegs));
while(1) {
      wait(&status);
      if(WIFEXITED(status)){
          break;
        }
      event = (unsigned int) status >> 16;
      sig = WSTOPSIG(status);
      if(event == 0 && sig == syscall_trap_sig){
      orig_eax = ptrace(PTRACE_PEEKUSER, traced_process, sizeof(long) * ORIG_RAX, NULL);
      if(orig_eax == SYS_write){
        if(!firstTime){
          sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
        }
        firstTime =0;
        syscallWriteHandler(&writeReturn);
        if(writeEntryExitFlag == 0) {
              // Syscall entry
              writeEntryExitFlag = 1;
              sList.array[sList.length].entry_exit_flag = 0;
              sList.length++;
              waitForNextButton();
            }
        else {
              // Syscall exit
              writeEntryExitFlag = 0;
              sList.array[sList.length].entry_exit_flag = 1;
              sList.length++;
              waitForNextButton();
          }
        writeReturn.length = 0;
        free(writeReturn.data);
        writeReturn.data = NULL;
      }
      else if(orig_eax == SYS_accept4){
        if(!firstTime){
          sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
        }
        firstTime =0;
        syscallAccept4Handler(&acceptReturn);
        if(acceptEntryExitFlag == 0) {
              // Syscall entry
              acceptEntryExitFlag = 1;
              sList.array[sList.length].entry_exit_flag = 0;
              sList.length++;
              waitForNextButton();
            }
        else {
              // Syscall exit
              acceptEntryExitFlag = 0;
              sList.array[sList.length].entry_exit_flag = 1;
              sList.length++;
              waitForNextButton();
          }
        acceptReturn.length = 0;
        free(sendtoReturn.data);
        acceptReturn.data = NULL;
      }
      else if(orig_eax == SYS_sendto){
        if(!firstTime){
          sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
        }
        firstTime =0;
        syscallSendtoHandler(&sendtoReturn);
        if(sendtoEntryExitFlag == 0) {
              // Syscall entry
              sendtoEntryExitFlag = 1;
              sList.array[sList.length].entry_exit_flag = 0;
              sList.length++;
              waitForNextButton();
            }
        else {
              // Syscall exit
              sendtoEntryExitFlag = 0;
              sList.array[sList.length].entry_exit_flag = 1;
              sList.length++;
              waitForNextButton();
          }
        sendtoReturn.length = 0;
        free(sendtoReturn.data);
        sendtoReturn.data = NULL;
      }
      else if(orig_eax == SYS_connect){
        if(!firstTime){
          sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
        }
        firstTime =0;
        syscallConnectHandler(&connectReturn);
        if(connectEntryExitFlag == 0) {
              // Syscall entry
              connectEntryExitFlag = 1;
              sList.array[sList.length].entry_exit_flag = 0;
              sList.length++;
              waitForNextButton();
            }
        else {
              // Syscall exit
              connectEntryExitFlag = 0;
              sList.array[sList.length].entry_exit_flag = 1;
              sList.length++;
              waitForNextButton();
          }
        connectReturn.length = 0;
        free(connectReturn.data);
        connectReturn.data = NULL;
      }
      else if(orig_eax == SYS_recvfrom){
        if(!firstTime){
          sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
        }
        firstTime =0;
        syscallRecvfromHandler(&recvfromReturn);
        if(recvfromEntryExitFlag == 0) {
              // Syscall entry
              recvfromEntryExitFlag = 1;
              sList.array[sList.length].entry_exit_flag = 0;
              sList.length++;
              waitForNextButton();
            }
        else {
              // Syscall exit
              recvfromEntryExitFlag = 0;
              sList.array[sList.length].entry_exit_flag = 1;
              sList.length++;
              waitForNextButton();
          }
        recvfromReturn.length = 0;
        free(recvfromReturn.data);
        recvfromReturn.data = NULL;
      }
      else if(orig_eax == SYS_openat){
        if(!firstTime){
          sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
        }
        firstTime =0;
        syscallOpenHandler(&openReturn);
        if(openEntryExitFlag == 0) {
         // Syscall entry
              openEntryExitFlag = 1;
              sList.array[sList.length].entry_exit_flag = 0;
              sList.length++;
              waitForNextButton();
        }
        else { // Syscall exit
              openEntryExitFlag = 0;
              sList.array[sList.length].entry_exit_flag = 1;
              sList.length++;
              waitForNextButton();
        }
        openReturn.length = 0;
        free(openReturn.fileName);
        openReturn.fileName = NULL;
      }
      else if(orig_eax == SYS_close){
        if(!firstTime){
          sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
        }
        firstTime = 0;
        syscallCloseHandler(&closeReturn);
        if(closeEntryExitFlag == 0) {
        /* Syscall entry
            closeEntryExitFlag = 1;
            sList.array[sList.length].entry_exit_flag = 0;
            sList.length++;
            waitForNextButton();
          }
          else { /* Syscall exit
            closeEntryExitFlag = 0;
            sList.array[sList.length].entry_exit_flag = 1;
            sList.length++;
            waitForNextButton();
        }
        closeReturn.fileDescriptor = 0;
      }
      else if(orig_eax == SYS_read){
        if(!firstTime){
          sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
        }
        firstTime = 0;
        syscallReadHandler(&readReturn);
        if(readEntryExitFlag == 0) {
         /* Syscall entry
              readEntryExitFlag = 1;
              sList.array[sList.length].entry_exit_flag = 0;
              sList.length++;
              waitForNextButton();
        }
        else { /* Syscall exit
              struct timespec ts;
              struct iovec local,remote;
              ts.tv_sec=0;
              ts.tv_nsec=10000000; // 10 milliseconds
              readEntryExitFlag = 0;
              sList.array[sList.length].entry_exit_flag = 1;
              sList.length++;
              while(1){
                nanosleep(&ts, NULL);
                if(flagForNext == 1){
                  if(modify){
                      struct sys_readModify readModify;
                      modify = 0;
                      readModify.data = modifiedValue;
                      readModify.length = strlen(modifiedValue);
                      sys_readModify(traced_process,sList.array[sList.length-1].regs,&readModify);
                      sList.array[sList.length-1].data = realloc(sList.array[sList.length-1].data,sizeof(char)*readModify.length+1);
                      for(int i=0;i<readModify.length;i++){
                        sList.array[sList.length-1].data[i] = readModify.data[i];
                      }
                      sList.array[sList.length-1].data[readModify.length] = '\0';
                      readModify.length = 0;
                      free(readModify.data);
                      readModify.data = NULL;
                      modifiedValue = NULL;
                  }
                  flagForNext = 0;
                  break;
                }
              }
            }
        readReturn.length = 0;
        free(readReturn.data);
        readReturn.data = NULL;
        }
    }
  ptrace(PTRACE_SYSCALL, traced_process,NULL, NULL);
}
}
*/
