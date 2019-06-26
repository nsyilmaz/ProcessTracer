#include "util.h"
#include "sys_read.h"
#include "defs.h"
void sys_read(pid_t process,struct user_regs_struct* structRegs,struct sys_readReturn* readReturn){
  struct iovec local;
  struct iovec remote;
  if(structRegs->rax && structRegs->rax < BUFFER_SIZE){
    readReturn->data = malloc(sizeof(char)*structRegs->rax);
    local.iov_base = readReturn->data;
    local.iov_len = structRegs->rax;
    remote.iov_base = (void *) structRegs->rsi;
    remote.iov_len = structRegs->rax;
    process_vm_readv(process, &local, 1, &remote, 1, 0);
    readReturn->length = structRegs->rax;
  }
}

/*
syscallwritein = 1;
if(!firstTime){
  sList.array = realloc(sList.array,(sList.length+1)*sizeof(struct syscallRegs));
}
firstTime = 0;
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
sList.array[sList.length].data[sList.array[sList.length].regs->rax] = '\0'; */
