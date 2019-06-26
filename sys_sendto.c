#include "sys_sendto.h"
#include "util.h"
void sys_sendto(pid_t process,struct user_regs_struct* structRegs,struct sys_sendtoReturn* sendtoReturn){
  struct iovec local;
  struct iovec remote;
  if(structRegs->rdx){
    sendtoReturn->data = malloc(sizeof(char)*structRegs->rdx);
    sendtoReturn->length = structRegs->rdx;
    local.iov_base = sendtoReturn->data;
    local.iov_len = structRegs->rdx;
    remote.iov_base = (void *) structRegs->rsi;
    remote.iov_len = structRegs->rdx;
    process_vm_readv(process, &local, 1, &remote, 1, 0);
  }
}
