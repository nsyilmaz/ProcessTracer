#include "sys_connect.h"
#include "util.h"
void sys_connect(pid_t process,struct user_regs_struct* structRegs,struct sys_connectReturn* connectReturn){
  struct iovec local;
  struct iovec remote;
  if(structRegs->rdx){
    connectReturn->data = malloc(sizeof(char)*structRegs->rdx);
    connectReturn->length = structRegs->rdx;
    local.iov_base = connectReturn->data;
    local.iov_len = structRegs->rdx;
    remote.iov_base = (void *) structRegs->rsi;
    remote.iov_len = structRegs->rdx;
    process_vm_readv(process, &local, 1, &remote, 1, 0);
  }
}
