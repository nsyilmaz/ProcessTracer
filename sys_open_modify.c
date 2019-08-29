#include "util.h"
#include "sys_open_modify.h"
#include "defs.h"
void sys_openModify(pid_t process,struct user_regs_struct* structRegs,struct sys_openModify* openModify){
  struct iovec local;
  struct iovec remote;
  if(openModify->length){
    local.iov_base = openModify->data;
    local.iov_len = openModify->length;
    remote.iov_base = (void *) structRegs->rsi;
    remote.iov_len = openModify->length;
    process_vm_writev(process, &local, 1, &remote, 1, 0);
    ptrace(PTRACE_SETREGS,process,NULL,structRegs);
  }
}
