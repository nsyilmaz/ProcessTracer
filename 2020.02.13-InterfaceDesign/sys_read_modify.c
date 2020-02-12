#include "util.h"
#include "sys_read_modify.h"
#include "defs.h"
void sys_readModify(pid_t process,struct user_regs_struct* structRegs,struct sys_readModify* readModify){
    struct iovec local;
    struct iovec remote;
    if(readModify->length){
        local.iov_base = readModify->data;
        local.iov_len = readModify->length;
        remote.iov_base = (void *) structRegs->rsi;
        remote.iov_len = readModify->length;
        process_vm_writev(process, &local, 1, &remote, 1, 0);
        structRegs->rax = readModify->length;
        ptrace(PTRACE_SETREGS,process,NULL,structRegs);
    }
}
