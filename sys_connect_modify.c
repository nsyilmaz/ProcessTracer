#include "util.h"
#include "sys_connect_modify.h"
#include "defs.h"


void sys_connectModify(pid_t process,struct user_regs_struct* structRegs,struct sys_connectModify* connectModify){
    struct iovec local;
    struct iovec remote;
    if(connectModify->length){
        local.iov_base = connectModify->data;
        local.iov_len = connectModify->length;
        remote.iov_base = (void *) structRegs->rsi;
        remote.iov_len = connectModify->length;
        process_vm_writev(process, &local, 1, &remote, 1, 0);
        structRegs->rdx = connectModify->length;
        ptrace(PTRACE_SETREGS,process,NULL,structRegs);
    }
}
