#include "util.h"
#include "sys_sendto_modify.h"
#include "defs.h"
void sys_sendtoModify(pid_t process,struct user_regs_struct* structRegs,struct sys_sendtoModify* sendtoModify){
    struct iovec local;
    struct iovec remote;
    if(sendtoModify->length){
        local.iov_base = sendtoModify->data;
        local.iov_len = sendtoModify->length+1;
        remote.iov_base = (void *) structRegs->rsi;
        remote.iov_len = sendtoModify->length+1;
        process_vm_writev(process, &local, 1, &remote, 1, 0);
        structRegs->rdx = sendtoModify->length+1;
        ptrace(PTRACE_SETREGS,process,NULL,structRegs);
    }
}
