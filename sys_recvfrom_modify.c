#include "util.h"
#include "sys_recvfrom_modify.h"
#include "defs.h"
void sys_recvfromModify(pid_t process,struct user_regs_struct* structRegs,struct sys_recvfromModify* recvfromModify){
    struct iovec local;
    struct iovec remote;
    if(recvfromModify->length){
        local.iov_base = recvfromModify->data;
        local.iov_len = recvfromModify->length;
        remote.iov_base = (void *) structRegs->rsi;
        remote.iov_len = recvfromModify->length;
        process_vm_writev(process, &local, 1, &remote, 1, 0);
        structRegs->rdx = recvfromModify->length;
        ptrace(PTRACE_SETREGS,process,NULL,structRegs);
    }
}
