#include "util.h"
#include "sys_write_modify.h"
#include "defs.h"
void sys_writeModify(pid_t process,struct user_regs_struct* structRegs,struct sys_writeModify* writeModify){
    struct iovec local;
    struct iovec remote;
    if(writeModify->length){
        structRegs->rdx = writeModify->length+1;
	    //structRegs->r14 = writeModify->length+1;
        structRegs->r14 = writeModify->length+1;
        structRegs->rbx = writeModify->length+1;
        local.iov_base = writeModify->data;
        local.iov_len = structRegs->rdx;
        remote.iov_base = (void *) structRegs->rsi;
        remote.iov_len = structRegs->rdx;
        process_vm_writev(process, &local, 1, &remote, 1, 0);
        perror("Process vm write: ");
        ptrace(PTRACE_SETREGS,process,NULL,structRegs);
    }
}
