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
