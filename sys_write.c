#include "sys_write.h"
#include "util.h"
void sys_write(pid_t process,struct user_regs_struct* structRegs,struct sys_writeReturn* writeReturn){
    struct iovec local;
    struct iovec remote;
    if(structRegs->rdx){
        writeReturn->data = malloc(sizeof(char)*structRegs->rdx);
        writeReturn->length = structRegs->rdx;
        local.iov_base = writeReturn->data;
        local.iov_len = structRegs->rdx;
        remote.iov_base = (void *) structRegs->rsi;
        remote.iov_len = structRegs->rdx;
        process_vm_readv(process, &local, 1, &remote, 1, 0);
    }
}
