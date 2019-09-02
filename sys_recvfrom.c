#include "sys_recvfrom.h"
#include "util.h"
void sys_recvfrom(pid_t process,struct user_regs_struct* structRegs,struct sys_recvfromReturn* recvfromReturn){
    struct iovec local;
    struct iovec remote;
    if(structRegs->rdx){
        recvfromReturn->data = malloc(sizeof(char)*structRegs->rdx);
        recvfromReturn->length = structRegs->rdx;
        local.iov_base = recvfromReturn->data;
        local.iov_len = structRegs->rdx;
        remote.iov_base = (void *) structRegs->rsi;
        remote.iov_len = structRegs->rdx;
        process_vm_readv(process, &local, 1, &remote, 1, 0);
    }
}
