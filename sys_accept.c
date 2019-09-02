#include "sys_accept.h"
#include "util.h"
void sys_accept(pid_t process,struct user_regs_struct* structRegs,struct sys_acceptReturn* acceptReturn){
    struct iovec localSize;
    struct iovec remoteSize;
    struct iovec localData;
    struct iovec remoteData;
    int* pointerToLength = malloc(sizeof(int));
    localSize.iov_base = pointerToLength;
    localSize.iov_len = sizeof(int);
    remoteSize.iov_base = (void *) structRegs->rdx;
    remoteSize.iov_len = sizeof(int);
    process_vm_readv(process,&localSize,1,&remoteSize,1,0);
    acceptReturn->length = *pointerToLength;
    free(pointerToLength);
    if(acceptReturn->length){
        acceptReturn->data = malloc(sizeof(char)*acceptReturn->length);
        localData.iov_base = acceptReturn->data;
        localData.iov_len = acceptReturn->length;
        remoteData.iov_base = (void *) structRegs->rsi;
        remoteData.iov_len = acceptReturn->length;
        process_vm_readv(process, &localData, 1, &remoteData, 1, 0);
    }
}
