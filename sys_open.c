#include "sys_open.h"
#include "util.h"
#include "defs.h"

void sys_open(pid_t process,struct user_regs_struct* structRegs,struct sys_openReturn* openReturn){
    char buffer[BUFFER_SIZE];
    int lengthOfFileName = 0;
    char *bufferPointer = buffer;
    struct iovec local;
    struct iovec remote;
    local.iov_base = buffer;
    local.iov_len = BUFFER_SIZE;
    remote.iov_base = (void *) structRegs->rsi;
    remote.iov_len = BUFFER_SIZE;
    process_vm_readv(process, &local, 1, &remote, 1, 0);
    lengthOfFileName = strlen(buffer);
    openReturn->length = strlen(buffer);
    if(openReturn->length){
        openReturn->fileName = malloc(sizeof(char)*lengthOfFileName+1);
        for(int i=0;i<lengthOfFileName;i++){
            openReturn->fileName[i] = buffer[i];
        }
        openReturn->fileName[lengthOfFileName] = '\0';
    }
}
