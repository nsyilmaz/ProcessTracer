#include "util.h"
#include "sys_accept_modify.h"
#include "defs.h"

void sys_acceptModify(pid_t process,struct user_regs_struct* structRegs,struct sys_acceptModify* acceptModify){
  struct iovec localSize;
  struct iovec remoteSize;
  struct iovec localData;
  struct iovec remoteData;
  int* pointerToLength = malloc(sizeof(int));
  *pointerToLength = acceptModify->length;
  localSize.iov_base = pointerToLength;
  localSize.iov_len = sizeof(int);
  remoteSize.iov_base = (void *) structRegs->rdx;
  remoteSize.iov_len = sizeof(int);
  process_vm_writev(process,&localSize,1,&remoteSize,1,0);
  free(pointerToLength);
  localData.iov_base = acceptModify->data;
  localData.iov_len = acceptModify->length;
  remoteData.iov_base = (void *) structRegs->rsi;
  remoteData.iov_len = acceptModify->length;
  process_vm_writev(process, &localData, 1, &remoteData, 1, 0);
}
