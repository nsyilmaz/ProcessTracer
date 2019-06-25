#include "sys_close.h"
void sys_close(pid_t process,struct user_regs_struct* structRegs,struct sys_closeReturn* closeReturn){
        closeReturn->fileDescriptor = structRegs->rdi;
}
