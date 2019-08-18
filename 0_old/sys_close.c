#include "defs.h"
#include "util.h"
#include "sys_close.h"


void sys_close(pid_t forked_process, struct user_regs_struct* regs){

	unsigned char buffer[BUFFER_SIZE];

	printf("SYS_close \n");
	printf("Return: %li\n", regs->eax );
	printf("FD: %li\n", regs->ebx );
	printf("---\n");

}
