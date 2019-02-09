#include "defs.h"
#include "util.h"
#include "sys_open.h"


void sys_open(pid_t forked_process, struct user_regs_struct* regs){

	unsigned char buffer[BUFFER_SIZE];
	long addr;

	printf("SYS_open \n");
	printf("Return: %li\n", regs->eax );
	addr = regs->ebx;

	// if legitimate
	if (regs->eax > 0){
		umovestr_peekdata(forked_process, addr, BUFFER_SIZE, buffer );
		if(strlen(buffer)){
			printf("%s\n",buffer);
		}
	}
	printf("---\n");

}
