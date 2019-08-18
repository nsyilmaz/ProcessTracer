#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/net.h>
#include "defs.h"
#include "sys_open.h"
#include "sys_close.h"
#include "sys_read.h"
#include "sys_write.h"
#include "sys_send.h"
#include "sys_recv.h"
#include "sys_read_modify.h"
#include "sys_write_modify.h"







extern unsigned max_strlen;

int main(int argc, char* argv[]) {   

	char child_cmdline[BUFFER_SIZE];
	pid_t forked_process;


	if (argc == 1) {
		exit(0);
	}

	char* command[argc];
	int i = 0;

	while (i < argc - 1) {
		command[i] = argv[i+1];
		i++;
	}

	command[i] = NULL;

	forked_process = fork();

	if(forked_process == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execvp(command[0], command);
	}
	else {
		int status;
		int toggle = 0;
		//unsigned char buffer[BUFFER_SIZE];
		while(waitpid(forked_process, &status, 0) && ! WIFEXITED(status)) {
			struct user_regs_struct regs; 
			ptrace(PTRACE_GETREGS, forked_process, NULL, &regs);
      

			if (regs.orig_eax == 102 && regs.ebx == 9) { // SYS_SEND
				//sys_send(forked_process, &regs);
			}

			if (regs.orig_eax == 102 && regs.ebx == 10) { // SYS_RECV
				//sys_recv(forked_process, &regs);
			}

			if(regs.orig_eax == SYS_open ){
				//sys_open(forked_process, &regs);
			}

			if(regs.orig_eax == SYS_close ){
				//sys_close(forked_process, &regs);
			}

			if(regs.orig_eax == SYS_read ){
				//sys_read_modify(forked_process, &regs);
				//sys_read(forked_process, &regs);
			}

			if(regs.orig_eax == SYS_write ){
				if(toggle == 0 || toggle==1) {
					toggle++;
					sys_write_modify(forked_process, &regs);
					//sys_write(forked_process, &regs);
				}
				else {
					toggle = 0;
				}
			}



			//ptrace(PTRACE_SINGLESTEP, forked_process, NULL, NULL);
			//ptrace(PTRACE_SYSCALL, forked_process, NULL, NULL);
			ptrace(PTRACE_SYSCALL, forked_process, 0x1, NULL);
			//ptrace(PTRACE_SYSCALL, forked_process, NULL, NULL);
			//ptrace(PTRACE_SINGLESTEP, forked_process, NULL, NULL);
		}
	}

	return 0;
	
}




