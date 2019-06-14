#include "defs.h"
#include "util.h"


const char *syscallName(long call) {
	switch(call) {

		case SYS_open :
			return "open";

		case SYS_read :
			return "read";

		case SYS_write :
			return "write";

		default:
			return "unknown";
	}
}



void putdata(pid_t child, long addr, char *str, int len){

	char *laddr;
	int i, j;
	union u {
		long val;
		char chars[long_size];
	}data;

	i = 0;
	j = len / long_size;
	laddr = str;

	while(i < j){
		memcpy(data.chars, laddr, long_size);
		ptrace(PTRACE_POKEDATA, child, addr + i * 4, data.val);
		++i;
		laddr += long_size;
	}

	j = len % long_size;
	if(j != 0) {
		memcpy(data.chars, laddr, j);
		ptrace(PTRACE_POKEDATA, child, addr + i * 4, data.val);
	}
}


void getdata(pid_t child, long addr,char *str, int len){

	char *laddr;
	int i, j;

	union u{
		long val;
		char chars[long_size];
	}data;

	i = 0;
	j = len / long_size;
	laddr = str;



	while(i < j){
		if((data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 4, NULL)) == -1){
			break;
		}

		memcpy(laddr, data.chars, long_size);
		++i;
		laddr += long_size;
	}


	j = len % long_size;

	if(j != 0){
		if((data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 4, NULL)) == -1){
			//error_exit("PTRACE_PEEKDATA failed.");
		}
	 	memcpy(laddr, data.chars, j);
	}
	str[len] = '\0';
}

void get_args(pid_t process, long addr, int len, unsigned char *buf) {
	long args[6];
	int i;

	for (i = 0; i < len; i++) {
		args[i] = ptrace(PTRACE_PEEKDATA, process, addr + i * 4, NULL);
	}

	getdata(process, args[1], buf, args[2]);

	return;
}


int umovestr_peekdata(const int pid, kernel_ulong_t addr, unsigned int len, void *laddr) {
	unsigned int nread = 0;
	unsigned int residue = addr & (sizeof(long) - 1);
	void *const orig_addr = laddr;

	while (len) {
		addr &= -sizeof(long);		/* aligned address */

		//errno = 0;
		union {
			unsigned long val;
			char x[sizeof(long)];
		} u = { .val = ptrace(PTRACE_PEEKDATA, pid, addr, 0) };

		switch (errno) {
			case 0:
				break;
			case ESRCH: case EINVAL:
				/* these could be seen if the process is gone */
				return -1;
			case EFAULT: case EIO: case EPERM:
				/* address space is inaccessible */
				if (nread) {
					//perror_msg("umovestr: short read (%d < %d) @0x%" PRI_klx,
					//	   nread, nread + len, addr - nread);
				}
				return -1;
			default:
				/* all the rest is strange and should be reported */
				//perror_msg("umovestr: PTRACE_PEEKDATA pid:%d @0x%" PRI_klx,
				//	   pid, addr);
				return -1;
		}

		unsigned int m = MIN(sizeof(long) - residue, len);
		memcpy(laddr, &u.x[residue], m);
		while (residue < sizeof(long))
			if (u.x[residue++] == '\0')
				return (laddr - orig_addr) + residue;
		residue = 0;
		addr += sizeof(long);
		laddr += m;
		nread += m;
		len -= m;
	}

	return 0;
}




int umoven_peekdata(const int pid, kernel_ulong_t addr, unsigned int len, char *laddr) {

        unsigned int nread = 0;
        unsigned int residue = addr & (sizeof(long) - 1);

        while (len) {
                addr &= -sizeof(long);          /* aligned address */

                errno = 0;
                union {
                        long val;
                        char x[sizeof(long)];
                } u = { .val = ptrace(PTRACE_PEEKDATA, pid, addr, 0) };

                switch (errno) {
                        case 0:
                                break;
                        case ESRCH: case EINVAL:
                                /* these could be seen if the process is gone */
                                return -1;
                        case EFAULT: case EIO: case EPERM:
                                /* address space is inaccessible */
                                if (nread) {
                                        //perror_msg("umoven: short read (%u < %u) @0x%" PRI_klx,
                                          //         nread, nread + len, addr - nread);
                                }
                                return -1;
                        default:
                                /* all the rest is strange and should be reported */
                                //perror_msg("umoven: PTRACE_PEEKDATA pid:%d @0x%" PRI_klx,
                                  //          pid, addr);
                                return -1;
                }

                unsigned int m = MIN(sizeof(long) - residue, len);
                memcpy(laddr, &u.x[residue], m);

		//if(strstr(laddr,"\0")){
		//	return 0;
		//}
                residue = 0;
                addr += sizeof(long);
                laddr += m;
                nread += m;
                len -= m;
        }

        return 0;
}



