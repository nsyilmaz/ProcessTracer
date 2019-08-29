#include "defs.h"
#include "util.h"
#include <sys/uio.h>

int modify = 0;

int port;

char* ipaddr= NULL;

char* modifiedValue = NULL;
int readFilterFlag = 0;
int writeFilterFlag = 0;
int openFilterFlag = 0;
int acceptFilterFlag = 0;
int connectFilterFlag = 0;
int closeFilterFlag = 0;
int sendFilterFlag = 0;
int recvFilterFlag = 0;

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

void ipModifyValueTaker(char* buffer){
	char* startOfIPValue = strstr(buffer,"ip=")+3;
	int lengthOfIp = 0;
	while(*startOfIPValue != '&'){
		lengthOfIp++;
		startOfIPValue++;
	}
	ipaddr = malloc(sizeof(char)*lengthOfIp);
	startOfIPValue = strstr(buffer,"ip=")+3;
	for(int i=0;i<lengthOfIp;i++){
		ipaddr[i] = startOfIPValue[i];
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

void sendModifyHTTPHandler(){
	int numberOfNewlines = 0;
	int newPointerSize = 0;
	char* newPointer;
	for(int i=0;i<strlen(modifiedValue);i++){
		if(modifiedValue[i] == '\n'){
			numberOfNewlines++;
		}
	}
	newPointerSize = strlen(modifiedValue)+numberOfNewlines;
	newPointer = malloc(sizeof(char)*newPointerSize);
	for(int i=0,j=0;j<newPointerSize;){
		if(modifiedValue[i] == '\n'){
			newPointer[j++] = '\r';
		}
			newPointer[j] = modifiedValue[i];
			i++;
			j++;
	}
	free(modifiedValue);
	modifiedValue = newPointer;
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

char* pathForPtrace = NULL;


char responseHeader[] = "HTTP/1.1 200 OK\r\n"
"Content-Type: text/html; charset=UTF-8\r\n\r\n";

char htmlStart[] = "<!DOCTYPE html>\n"
"<html>\n"
"<head>\n"
"<title>Process Tracer</title>\n"
"</head>\n"
"<body>\n";

struct AJAXList* headSysCallList;

int counterForDeneme = 0;

char xmlSysCallScript[] =
"<div id=\"ajax-content\">\n"
"</div>\n"
"<script>\n"
"function nextSyscall() {\n"
"var myRequest = new XMLHttpRequest(); \n"
"myRequest.open('POST','/');\n"
"myRequest.send('xml=1');\n"
"myRequest.onreadystatechange = function(){ \n"
"if (myRequest.readyState === 4) {\n"
"document.getElementById('ajax-content').innerHTML = myRequest.responseText; \n"
"	}\n"
"}\n"
"};\n"
"</script>\n";

char xmlFirstSysCallScript[] =
"<div id=\"ajax-content\">\n"
"</div>\n"
"<script>\n"
"function firstSyscall() {\n"
"var myRequest = new XMLHttpRequest(); \n"
"myRequest.open('POST','/');\n"
"myRequest.send('attach=1');\n"
"myRequest.onreadystatechange = function(){ \n"
"if (myRequest.readyState === 4) {\n"
"document.getElementById('ajax-content').innerHTML = myRequest.responseText; \n"
"	}\n"
"}\n"
"};\n"
"firstSyscall();\n"
"</script>\n";

char xmlSysCallModifyScript[] =
"<script>\n"
"function modifySyscall() {\n"
"var modifyRequest = new XMLHttpRequest();\n"
"var modifyValue = document.getElementById(\"modifiedValue\");"
"var modifyIP = document.getElementById(\"ip\");"
"var modifyPort = document.getElementById(\"port\");"
"if(modifyIP && modifyPort){\n"
"modifyRequest.open('POST','/');\n"
"modifyRequest.send('xml=1&modify=1'+'&ip='+modifyIP.value+'&port='+modifyPort.value);\n"
"}\n"
"else if(modifyValue){"
"modifyRequest.open('POST','/');\n"
"modifyRequest.send('xml=1&modify=1'+'&value='+modifyValue.value);\n"
"}\n"
"modifyRequest.onreadystatechange = function(){ \n"
"if (modifyRequest.readyState === 4) {\n"
"document.getElementById('ajax-content').innerHTML = modifyRequest.responseText; \n"
"	}\n"
"}\n"
"};\n"
"</script>\n";

char htmlEnd[]=
"</body>\n"
"</html>\n";

char htmlStartWithCSS[] ="<!DOCTYPE html>\n"
"<html>\n"
"<head>\n"
"<style>\n"
"table, th, td { \n"
"  border: 1px solid black; \n "
"  border-collapse: collapse; \n "
"}\n"
"#path {\n"
" margin-left:200px;"
" margin-bottom:50px;"
"}\n"
"</style>\n"
"</head>\n"
"<body>\n";
char mainPanelHTML[]="<form action=\"/\" method=\"post\">\n"
"<input type=\"hidden\" id=\"execution\" name=\"operation\" value=\"0\">\n"
"<button id=\"path\" type=\"submit\">Exit</button>\n"
"</form>\n"
"<form action=\"/\" method=\"post\">\n"
"<p style=\"margin-left:200px;\">Path</p> \n <br>"
"<input type=\"checkbox\" name=\"filter\" value=\"Read\" style=\"margin-left:200px;\"> Read System Call\n"
"<input type=\"checkbox\" name=\"filter\" value=\"Write\"> Write System Call     \n"
"<input type=\"checkbox\" name=\"filter\" value=\"Open\"> Open System Call     \n"
"<input type=\"checkbox\" name=\"filter\" value=\"Accept\"> Accept System Call     <br>\n"
"<input style=\"margin-left:200px;\" type=\"checkbox\" name=\"filter\" value=\"Connect\"> Connect System Call     \n"
"<input type=\"checkbox\" name=\"filter\" value=\"Close\"> Close System Call     \n"
"<input type=\"checkbox\" name=\"filter\" value=\"Send\"> Send System Call     \n"
"<input type=\"checkbox\" name=\"filter\" value=\"Recv\"> Recv System Call     <br>\n"
"<input type=\"text\" name=\"path\"placeholder=\"Full Path to binary\" id=\"execution\" style =\"margin-left:200px\"></br>\n"
"<button id=\"path\" type=\"submit\">Submit</button>\n"
"</form>"
"<form action=\"/\" method=\"post\">\n"
"<input type=\"checkbox\" name=\"filter\" value=\"Read\" style=\"margin-left:200px;\"> Read System Call\n"
"<input type=\"checkbox\" name=\"filter\" value=\"Write\"> Write System Call     \n"
"<input type=\"checkbox\" name=\"filter\" value=\"Open\"> Open System Call     \n"
"<input type=\"checkbox\" name=\"filter\" value=\"Accept\"> Accept System Call     <br>\n"
"<input style=\"margin-left:200px;\" type=\"checkbox\" name=\"filter\" value=\"Connect\"> Connect System Call     \n"
"<input type=\"checkbox\" name=\"filter\" value=\"Close\"> Close System Call     \n"
"<input type=\"checkbox\" name=\"filter\" value=\"Send\"> Send System Call     \n"
"<input type=\"checkbox\" name=\"filter\" value=\"Recv\"> Recv System Call     <br>\n"
"<div id='process-table'>\n";

char tableStart[] = "<table  width=\"50%\" id=\"tab\" style=\"margin-left:200px;\">\n"
"<thead>\n"
"<tr>\n"
  "<th>Processes</th>\n"
  "<th> PID</th>\n"
	"<th> PPID </th>\n"
  "<th> Owner </th>\n"
    "<th> Command Line Arguments </th>\n"
  "<th> Choose </th>"
"</tr>\n"
"</thead> \n"
"<tbody id=\"tablediv\">\n";

char tableEnd[] = "<tr><td> <input type=\"submit\" value=\"Submit\"></td></tr>\n"
              "</tbody>\n"
              "</table>\n"
								      "</div>\n"
							              "</form>\n";

char xmlProcessListScript[] =
	      "<script>\n"
	      "setInterval(function(){ \n"
              "var myRequest = new XMLHttpRequest(); \n"
              "myRequest.open('POST','/');\n"
	      "myRequest.send('xml=2');\n"
	      "myRequest.onreadystatechange = function(){ \n"
	      "if (myRequest.readyState === 4) {\n"
	      "document.getElementById('process-table').innerHTML = myRequest.responseText; \n"
	      "}\n"
	      "}\n"
	      "},5000);\n"
	      "</script>\n";

struct processList pList = {0,NULL};
struct syscallList sList = {0,NULL};


pid_t traced_process = -1;
pthread_t threadAttach;
pthread_t threadFork;
int isStartedPtrace = 0;

int execvArraySize(char* cursor){
  int counter=2;
  while(*cursor){
      if(*cursor == ' '){
        counter++;
      }
      cursor++;
  }
  return counter;
}

int ishex(int x)
{
	return	(x >= '0' && x <= '9')	||
		(x >= 'a' && x <= 'f')	||
		(x >= 'A' && x <= 'F');
}

int decode(const char *s, char *dec)
{
	char *o;
	const char *end = s + strlen(s);
	int c;

	for (o = dec; s <= end; o++) {
		c = *s++;
		if (c == '+') c = ' ';
		else if (c == '%' && (	!ishex(*s++)	||
					!ishex(*s++)	||
					!sscanf(s - 2, "%2x", &c)))
			return -1;

		if (dec) *o = c;
	}

	return o - dec;
}

int stringSplit(char* c){
  int counter = 0;
  int i=0;
  while(c[i]){
      if(c[i] == 9){
          return counter;
      }
      i++;
      counter++;
  }
}

int checkInt(char buffer[]){
  int i=0;
  while(i<strlen(buffer)){
    if(!isdigit(buffer[i])){
      return 0;
    }
    i++;
  }
  return 1;
}

void resetFilterFlags(){
  readFilterFlag = 0;
  writeFilterFlag = 0;
  openFilterFlag = 0;
  acceptFilterFlag = 0;
  connectFilterFlag = 0;
  closeFilterFlag = 0;
  sendFilterFlag = 0;
  recvFilterFlag = 0;
}

void cats(char **str, const char *str2) {
    char *tmp = NULL;

    // Reset *str
    if ( *str != NULL && str2 == NULL ) {
        free(*str);
        *str = NULL;
        return;
    }

    // Initial copy
    if (*str == NULL) {
        *str = calloc( strlen(str2)+1, sizeof(char) );
        memcpy( *str, str2, strlen(str2) );
    }
    else { // Append
        tmp = calloc( strlen(*str)+1, sizeof(char) );
        memcpy( tmp, *str, strlen(*str) );
        *str = calloc( strlen(*str)+strlen(str2)+1, sizeof(char) );
        memcpy( *str, tmp, strlen(tmp) );
        memcpy( *str + strlen(*str), str2, strlen(str2) );
        free(tmp);
    }

}

int flagForNext = 0;

struct process* searchByPID(char *pid){
 for(int i=0;i<pList.length;i++){
	 if(strncmp(pList.array[i].pid,pid,strlen(pid)) == 0){
		 return (pList.array+i);
	 }
 }
 return NULL;
}

int returnForRequestHandler = 0;
int processListStateFlag = 0; //0 means wait, 1 means take current processes, 2 means stop
