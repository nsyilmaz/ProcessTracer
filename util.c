#include "defs.h"
#include "util.h"

int detachHasTouched = 0;

int modify = 0;

int port;

int isFilterChosen = 0;

char* ipaddr= NULL;

char* modifiedValue = NULL;

char* pathForPtrace = NULL;

int readFilterFlag = 0;

int writeFilterFlag = 0;

int openatFilterFlag = 0;

int acceptFilterFlag = 0;

int connectFilterFlag = 0;

int closeFilterFlag = 0;

int sendtoFilterFlag = 0;

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

char responseHeader[] = "HTTP/1.1 200 OK\r\n"
	"Content-Type: text/html; charset=UTF-8\r\n\r\n";

char htmlStart[] = "<!DOCTYPE html>\n"
	"<html>\n"
	"<head>\n"
	"<style>\n"
	".hexEditorCSS{margin:0;padding:0;vertical-align:top;font:1em/1em courier}\n"
	"#m{height:1.5em;resize:none;overflow:hidden}\n"
	"#t{padding:0 2px}\n"
	"#w{position:absolute;opacity:.001}\n"
	"</style>\n"
	"<title>Process Tracer</title>\n"
	"</head>\n"
	"<body>\n";

char htmlRegisterStart[] = "<!DOCTYPE html>\n"
		"<html>\n"
		"<head>\n"
		"<style>\n"
		".hexEditorCSS{margin:0;padding:0;vertical-align:top;font:1em/1em courier}\n"
		"#m{height:1.5em;resize:none;overflow:hidden}\n"
		"#t{padding:0 2px}\n"
		"#w{position:absolute;opacity:.001}\n"
		"</style>\n"
		"<title>Process Tracer</title>\n"
		"</head>\n"
		"<body>\n";

char textHexSwitchButton[] = "<input type=\"radio\" onclick=\"handleEditorChange(this);\" name=\"myRadios\"  value=\"Text\" checked/>Text\n"
    "<input type=\"radio\" name=\"myRadios\" onclick=\"handleEditorChange(this);\" value=\"Hex\" /> Hex\n";

char restOfHexEditor[] = "<table border class='hexEditorCSS' id=\"hexEditorTable\" style=\"display:none\">\n"
	"<td class='hexEditorCSS' >\n"
	"<pre class='hexEditorCSS' >\n"
	"</td>\n"
	"<td id=t class='hexEditorCSS'>\n"
	"<tr class='hexEditorCSS'>\n"
	"<td id=l class='hexEditorCSS' width=80>00000000</td>\n"
	"<td class='hexEditorCSS'>\n"
	"<textarea spellcheck=false id=m class='hexEditorCSS' oninput='\n"
	"b=value.substr(0,selectionStart).replace(/[^0-9A-F]/ig,\"\").replace(/(..)/g,\"$1 \").length;\n"
	"value=value.replace(/[^0-9A-F]/ig,\"\").replace(/(..)/g,\"$1 \").replace(/ $/,\"\").toUpperCase();\n"
	"style.height=(1.5+value.length/47)+\"em\";\n"
	"h=\"\";\n"
	"for(i=0;i<value.length/48;i++)\n"
	"h+=(1E7+(16*i).toString(16)).slice(-8)+\" \";\n"
	"l.innerHTML=h;\n"
	"h=\"\";\n"
	"for(i=0;i<value.length;i+=3)\n"
	"c=parseInt(value.substr(i,2),16),\n"
	"h=31<c&&127>c?h+String.fromCharCode(c):h+\".\";\n"
	"r.innerHTML=h.replace(/(.{16})/g,\"$1 \");\n"
	"if(value[b]==\" \")\n"
	"b--;\n"
	"setSelectionRange(b,b)' cols=48>\n";

char restOfHexEditor2[]=	"</textarea>\n"
	"</td>\n"
	"</td>\n"
	"<td width=160 id=r class='hexEditorCSS'>.</td>\n"
	"</table>\n"
	"<button onclick= 'modifySyscall()' id='hexEditorButton'  style=\"display:none\"> Modify & Continue </button></tr>\n";

struct AJAXList* headSysCallList;

struct process* chosenProcess = NULL;

int counterForDeneme = 0;

char finishWithoutCatchResponse[] = "<div class='jumbotron' style='width:70%; margin: auto;padding-top: 16px;padding-bottom: 16px;' align='center'>\n"
	"<h4 style='text-align:left;'>\n"
		"<font face='lato'>Attached Process has finished and It hasn't made any system call that specified.</font>\n"
	"</h4>\n"
"</div>\n"
"<table id='customers' style='margin-top: 50px;margin-bottom: 50px;' align='center'>\n"
	"<tbody>\n"
		"<tr>\n"
			"<th colspan='8'>Registers</th>\n"
		"</tr>\n"
	"</tbody>\n"
"</table>\n"
"<table id='customers' style='margin-bottom: 100px;' align='center'>\n"
	"<tbody>\n"
		"<tr>\n"
			"<th style='background-color:#4CAF50;'>Data</th>\n"
			"<th style='background-color:#4CAF50;'>Modify Area</th>\n"
		"</tr>\n"
	"</tbody>\n"
"</table>\n"
"<div style='position:absolute; bottom:0; width:100%;'>\n"
	"<h1> Latest System Calls </h1>\n"
	"<table id='customers' style='width:100%;'>\n"
		"<tbody>\n"
			"<tr>\n"
				"<th style='background-color:#4CAF50;'>System Call Name</th>\n"
				"<th style='background-color:#4CAF50;'>System Call Type</th>\n"
				"<th style='background-color:#4CAF50;'>RAX</th>\n"
				"<th style='background-color:#4CAF50;'>RDI</th>\n"
				"<th style='background-color:#4CAF50;'>RSI</th>\n"
				"<th style='background-color:#4CAF50;'>RDX</th>\n"
				"<th style='background-color:#4CAF50;'>RCX</th>\n"
				"<th style='background-color:#4CAF50;'>R8</th>\n"
				"<th style='background-color:#4CAF50;'>R9</th>\n"
			"</tr>\n"
		"</tbody>\n"
	"</table>\n"
"</div>\n";

char htmlEnd[] = "</body>\n"
	"</html>\n";

char tableStart[] = "<table  width=\"50%\" id=\"customers\" align=\"left\">\n"
	"<tbody>\n"
	"<tr>\n"
	"<th>Processes</th>\n"
	"<th> PID</th>\n"
	"<th> PPID </th>\n"
	"<th> Owner </th>\n"
	"<th> Command Line Arguments </th>\n"
	"<th> Select </th>"
	"</tr>\n"
	"<tbody>\n";

char tableEnd[] = //"<tr><td> <input class='button button2' type=\"submit\" value=\"Submit\"></td></tr>\n"
	"</tbody>\n"
	"</table>\n";

char systemCallTable[] = "<table id='table1' width='30%' border='1'>\n"
	"<thead>\n"
		"<tr>\n"
			"<th>Col1</th>\n"
			"<th>Col2</th>\n"
			"<th>Col3</th>\n"
		"</tr>\n"
	"</thead>\n"
	"<tbody>\n"
		"<tr>\n"
			"<td>info</td>\n"
			"<td>info</td>\n"
			"<td>info</td>\n"
		"</tr>\n"
		"<tr>\n"
			"<td>info</td>\n"
			"<td>info</td>\n"
			"<td>info</td>\n"
		"</tr>\n"
		"<tr>\n"
			"<td>info</td>\n"
			"<td>info</td>\n"
			"<td>info</td>\n"
		"</tr>\n"
	"</tbody>\n"
"</table>\n"
"<table id='header-fixed' style='position: fixed; display:none; top: 0px; background-color: white;' width='30%' border='1'>\n"
"</table>";
	//"</div>\n"
	//"</form>\n"


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
	return	(x >= '0' && x <= '9')	||	(x >= 'a' && x <= 'f')	||	(x >= 'A' && x <= 'F');
}

int decode(const char *s, char *dec)
{
	char *o;
	const char *end = s + strlen(s);
	int c;
	for (o = dec; s <= end; o++) {
		c = *s++;
		if (c == '+') c = ' ';
		else if (c == '%' && (	!ishex(*s++)	||	!ishex(*s++)	||	!sscanf(s - 2, "%2x", &c)))
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
	openatFilterFlag = 0;
	acceptFilterFlag = 0;
	connectFilterFlag = 0;
	closeFilterFlag = 0;
	sendtoFilterFlag = 0;
	recvFilterFlag = 0;
	isFilterChosen = 0;
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

char* stringToHex(char* string, int lengthOfString){
	char *hexArray = malloc(sizeof(char)*3*lengthOfString);
	char *returnedPointer = hexArray;
	for(int i=0;i<lengthOfString;i++){
		if(string[i] == '\n'){
			sprintf(hexArray,"0A");
		}
		else{
			sprintf(hexArray,"%02x",string[i]);
		}
		hexArray+=2;
		sprintf(hexArray," ");
		hexArray++;
	}
	returnedPointer[3*lengthOfString-1] = '\0';
	return returnedPointer;

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
