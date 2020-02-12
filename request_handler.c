#include "util.h"
#include "request_handler.h"
#include "process_list.h"
#include "ptrace.h"
#include "defs.h"

void HTMLPageSender(int* fd_client, char *fileName){
    struct stat buf;
    int bytes_read, bytes_remaining, total_bytes = 0;
    char* buffer;
    if(stat(fileName,&buf) ==-1){
        perror("Stat Failure: ");
        exit(0);
    }
    FILE *fp = fopen(fileName,"rb");
    if(fp){
        //content type?
        //First take the cursor end of file
        //Then take the position of cursor
        int sizeofFile = (int) buf.st_size;
        buffer = malloc(sizeofFile);
        //Copy the file to the buffer
        fread(buffer,1, sizeofFile, fp);
        write(*fd_client,responseHeader,strlen(responseHeader));
        write(*fd_client,buffer,sizeofFile);
        free(buffer);
        fclose(fp);
    }
    else{
        perror("Can't Find the HTML File: ");
        exit(0);
    }
}

void sendProcessInformationPID(int* fd_client){
    //chosenProcess freelenmedi.
    char buffer[5012];
    write(*fd_client,responseHeader,strlen(responseHeader));
    write(*fd_client,htmlStart,strlen(htmlStart));
    sprintf(buffer,"<nav class='navbar navbar-light' style='margin-bottom: 50px;'>\n");
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<div class='container-fluid'>\n");
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<div class='navbar-header'>\n");
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<div class='dropdown'>\n");
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<button class='btn btn-success dropdown-toggle' type='button' data-toggle='dropdown' style='margin-top: 5px;margin-bottom: 5px; width:150%%;' aria-haspopup='true' aria-expanded='false'>Currently Attached Process Information <span class='caret'></span></button>\n");
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<ul class='dropdown-menu' style='width:150%%;'>\n");
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<li style='margin-left: 5px;'>Name Of Process: %s</li><div class='dropdown-divider'></div>\n",chosenProcess->name);
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<li style='margin-left: 5px;'>Process Id: %s</li><div class='dropdown-divider'></div>\n",chosenProcess->pid);
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<li style='margin-left: 5px;'>Parent Process Id: %s</li><div class='dropdown-divider'></div>\n",chosenProcess->ppid);
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<li style='margin-left: 5px;'>Process Owner: %s</li><div class='dropdown-divider'></div>\n",chosenProcess->user);
    write(*fd_client,buffer,strlen(buffer));
    if(strlen(chosenProcess->cmdline) == 0){
        sprintf(buffer,"<li style='margin-left: 5px;'>Commandline Arguments: Empty </li>\n");
        write(*fd_client,buffer,strlen(buffer));
    }
    else{
        sprintf(buffer,"<li style='margin-left: 5px;'>Commandline Arguments: %s</li>\n",chosenProcess->cmdline);
        write(*fd_client,buffer,strlen(buffer));
    }
    sprintf(buffer,"</ul>\n</div>\n</div>\n<div><form action='/' method='post'><input type='hidden' name='detach' value='1'><button class='btn btn-danger' onclick='abortTheSyscall()' type='submit' style='margin-top: 5px;margin-bottom: 5px; width:100%%;'>Detach From Current Process</button></form></div></div>\n</nav>\n");
    write(*fd_client,buffer,strlen(buffer));
    write(*fd_client,htmlEnd,strlen(htmlEnd));
}

void sendFilterInformation(int* fd_client){
    char buffer[5012];
    int comaFlag = 0;
    write(*fd_client,responseHeader,strlen(responseHeader));
    write(*fd_client,htmlStart,strlen(htmlStart));
    sprintf(buffer,"<h4 style='text-align:center; color:#28a745; margin-bottom:1em;'><font face='lato'>Filtered System Calls: ");
    write(*fd_client,buffer,strlen(buffer));
    if(readFilterFlag){
        sprintf(buffer,"Read");
        write(*fd_client,buffer,strlen(buffer));
        comaFlag=1;
    }
    if(writeFilterFlag){
        if(comaFlag){
            sprintf(buffer,", Write");
            write(*fd_client,buffer,strlen(buffer));
            comaFlag=1;
        }
        else{
            sprintf(buffer,"Write");
            write(*fd_client,buffer,strlen(buffer));
            comaFlag=1;
        }
    }
    if(openatFilterFlag){
        if(comaFlag){
            sprintf(buffer,", Openat");
            write(*fd_client,buffer,strlen(buffer));
            comaFlag=1;
        }
        else{
            sprintf(buffer,"Openat");
            write(*fd_client,buffer,strlen(buffer));
            comaFlag=1;
        }
    }
    if(acceptFilterFlag){
        if(comaFlag){
            sprintf(buffer,", Accept");
            write(*fd_client,buffer,strlen(buffer));
            comaFlag=1;
        }
        else{
            sprintf(buffer,"Accept");
            write(*fd_client,buffer,strlen(buffer));
            comaFlag=1;
        }
    }
    if(connectFilterFlag){
        if(comaFlag){
            sprintf(buffer,", Connect");
            write(*fd_client,buffer,strlen(buffer));
            comaFlag=1;
        }
        else{
            sprintf(buffer,"Connect");
            write(*fd_client,buffer,strlen(buffer));
            comaFlag=1;
        }
    }
    if(closeFilterFlag){
        if(comaFlag){
            sprintf(buffer,", Close");
            write(*fd_client,buffer,strlen(buffer));
            comaFlag=1;
        }
        else{
            sprintf(buffer,"Close");
            write(*fd_client,buffer,strlen(buffer));
            comaFlag=1;
        }
    }
    if(sendtoFilterFlag){
        if(comaFlag){
            sprintf(buffer,", Sendto");
            write(*fd_client,buffer,strlen(buffer));
            comaFlag=1;
        }
        else{
            sprintf(buffer,"Sendto");
            write(*fd_client,buffer,strlen(buffer));
            comaFlag=1;
        }
    }
    if(recvFilterFlag){
        if(comaFlag){
            sprintf(buffer,", RecvFrom");
            write(*fd_client,buffer,strlen(buffer));
            comaFlag=1;
        }
        else{
            sprintf(buffer,"RecvFrom");
            write(*fd_client,buffer,strlen(buffer));
            comaFlag=1;
        }
    }
    sprintf(buffer,"</font></h4>");
    write(*fd_client,buffer,strlen(buffer));
    write(*fd_client,htmlEnd,strlen(htmlEnd));
}

void filterFlagHandler(char* buffer){
    if(strstr(buffer,"filter=Read")){
        readFilterFlag = 1;
        isFilterChosen = 1;
    }
    if(strstr(buffer,"filter=Write")){
        writeFilterFlag = 1;
        isFilterChosen = 1;
    }
    if(strstr(buffer,"filter=Openat")){
        openatFilterFlag = 1;
        isFilterChosen = 1;
    }
    if(strstr(buffer,"filter=Accept")){
        acceptFilterFlag = 1;
        isFilterChosen = 1;
    }
    if(strstr(buffer,"filter=Connect")){
        connectFilterFlag = 1;
        isFilterChosen = 1;
    }
    if(strstr(buffer,"filter=Close")){
        closeFilterFlag = 1;
        isFilterChosen = 1;
    }
    if(strstr(buffer,"filter=Sendto")){
        sendtoFilterFlag = 1;
        isFilterChosen = 1;
    }
    if(strstr(buffer,"filter=Recv")){
        recvFilterFlag = 1;
        isFilterChosen = 1;
    }
}

void freeChosenProcess(){
    free(chosenProcess->pid);
    free(chosenProcess->ppid);
    free(chosenProcess->user);
    free(chosenProcess->name);
    free(chosenProcess->cmdline);
    chosenProcess->pid = NULL;
    chosenProcess->ppid = NULL;
    chosenProcess->user = NULL;
    chosenProcess->name = NULL;
    chosenProcess->cmdline = NULL;
    free(chosenProcess);
    chosenProcess = NULL;
}

void chosenProcessCopier(struct process* chosenProcessPointer){
    if(chosenProcess != NULL){
        freeChosenProcess();
    }
    chosenProcess = malloc(sizeof(struct process));
    int lengthOfPid = strlen(chosenProcessPointer->pid);
    int lengthOfPPid = strlen(chosenProcessPointer->ppid);
    int lengthOfUser = strlen(chosenProcessPointer->user);
    int lengthOfName = strlen(chosenProcessPointer->name);
    int lengthOfCmdline = strlen(chosenProcessPointer->cmdline);

    chosenProcess->pid = malloc(lengthOfPid+1);
    chosenProcess->ppid = malloc(lengthOfPPid+1);
    chosenProcess->user = malloc(lengthOfUser+1);
    chosenProcess->name = malloc(lengthOfName+1);
    chosenProcess->cmdline = malloc(lengthOfCmdline+1);

    strncpy(chosenProcess->pid,chosenProcessPointer->pid,lengthOfPid);
    strncpy(chosenProcess->ppid,chosenProcessPointer->ppid,lengthOfPPid);
    strncpy(chosenProcess->user,chosenProcessPointer->user,lengthOfUser);
    strncpy(chosenProcess->name,chosenProcessPointer->name,lengthOfName);
    strncpy(chosenProcess->cmdline,chosenProcessPointer->cmdline,lengthOfCmdline);

    chosenProcess->pid[lengthOfPid] = '\0';
    chosenProcess->ppid[lengthOfPPid] = '\0';
    chosenProcess->user[lengthOfUser] = '\0';
    chosenProcess->name[lengthOfName] = '\0';
    chosenProcess->cmdline[lengthOfCmdline] = '\0';

}

void startPtraceFromPID(int* fd_client,char* request){
    if(isStartedPtrace == 0){
        char *starterOfStringPID = strstr(request,"pid=") + 4;
        char *pid = malloc(sizeof(char));
        int i=0;
        while(*starterOfStringPID != EOF && *starterOfStringPID != '\n' && *starterOfStringPID != '&'){
            pid[i++] = *starterOfStringPID++;
            pid = realloc(pid,sizeof(char)*(i+1));
        }
        pid[i] = '\0';
        struct process* chosenProcessPointer = searchByPID(pid);
        if(chosenProcessPointer == NULL){
            perror("WRONG PID");
        }
        else{
            chosenProcessCopier(chosenProcessPointer);
            filterFlagHandler(request);
            if(!isFilterChosen){
                free(pid);
                HTMLPageSender(fd_client,"mainPage.html");
                return;
            }
            HTMLPageSender(fd_client,"startProcessFromPID.html");
            traced_process = atoi(pid);
            if(traced_process >= 0){
                flagForNext = 0;
                int err = pthread_create(&threadAttach,NULL,ptraceAttach,&traced_process);
                if(err != 0){
                    perror("Running Process Tracer By PID Error:");
                    exit(0);
                }
                isStartedPtrace = 1;
            }
            free(pid);
        }
    }
}

void sendProcessInformationPath(int* fd_client){
    char buffer[5012];
    write(*fd_client,responseHeader,strlen(responseHeader));
    write(*fd_client,htmlStart,strlen(htmlStart));
    sprintf(buffer,"<nav class='navbar navbar-light' style='margin-bottom: 50px;'>\n");
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<div class='container-fluid'>\n");
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<div class='navbar-header'>\n");
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<div class='dropdown'>\n");
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<button class='btn btn-success dropdown-toggle' type='button' data-toggle='dropdown' style='margin-top: 5px;margin-bottom: 5px; width:150%%;' aria-haspopup='true' aria-expanded='false'>Currently Attached Process Information <span class='caret'></span></button>\n");
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<ul class='dropdown-menu' style='width:150%%;'>\n");
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<li style='margin-left: 5px;'>Path Of Attached Process: %s</li>\n",pathForPtrace);
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"</ul>\n</div>\n</div>\n<div><form action='/' method='post'><input type='hidden' name='detach' value='1'><button class='btn btn-danger' type='submit' onclick='abortTheSyscall()' style='margin-top: 5px;margin-bottom: 5px; width:100%%;'>Detach From Current Process</button></form></div></div>\n</nav>\n");
    write(*fd_client,buffer,strlen(buffer));
    write(*fd_client,htmlEnd,strlen(htmlEnd));
}

void sendModifyTable(int* fd_client,char* buffer,int i){
    if(sList.array[i].length){
        /*write(*fd_client,textHexSwitchButton,strlen(textHexSwitchButton));
        char* hexData = stringToHex(sList.array[i].data,sList.array[i].length);
        write(*fd_client,restOfHexEditor,strlen(restOfHexEditor));
        sprintf(buffer, "%s",hexData);
        write(*fd_client,buffer,strlen(buffer));
        write(*fd_client,restOfHexEditor2,strlen(restOfHexEditor2));
        free(hexData); */
        //TODO: Hex Table
    }
    sprintf(buffer,"<table id='customers' align='center' style='margin-bottom: 100px;'>");
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<tr><th style='background-color:#4CAF50;'>Data</th><th style='background-color:#4CAF50;'>Modify Area</th></tr>");
    write(*fd_client,buffer,strlen(buffer));

    if(sList.array[i].regs->orig_eax == SYS_close){
        sprintf(buffer,"<tr> <td>%llu</td> <td><textarea class=\"form-control \" id=\"modifiedValue\" rows=\"6\" cols=\"50\">%llu</textarea></td>",sList.array[i].regs->rdi,sList.array[i].regs->rdi);
        write(*fd_client,buffer,strlen(buffer));
    }
    else{
        sprintf(buffer,"<tr> <td>%.4000s</td>  <td><textarea class=\"form-control \" id=\"modifiedValue\" rows=\"6\" cols=\"50\">%.4000s</textarea></td></tr>",sList.array[i].data,sList.array[i].data);
        write(*fd_client,buffer,strlen(buffer));
    }
    sprintf(buffer,"<tr onmouseover=\"this.style.background='white'\" style=\"border:0;\"><td style='border: 0; text-align: center;'><button class='button button2' onclick = 'nextSyscall()'>Next</button></td><td style='border: 0; text-align: center;'><button class='button button2' align='center' onclick = 'modifySyscall()'>Modify & Continue</button></td>");
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer, "</tbody></table>");
    write(*fd_client,buffer,strlen(buffer));
}

void startPtraceFromPath(int* fd_client,char* request){
    if(isStartedPtrace == 0){
        char *starterOfStringPath = strstr(request,"path=")+5;
        char *path = malloc(sizeof(char)*strlen(starterOfStringPath));
        if(decode(starterOfStringPath, path) > 0){
            pathForPtrace = malloc(strlen(path)+1);
            strncpy(pathForPtrace,path,strlen(path));
            pathForPtrace[strlen(path)] = '\0';
            filterFlagHandler(request);
            if(!isFilterChosen){
                free(path);
                free(pathForPtrace);
                path = NULL;
                pathForPtrace = NULL;
                HTMLPageSender(fd_client,"mainPage.html");
                return;
            }
            HTMLPageSender(fd_client,"startProcessFromPath.html");
            threadFork = 0;
            int err = pthread_create(&threadFork,NULL,ptraceFork,path);
            flagForNext = 0;
            if(err != 0){
                perror("Running Process Tracer By PID Error:");
                exit(0);
            }
            isStartedPtrace = 1;
        }
    }
}

void sys_connectDataWithModifySender(int *fd_client,int i){
    char buffer[5012];
    struct sockaddr_in* connectStruct = (struct sockaddr_in*) sList.array[i].data;
    sprintf(buffer,"<table id='customers' align='center' style='margin-bottom: 100px;'>");
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<tr><th style='background-color:#4CAF50;'>Data</th><th style='background-color:#4CAF50;'>Modify Area</th></tr>");
    write(*fd_client,buffer,strlen(buffer));
    if(sList.array[i].entry_exit_flag == 0){
        sprintf(buffer,"<tr><td><p> Ip address: %s</p>",inet_ntoa(connectStruct->sin_addr));
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<p> Port: %d</p></td>",htons(connectStruct->sin_port));
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<td><p> Ip address: <input id=\"ip\" value= \"%s\"></p>",inet_ntoa(connectStruct->sin_addr));
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<p> Port: <input id=\"port\" value = \"%d\"></p></td></tr>",htons(connectStruct->sin_port));
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<tr onmouseover=\"this.style.background='white'\" style=\"border:0;\"><td style='border: 0; text-align: center;'><button class='button button2' onclick = 'nextSyscall()'>Next</button></td><td style='border: 0; text-align: center;'><button class='button button2' align='center' onclick = 'modifySyscall()'>Modify & Continue</button></td>");
        write(*fd_client,buffer,strlen(buffer));
    }
    else{
        sprintf(buffer,"<tr><td><p> Ip adress: %s </p>\n",inet_ntoa(connectStruct->sin_addr));
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<p> Port: %d </p></td>\n",htons(connectStruct->sin_port));
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<td>In Connect System Call, On The Exit Of It, You Can't Manipulate The Data.</td></tr>");
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<tr onmouseover=\"this.style.background='white'\" style=\"border:0;\"><td style='border: 0; text-align: center;'><button class='button button2' onclick = 'nextSyscall()'>Next</button></td>");
        write(*fd_client,buffer,strlen(buffer));
    }
    sprintf(buffer, "</tbody></table>");
    write(*fd_client,buffer,strlen(buffer));
}

void sys_openatDataWithModifySender(int *fd_client,int i){
    char buffer[5012];
    if(sList.array[i].entry_exit_flag == 0){
        sendModifyTable(fd_client,buffer,i);
    }
    else if(sList.array[i].entry_exit_flag == 1){
        sprintf(buffer,"<table id='customers' align='center' style='margin-bottom: 100px;'>");
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<tr><th style='background-color:#4CAF50;'>Data</th><th style='background-color:#4CAF50;'>Modify Area</th></tr>");
        write(*fd_client,buffer,strlen(buffer));
        if(sList.array[i].data){
            sprintf(buffer,"<tr> <td>%s</td><td>In Openat System Call, On The Exit Of It, You Can't Manipulate The Data.</td></tr>",sList.array[i].data);
            write(*fd_client,buffer,strlen(buffer));
        }
        else{
            sprintf(buffer,"<tr> <td></td>  <td>In Openat System Call, On The Exit Of It, You Can't Manipulate The Data.</td></tr>");
            write(*fd_client,buffer,strlen(buffer));
        }
        sprintf(buffer,"<tr onmouseover=\"this.style.background='white'\" style=\"border:0;\"><td style='border: 0; text-align: center;'><button class='button button2' onclick = 'nextSyscall()'>Next</button></td>");
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer, "</tbody></table>");
        write(*fd_client,buffer,strlen(buffer));
        }
}

void sys_closeDataWithModifySender(int *fd_client, int i){
    char buffer[5012];
    if(sList.array[i].entry_exit_flag == 0){
        sendModifyTable(fd_client,buffer,i);
    }
    else if(sList.array[i].entry_exit_flag == 1){
        sprintf(buffer,"<table id='customers' align='center' style='margin-bottom: 100px;'>");
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<tr><th style='background-color:#4CAF50;'>Data</th><th style='background-color:#4CAF50;'>Modify Area</th></tr>");
        write(*fd_client,buffer,strlen(buffer));
        if(sList.array[i].data){
            sprintf(buffer,"<tr> <td>%llu</td><td>In Close System Call, On The Exit Of It, You Can't Manipulate The Data.</td></tr>",sList.array[i].regs->rdi);
            write(*fd_client,buffer,strlen(buffer));
        }
        else{
            sprintf(buffer,"<tr> <td></td>  <td>In Close System Call, On The Exit Of It, You Can't Manipulate The Data.</td></tr>");
            write(*fd_client,buffer,strlen(buffer));
        }
        sprintf(buffer,"<tr onmouseover=\"this.style.background='white'\" style=\"border:0;\"><td style='border: 0; text-align: center;'><button class='button button2' onclick = 'nextSyscall()'>Next</button></td>");
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer, "</tbody></table>");
        write(*fd_client,buffer,strlen(buffer));
    }
}

void sys_writeDataWithModifySender(int *fd_client, int i){
    char buffer[5012];
    if(sList.array[i].entry_exit_flag == 0){
        sendModifyTable(fd_client,buffer,i);
    }
    else if(sList.array[i].entry_exit_flag == 1){
        sprintf(buffer,"<table id='customers' align='center' style='margin-bottom: 100px;'>");
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<tr><th style='background-color:#4CAF50;'>Data</th><th style='background-color:#4CAF50;'>Modify Area</th></tr>");
        write(*fd_client,buffer,strlen(buffer));
        if(sList.array[i].data){
            sprintf(buffer,"<tr> <td>%s</td><td>In Write System Call, On The Exit Of It, You Can't Manipulate The Data.</td></tr>",sList.array[i].data);
            write(*fd_client,buffer,strlen(buffer));
        }
        else{
            sprintf(buffer,"<tr> <td></td>  <td>In Write System Call, On The Exit Of It, You Can't Manipulate The Data.</td></tr>");
            write(*fd_client,buffer,strlen(buffer));
        }
        sprintf(buffer,"<tr onmouseover=\"this.style.background='white'\" style=\"border:0;\"><td style='border: 0; text-align: center;'><button class='button button2' onclick = 'nextSyscall()'>Next</button></td>");
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer, "</tbody></table>");
        write(*fd_client,buffer,strlen(buffer));
    }
}

void sys_callEntryExitSender(int *fd_client,int i){
    char buffer[5012];
    if(sList.array[i].entry_exit_flag == 1){
        sprintf(buffer,"<td>System Call Exit</td>");
        write(*fd_client,buffer,strlen(buffer));
    }
    else{
        sprintf(buffer,"<td>System Call Entry</td>");
        write(*fd_client,buffer,strlen(buffer));
    }
}

void sys_sendtoDataWithModifySender(int *fd_client,int i){
    char buffer[5012];
    if(sList.array[i].entry_exit_flag == 0){
        sendModifyTable(fd_client,buffer,i);
    }
    else if(sList.array[i].entry_exit_flag == 1){
        sprintf(buffer,"<table id='customers' align='center' style='margin-bottom: 100px;'>");
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<tr><th style='background-color:#4CAF50;'>Data</th><th style='background-color:#4CAF50;'>Modify Area</th></tr>");
        write(*fd_client,buffer,strlen(buffer));
        if(sList.array[i].data){
            sprintf(buffer,"<tr> <td>%s</td><td>In SendTo System Call, On The Exit Of It, You Can't Manipulate The Data.</td></tr>",sList.array[i].data);
            write(*fd_client,buffer,strlen(buffer));
        }
        else{
            sprintf(buffer,"<tr> <td></td>  <td>In SendTo System Call, On The Exit Of It, You Can't Manipulate The Data.</td></tr>");
            write(*fd_client,buffer,strlen(buffer));
        }
        sprintf(buffer,"<tr onmouseover=\"this.style.background='white'\" style=\"border:0;\"><td style='border: 0; text-align: center;'><button class='button button2' onclick = 'nextSyscall()'>Next</button></td>");
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer, "</tbody></table>");
        write(*fd_client,buffer,strlen(buffer));
    }
}

void sys_recvfromDataWithModifySender(int *fd_client,int i){
    char buffer[5012];
    if(sList.array[i].entry_exit_flag == 1){
        sendModifyTable(fd_client,buffer,i);
    }
    else if(sList.array[i].entry_exit_flag == 0){
        sprintf(buffer,"<table id='customers' align='center' style='margin-bottom: 100px;'>");
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<tr><th style='background-color:#4CAF50;'>Data</th><th style='background-color:#4CAF50;'>Modify Area</th></tr>");
        write(*fd_client,buffer,strlen(buffer));
        if(sList.array[i].data){
            sprintf(buffer,"<tr> <td>%s</td><td>In RecvFrom System Call, On The Entry Of It, You Can't Manipulate The Data.</td></tr>",sList.array[i].data);
            write(*fd_client,buffer,strlen(buffer));
        }
        else{
            sprintf(buffer,"<tr> <td></td>  <td>In RecvFrom System Call, On The Entry Of It, You Can't Manipulate The Data.</td></tr>");
            write(*fd_client,buffer,strlen(buffer));
        }
        sprintf(buffer,"<tr onmouseover=\"this.style.background='white'\" style=\"border:0;\"><td style='border: 0; text-align: center;'><button class='button button2' onclick = 'nextSyscall()'>Next</button></td>");
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer, "</tbody></table>");
        write(*fd_client,buffer,strlen(buffer));
    }
}

void sys_readDataWithModifySender(int *fd_client,int i){
    char buffer[5012];
    if(sList.array[i].entry_exit_flag == 1){
        sendModifyTable(fd_client,buffer,i);
    }
    else if(sList.array[i].entry_exit_flag == 0){
        sprintf(buffer,"<table id='customers' align='center' style='margin-bottom: 100px;'>");
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<tr><th style='background-color:#4CAF50;'>Data</th><th style='background-color:#4CAF50;'>Modify Area</th></tr>");
        write(*fd_client,buffer,strlen(buffer));
        if(sList.array[i].data){
            sprintf(buffer,"<tr> <td>%s</td><td>In Read System Call, On The Entry Of It, You Can't Manipulate The Data.</td></tr>",sList.array[i].data);
            write(*fd_client,buffer,strlen(buffer));
        }
        else{
            sprintf(buffer,"<tr> <td></td>  <td>In Read System Call, On The Entry Of It, You Can't Manipulate The Data.</td></tr>");
            write(*fd_client,buffer,strlen(buffer));
        }
        sprintf(buffer,"<tr onmouseover=\"this.style.background='white'\" style=\"border:0;\"><td style='border: 0; text-align: center;'><button class='button button2' onclick = 'nextSyscall()'>Next</button></td>");
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer, "</tbody></table>");
        write(*fd_client,buffer,strlen(buffer));
    }
}

void sys_acceptDataWithModifySender(int *fd_client,int i){
    char buffer[5012];
    struct sockaddr_in* acceptStruct = (struct sockaddr_in*) sList.array[i].data;
    sprintf(buffer,"<table id='customers' align='center' style='margin-bottom: 100px;'>");
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<tr><th style='background-color:#4CAF50;'>Data</th><th style='background-color:#4CAF50;'>Modify Area</th></tr>");
    write(*fd_client,buffer,strlen(buffer));
    if(sList.array[i].entry_exit_flag == 1){
        sprintf(buffer,"<tr><td><p> Ip address: %s</p>",inet_ntoa(acceptStruct->sin_addr));
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<p> Port: %d</p></td>",htons(acceptStruct->sin_port));
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<td><p> Ip address: <input id=\"ip\" value= \"%s\"></p>",inet_ntoa(acceptStruct->sin_addr));
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<p> Port: <input id=\"port\" value = \"%d\"></p></td></tr>",htons(acceptStruct->sin_port));
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<tr onmouseover=\"this.style.background='white'\" style=\"border:0;\"><td style='border: 0; text-align: center;'><button class='button button2' onclick = 'nextSyscall()'>Next</button></td><td style='border: 0; text-align: center;'><button class='button button2' align='center' onclick = 'modifySyscall()'>Modify & Continue</button></td>");
        write(*fd_client,buffer,strlen(buffer));
    }
    else{
        sprintf(buffer,"<tr><td><p> Ip adress: %s </p>\n",inet_ntoa(acceptStruct->sin_addr));
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<p> Port: %d </p></td>\n",htons(acceptStruct->sin_port));
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<td>In Accept System Call, On The Entry Of It, You Can't Manipulate The Data.</td></tr>");
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<tr onmouseover=\"this.style.background='white'\" style=\"border:0;\"><td style='border: 0; text-align: center;'><button class='button button2' onclick = 'nextSyscall()'>Next</button></td>");
        write(*fd_client,buffer,strlen(buffer));
    }
    sprintf(buffer, "</tbody></table>");
    write(*fd_client,buffer,strlen(buffer));
}

void sys_connectDataSender(int *fd_client,int i){
    char buffer[5012];
    struct sockaddr_in* connectStruct = (struct sockaddr_in*) sList.array[i].data;
    sprintf(buffer,"<p> Ip adress: %s </p>",inet_ntoa(connectStruct->sin_addr));
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<p> Port: %d </p>",htons(connectStruct->sin_port));
    write(*fd_client,buffer,strlen(buffer));
}

void sys_openatDataSender(int *fd_client,int i){
    char buffer[5012];
    if(sList.array[i].data){
        sprintf(buffer,"<p> Data: %s </p>",sList.array[i].data);
    }
    else{
        sprintf(buffer,"<p> Data: </p>");
    }
    write(*fd_client,buffer,strlen(buffer));
}

void sys_closeDataSender(int *fd_client,int i){
    char buffer[5012];
    sprintf(buffer,"<p>File Descriptor: %lld",sList.array[i].regs->rdi);
    write(*fd_client,buffer,strlen(buffer));
}

void sys_writeDataSender(int *fd_client,int i){
    char buffer[5012];
    if(sList.array[i].data){
        sprintf(buffer,"<p> Data: %s </p>",sList.array[i].data);
    }
    else{
        sprintf(buffer,"<p> Data: </p>");
    }
    write(*fd_client,buffer,strlen(buffer));
}

void sys_sendtoDataSender(int *fd_client,int i){
    char buffer[5012];
    if(sList.array[i].data){
        sprintf(buffer,"<p> Data: %s </p>",sList.array[i].data);
    }
    else{
        sprintf(buffer,"<p> Data: </p>");
    }
    write(*fd_client,buffer,strlen(buffer));
}

void sys_recvfromDataSender(int *fd_client,int i){
    char buffer[5012];
    if(sList.array[i].data){
        sprintf(buffer,"<p> Data: %s </p>",sList.array[i].data);
    }
    else{
        sprintf(buffer,"<p> Data: </p>");
    }
    write(*fd_client,buffer,strlen(buffer));
}

void sys_readDataSender(int *fd_client,int i){
    char buffer[5012];
    if(sList.array[i].data){
        sprintf(buffer,"<p> Data: %s </p>",sList.array[i].data);
    }
    else{
        sprintf(buffer,"<p> Data: </p>");
    }
    write(*fd_client,buffer,strlen(buffer));
}

void sys_acceptDataSender(int *fd_client,int i){
    char buffer[5012];
    struct sockaddr_in* acceptStruct = (struct sockaddr_in*) sList.array[i].data;
    sprintf(buffer,"<p> Ip adress: %s </p>",inet_ntoa(acceptStruct->sin_addr));
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<p> Port: %d </p>",htons(acceptStruct->sin_port));
    write(*fd_client,buffer,strlen(buffer));
}

void sendRegistersFromIndex(int *fd_client,int i){
    char buffer[5012];
    if(i==sList.length-1){
        sprintf(buffer,"<table id='customers' align='center' style='margin-top: 50px;margin-bottom: 50px;'>");
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<tr><th colspan='8'>Registers</tr>");
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<tr> <td>RDI</td> <td>%llu</td> <td>RSI</td> <td>%llu</td> <td>RDX</td> <td>%llu</td> <td>RCX</td> <td>%llu</td> </tr>",sList.array[i].regs->rdi,sList.array[i].regs->rsi,sList.array[i].regs->rdx,sList.array[i].regs->rcx);
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<tr> <td>R8</td> <td>%llu</td> <td>R9</td> <td>%llu</td> <td>R10</td> <td>%llu</td> <td>R11</td> <td>%llu</td> </tr>",sList.array[i].regs->r8,sList.array[i].regs->r9,sList.array[i].regs->r10,sList.array[i].regs->r11);
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<tr> <td>R12</td> <td>%llu</td> <td>R13</td> <td>%llu</td> <td>R14</td> <td>%llu</td> <td>R15</td> <td>%llu</td> </tr>",sList.array[i].regs->r12,sList.array[i].regs->r13,sList.array[i].regs->r14,sList.array[i].regs->r15);
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<tr> <td>RBP</td> <td>%llu</td> <td>RBX</td> <td>%llu</td> <td>RAX</td> <td>%llu</td> <td>RSP</td> <td>%llu</td> </tr>",sList.array[i].regs->rbp,sList.array[i].regs->rbx,sList.array[i].regs->rax,sList.array[i].regs->rsp);
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"</tbody></table>");
        write(*fd_client,buffer,strlen(buffer));
    }
    else{
        sprintf(buffer,"<td>%llu</td>",sList.array[i].regs->rax);
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<td>%llu</td>",sList.array[i].regs->rdi);
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<td>%llu</td>",sList.array[i].regs->rsi);
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<td>%llu</td>",sList.array[i].regs->rdx);
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<td>%llu</td>",sList.array[i].regs->rcx);
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<td>%llu</td>",sList.array[i].regs->r8);
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<td>%llu</td>",sList.array[i].regs->r9);
        write(*fd_client,buffer,strlen(buffer));
    }

}

void sendSyscallNameFromIndex(int *fd_client,int i){
    char buffer[5012];
    if(sList.array[i].regs->orig_eax == SYS_write){
        if(i==sList.length-1){
            if(sList.array[i].entry_exit_flag == 1){
                sprintf(buffer,"<div class='jumbotron' style='width:70%%; margin: auto;padding-top: 16px;padding-bottom: 16px;' align='center'><h4 style='text-align:left;'><font face='lato'>Stopped at Exit of Write System Call</font></h4>");
                write(*fd_client,buffer,strlen(buffer));
            }
            else{
                sprintf(buffer,"<div class='jumbotron' style='width:70%%; margin: auto;padding-top: 16px;padding-bottom: 16px;' align='center'><h4 style='text-align:left;'><font face='lato'>Stopped at Entry of Write System Call</font></h4>");
                write(*fd_client,buffer,strlen(buffer));
            }
            sprintf(buffer,"<h5 style='margin-bottom: 0px; text-align:left;'>This system call writes to a file descriptor.<span style='float:right;'> size_t write(%llu,",sList.array[i].regs->rdi);
            write(*fd_client,buffer,strlen(buffer));
            if(sList.array[i].length > 8){
                sprintf(buffer,"\"%.8s...\",%llu)</h5></div>",sList.array[i].data,sList.array[i].regs->rdx);
                write(*fd_client,buffer,strlen(buffer));
            }
            else{
                sprintf(buffer,"\"%s\",%llu)</h5></div>",sList.array[i].data,sList.array[i].regs->rdx);
                write(*fd_client,buffer,strlen(buffer));
            }
            /*sprintf(buffer,"<h5 style='margin-bottom: 0px; text-align:left;'>This system call writes to a file descriptor.<span style='float:right;'> size_t write(int fd, const void *buf, size_t count)</h5></div>",sList.array[i].regs->rdi,sList.array[i].data,sList.array[i].regs->rdx);
            write(*fd_client,buffer,strlen(buffer));*/
        }
        else{
            sprintf(buffer,"<tr><td>Write System Call</td>");
            write(*fd_client,buffer,strlen(buffer));
        }
    }
    else if(sList.array[i].regs->orig_eax == SYS_sendto){
        if(i==sList.length-1){
            if(sList.array[i].entry_exit_flag == 1){
                sprintf(buffer,"<div class='jumbotron' style='width:70%%; margin: auto;padding-top: 16px;padding-bottom: 16px;' align='center'><h4 style='text-align:left;'><font face='lato'>Stopped at Exit of Sendto System Call</font></h4>");
                write(*fd_client,buffer,strlen(buffer));
            }
            else{
                sprintf(buffer,"<div class='jumbotron' style='width:70%%; margin: auto;padding-top: 16px;padding-bottom: 16px;' align='center'><h4 style='text-align:left;'><font face='lato'>Stopped at Entry of Sendto System Call</font></h4>");
                write(*fd_client,buffer,strlen(buffer));
            }
            sprintf(buffer,"<h5 style='margin-bottom: 0px; text-align:left;'>This system call sends a message on a socket.<span style='float:right;'> ssize_t sendto(%llu,",sList.array[i].regs->rdi);
            write(*fd_client,buffer,strlen(buffer));
            if(sList.array[i].length > 8){
                sprintf(buffer,"\"%.8s...\",%llu,%llu,%llu,%llu)</h5></div>",sList.array[i].data,sList.array[i].regs->rdx,sList.array[i].regs->rcx,sList.array[i].regs->r8,sList.array[i].regs->r9);
                write(*fd_client,buffer,strlen(buffer));
            }
            else{
                sprintf(buffer,"\"%s\",%llu,%llu,%llu,%llu)</h5></div>",sList.array[i].data,sList.array[i].regs->rdx,sList.array[i].regs->rcx,sList.array[i].regs->r8,sList.array[i].regs->r9);
                write(*fd_client,buffer,strlen(buffer));
            }
            /*sprintf(buffer,"<h5 style='margin-bottom: 0px; text-align:left;'>This system call sends a message on a socket.<span style='float:right;'> ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,const struct sockaddr *dest_addr, socklen_t addrlen)</h5></div>");
            write(*fd_client,buffer,strlen(buffer)); */
        }
        else{
            sprintf(buffer,"<tr><td>SendTo System Call</td>");
            write(*fd_client,buffer,strlen(buffer));
        }
    }
    else if(sList.array[i].regs->orig_eax == SYS_connect){
        if(i==sList.length-1){
            struct sockaddr_in* connectStruct = (struct sockaddr_in*) sList.array[i].data;
            if(sList.array[i].entry_exit_flag == 1){
                sprintf(buffer,"<div class='jumbotron' style='width:70%%; margin: auto;padding-top: 16px;padding-bottom: 16px;' align='center'><h4 style='text-align:left;'><font face='lato'>Stopped at Exit of Connect System Call</font></h4>");
                write(*fd_client,buffer,strlen(buffer));
            }
            else{
                sprintf(buffer,"<div class='jumbotron' style='width:70%%; margin: auto;padding-top: 16px;padding-bottom: 16px;' align='center'><h4 style='text-align:left;'><font face='lato'>Stopped at Entry of Connect System Call</font></h4>");
                write(*fd_client,buffer,strlen(buffer));
            }
            sprintf(buffer,"<h5 style='margin-bottom: 0px; text-align:left;'>This system call initiates a connection on a socket.<span style='float:right;'> int connect(%llu,sin_addr=\"%s\"-sin_port=%d, %llu)</h5></div>",sList.array[i].regs->rdi,inet_ntoa(connectStruct->sin_addr),htons(connectStruct->sin_port),sList.array[i].regs->rdx);
            write(*fd_client,buffer,strlen(buffer));
            /*
            sprintf(buffer,"<h5 style='margin-bottom: 0px; text-align:left;'>This system call initiates a connection on a socket.<span style='float:right;'> int connect(int sockfd, const struct sockaddr *addr,socklen_t addrlen)</h5></div>");
            write(*fd_client,buffer,strlen(buffer)); */
        }
        else{
            sprintf(buffer,"<tr><td>Connect System Call</td>");
            write(*fd_client,buffer,strlen(buffer));
        }
    }
    else if(sList.array[i].regs->orig_eax == SYS_accept){
        if(i==sList.length-1){
            struct sockaddr_in* acceptStruct = (struct sockaddr_in*) sList.array[i].data;
            if(sList.array[i].entry_exit_flag == 1){
                sprintf(buffer,"<div class='jumbotron' style='width:70%%; margin: auto;padding-top: 16px;padding-bottom: 16px;' align='center'><h4 style='text-align:left;'><font face='lato'>Stopped at Exit of Accept System Call</font></h4>");
                write(*fd_client,buffer,strlen(buffer));
            }
            else{
                sprintf(buffer,"<div class='jumbotron' style='width:70%%; margin: auto;padding-top: 16px;padding-bottom: 16px;' align='center'><h4 style='text-align:left;'><font face='lato'>Stopped at Entry of Accept System Call</font></h4>");
                write(*fd_client,buffer,strlen(buffer));
            }
            sprintf(buffer,"<h5 style='margin-bottom: 0px; text-align:left;'>This system call accepts a connection on a socket.<span style='float:right;'> int accept(%llu,sin_addr=\"%s\"-sin_port=%d, %llu)</h5></div>",sList.array[i].regs->rdi,inet_ntoa(acceptStruct->sin_addr),htons(acceptStruct->sin_port),sList.array[i].regs->rdx);
            write(*fd_client,buffer,strlen(buffer));
            /*
            sprintf(buffer,"<h5 style='margin-bottom: 0px; text-align:left;'>This system call accepts a connection on a socket.<span style='float:right;'> int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)</h5></div>");
            write(*fd_client,buffer,strlen(buffer)); */
        }
        else{
            sprintf(buffer,"<tr><td>Accept System Call</td>");
            write(*fd_client,buffer,strlen(buffer));
        }
    }
    else if(sList.array[i].regs->orig_eax == SYS_recvfrom){
        if(i==sList.length-1){
            if(sList.array[i].entry_exit_flag == 1){
                sprintf(buffer,"<div class='jumbotron' style='width:70%%; margin: auto;padding-top: 16px;padding-bottom: 16px;' align='center'><h4 style='text-align:left;'><font face='lato'>Stopped at Exit of Recvfrom System Call</font></h4>");
                write(*fd_client,buffer,strlen(buffer));
            }
            else{
                sprintf(buffer,"<div class='jumbotron' style='width:70%%; margin: auto;padding-top: 16px;padding-bottom: 16px;' align='center'><h4 style='text-align:left;'><font face='lato'>Stopped at Entry of Recvfrom System Call</font></h4>");
                write(*fd_client,buffer,strlen(buffer));
            }
            sprintf(buffer,"<h5 style='margin-bottom: 0px; text-align:left;'>This system call receives a message from a socket.<span style='float:right;'> ssize_t recvfrom(%llu,",sList.array[i].regs->rdi);
            write(*fd_client,buffer,strlen(buffer));
            if(strlen(sList.array[i].data) > 8){
                sprintf(buffer,"\"%.8s...\",%llu,%llu,%llu,%llu)</h5></div>",sList.array[i].data,sList.array[i].regs->rdx,sList.array[i].regs->rcx,sList.array[i].regs->r8,sList.array[i].regs->r9);
                write(*fd_client,buffer,strlen(buffer));
            }
            else{
                sprintf(buffer,"\"%s\",%llu,%llu,%llu,%llu)</h5></div>",sList.array[i].data,sList.array[i].regs->rdx,sList.array[i].regs->rcx,sList.array[i].regs->r8,sList.array[i].regs->r9);
                write(*fd_client,buffer,strlen(buffer));
            }
            /*sprintf(buffer,"<h5 style='margin-bottom: 0px; text-align:left;'>This system call receives a message from a socket.<span style='float:right;'> ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,struct sockaddr *src_addr, socklen_t *addrlen)</h5></div>");
            write(*fd_client,buffer,strlen(buffer));*/
        }
        else{
            sprintf(buffer,"<tr><td>RecvFrom System Call</td>");
            write(*fd_client,buffer,strlen(buffer));
        }
    }
    else if(sList.array[i].regs->orig_eax == SYS_read){
        if(i==sList.length-1){
            if(sList.array[i].entry_exit_flag == 1){
                sprintf(buffer,"<div class='jumbotron' style='width:70%%; margin: auto;padding-top: 16px;padding-bottom: 16px;' align='center'><h4 style='text-align:left;'><font face='lato'>Stopped at Exit of Read System Call</font></h4>");
                write(*fd_client,buffer,strlen(buffer));
            }
            else{
                sprintf(buffer,"<div class='jumbotron' style='width:70%%; margin: auto;padding-top: 16px;padding-bottom: 16px;' align='center'><h4 style='text-align:left;'><font face='lato'>Stopped at Entry of Read System Call</font></h4>");
                write(*fd_client,buffer,strlen(buffer));
            }
            sprintf(buffer,"<h5 style='margin-bottom: 0px; text-align:left;'>This system call reads from a file descriptor.<span style='float:right;'> ssize_t read(%llu,",sList.array[i].regs->rdi);
            write(*fd_client,buffer,strlen(buffer));
            if(sList.array[i].length > 8){
                sprintf(buffer,"\"%.8s...\",%llu)</h5></div>",sList.array[i].data,sList.array[i].regs->rdx);
                write(*fd_client,buffer,strlen(buffer));
            }
            else{
                sprintf(buffer,"\"%s\",%llu)</h5></div>",sList.array[i].data,sList.array[i].regs->rdx);
                write(*fd_client,buffer,strlen(buffer));
            }
            /*sprintf(buffer,"<h5 style='margin-bottom: 0px; text-align:left;'>This system call reads from a file descriptor.<span style='float:right;'> ssize_t read(int fd, void *buf, size_t count)</h5></div>");
            write(*fd_client,buffer,strlen(buffer)); */
        }
        else{
            sprintf(buffer,"<tr><td>Read System Call</td>");
            write(*fd_client,buffer,strlen(buffer));
        }
    }
    else if(sList.array[i].regs->orig_eax == SYS_openat){
        if(i==sList.length-1){
            if(sList.array[i].entry_exit_flag == 1){
                sprintf(buffer,"<div class='jumbotron' style='width:70%%; margin: auto;padding-top: 16px;padding-bottom: 16px;' align='center'><h4 style='text-align:left;'><font face='lato'>Stopped at Exit of Openat System Call</font></h4>");
                write(*fd_client,buffer,strlen(buffer));
            }
            else{
                sprintf(buffer,"<div class='jumbotron' style='width:70%%; margin: auto;padding-top: 16px;padding-bottom: 16px;' align='center'><h4 style='text-align:left;'><font face='lato'>Stopped at Entry of Openat System Call</font></h4>");
                write(*fd_client,buffer,strlen(buffer));
            }
            sprintf(buffer,"<h5 style='margin-bottom: 0px; text-align:left;'>This system call opens a file relative to a directory file descriptor.<span style='float:right;'> int openat(%llu,",sList.array[i].regs->rdi);
            write(*fd_client,buffer,strlen(buffer));
            if(strlen(sList.array[i].data) > 16){
                sprintf(buffer,"\"%.16s...\",%llu,%llu)</h5></div>",sList.array[i].data,sList.array[i].regs->rdx,sList.array[i].regs->rcx);
                write(*fd_client,buffer,strlen(buffer));
            }
            else{
                sprintf(buffer,"\"%s\",%llu,%llu)</h5></div>",sList.array[i].data,sList.array[i].regs->rdx,sList.array[i].regs->rcx);
                write(*fd_client,buffer,strlen(buffer));
            }
            /*sprintf(buffer,"<h5 style='margin-bottom: 0px; text-align:left;'>This system call opens a file relative to a directory file descriptor.<span style='float:right;'>int openat(int dirfd, const char *pathname, int flags, mode_t mode)</h5></div>");
            write(*fd_client,buffer,strlen(buffer));*/
        }
        else{
            sprintf(buffer,"<tr><td>OpenAt System Call</td>");
            write(*fd_client,buffer,strlen(buffer));
        }
    }
    else if(sList.array[i].regs->orig_eax == SYS_close){
        if(i==sList.length-1){
            if(sList.array[i].entry_exit_flag == 1){
                sprintf(buffer,"<div class='jumbotron' style='width:70%%; margin: auto;padding-top: 16px;padding-bottom: 16px;' align='center'><h4 style='text-align:left;'><font face='lato'>Stopped at Exit of Close System Call</font></h4>");
                write(*fd_client,buffer,strlen(buffer));
            }
            else{
                sprintf(buffer,"<div class='jumbotron' style='width:70%%; margin: auto;padding-top: 16px;padding-bottom: 16px;' align='center'><h4 style='text-align:left;'><font face='lato'>Stopped at Entry of Close System Call</font></h4>");
                write(*fd_client,buffer,strlen(buffer));
            }
            sprintf(buffer,"<h5 style='margin-bottom: 0px; text-align:left;'>This system call closes a file descriptor.<span style='float:right;'>int close(%llu)</h5></div>",sList.array[i].regs->rdi);
            write(*fd_client,buffer,strlen(buffer));
        }
        else{
            sprintf(buffer,"<tr><td>Close System Call</td>");
            write(*fd_client,buffer,strlen(buffer));
        }
    }
}

void sendSyscallDataFromIndex(int* fd_client,int i){
    if(i==sList.length-1){
        switch(sList.array[i].regs->orig_eax){
            case SYS_connect:
                sys_connectDataWithModifySender(fd_client,i);
                break;
            case SYS_openat:
                sys_openatDataWithModifySender(fd_client,i);
                break;
            case SYS_close:
                sys_closeDataWithModifySender(fd_client,i);
                break;
            case SYS_write:
                sys_writeDataWithModifySender(fd_client,i);
                break;
            case SYS_sendto:
                sys_sendtoDataWithModifySender(fd_client,i);
                break;
            case SYS_recvfrom:
                sys_recvfromDataWithModifySender(fd_client,i);
                break;
            case SYS_read:
                sys_readDataWithModifySender(fd_client,i);
                break;
            case SYS_accept:
                sys_acceptDataWithModifySender(fd_client,i);
                break;
        }
    }
    else{
        switch(sList.array[i].regs->orig_eax){
            case SYS_connect:
                sys_connectDataSender(fd_client,i);
                break;
            case SYS_openat:
                sys_openatDataSender(fd_client,i);
                break;
            case SYS_close:
                sys_closeDataSender(fd_client,i);
                break;
            case SYS_write:
                sys_writeDataSender(fd_client,i);
                break;
            case SYS_sendto:
                sys_sendtoDataSender(fd_client,i);
                break;
            case SYS_recvfrom:
                sys_recvfromDataSender(fd_client,i);
                break;
            case SYS_read:
                sys_readDataSender(fd_client,i);
                break;
            case SYS_accept:
                sys_acceptDataSender(fd_client,i);
                break;
        }
    }
}

void sendAllSysCalls(int* fd_client){
    char buffer[5012];
    write(*fd_client,responseHeader,strlen(responseHeader));
    write(*fd_client,htmlStart,strlen(htmlStart));
    sendSyscallNameFromIndex(fd_client,sList.length-1);
    //sys_callEntryExitSender(fd_client,sList.length-1);
    sendRegistersFromIndex(fd_client,sList.length-1);
    sendSyscallDataFromIndex(fd_client,sList.length-1);
    write(*fd_client,"<h1> Latest System Calls </h1>",30);
    write(*fd_client,"<table id='customers' style='width:100%;'>",62);
    sprintf(buffer,"<tbody><tr><th style='background-color:#4CAF50;'>System Call Name</th><th style='background-color:#4CAF50;'>System Call Type</th><th style='background-color:#4CAF50;'>RAX</th><th style='background-color:#4CAF50;'>RDI</th><th style='background-color:#4CAF50;'>RSI</th><th style='background-color:#4CAF50;'>RDX</th><th style='background-color:#4CAF50;'>RCX</th><th style='background-color:#4CAF50;'>R8</th><th style='background-color:#4CAF50;'>R9</th></tr>");
    write(*fd_client,buffer,strlen(buffer));
    for(int i=sList.length-2;i>=0;i--){
        sendSyscallNameFromIndex(fd_client,i);
        sys_callEntryExitSender(fd_client,i);
        sendRegistersFromIndex(fd_client,i);
        //sendSyscallDataFromIndex(fd_client,i); -> TO DO: LATEST SYSTEM CALL DATA
    }
    write(*fd_client,"</tbody></table>",16);
    write(*fd_client,htmlEnd,strlen(htmlEnd));
}

void sendProcessListTable(int* fd_client){
    char buffer[5012];
    write(*fd_client,tableStart,strlen(tableStart));
    for(int i=0;i<pList.length;i++){
        write(*fd_client,"<tr>\n",5);
        sprintf(buffer,"<td> %s </td> \n",pList.array[i].name);
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<td> %s </td> \n",pList.array[i].pid);
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<td> %s </td> \n",pList.array[i].ppid);
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<td> %s </td> \n",pList.array[i].user);
        write(*fd_client,buffer,strlen(buffer));
        if(pList.array[i].cmdline != NULL){
            sprintf(buffer,"<td> %s </td> \n",pList.array[i].cmdline);
            write(*fd_client,buffer,strlen(buffer));
        }
        else{
            write(*fd_client,"<td> </td>\n",10);
        }
        sprintf(buffer,"<td align='center'> <input type=\"radio\" name=\"pid\" value=\"%s\"> </td>",pList.array[i].pid);
        write(*fd_client,buffer,strlen(buffer));
        write(*fd_client,"</tr>\n",6);
    }
    write(*fd_client,tableEnd,strlen(tableEnd));
    write(*fd_client,htmlEnd,strlen(htmlEnd));
}

void* requestHandler(void *ptr){
    int *fd_client = (int *)ptr;
    char requestBuffer[2048]; //content sent by browser
    int fdimg; //for favicon
    char buffer[5012];
    struct timespec ts;
    ts.tv_sec=0;
    ts.tv_nsec=10000000;
    memset(requestBuffer,0,2048);
    read(*fd_client, requestBuffer, 2047);
    if(!strstr(requestBuffer,"favicon")){
        printf("%s\n",requestBuffer);

    }
    if(!strncmp(requestBuffer, "GET /favicon.ico",16)){
        //not yet completed...
        ;
    }
    else if(!strncmp(requestBuffer,"POST /",6)){
        if(strstr(requestBuffer,"pid=")){
            startPtraceFromPID(fd_client,requestBuffer);
        }
        else if(strstr(requestBuffer, "getPathInfo=1")){
            sendProcessInformationPath(fd_client);
        }
        else if(strstr(requestBuffer, "path=")){
            startPtraceFromPath(fd_client,requestBuffer);
        }
        else if(strstr(requestBuffer, "getFilterInfo=1")){
            sendFilterInformation(fd_client);
        }
        else if(strstr(requestBuffer, "processInfoFromPid=1")){
            sendProcessInformationPID(fd_client);
        }
        else if(strstr(requestBuffer, "attach=")){
            while(1){
                nanosleep(&ts, NULL);
                if(sList.length){
                    break;
                }
                if(isStartedPtrace == 0){
                    //Means it finished before catch
                    write(*fd_client,responseHeader,strlen(responseHeader));
                    write(*fd_client,htmlStart,strlen(htmlStart));
                    write(*fd_client,finishWithoutCatchResponse,strlen(finishWithoutCatchResponse));
                    write(*fd_client,htmlEnd,strlen(htmlEnd));
                    close(*fd_client);
                    returnForRequestHandler = 0;
                    pthread_exit(&returnForRequestHandler);
                }
            }
            sendAllSysCalls(fd_client);
        }
        else if(strstr(requestBuffer, "detach=1")){
            //Detach Button
            detachFromButton();
            //send main
            processListStateFlag = 1;
            while(1){
                if(processListStateFlag == 0){
                    break;
                }
                nanosleep(&ts, NULL);
            }
            HTMLPageSender(fd_client,"mainPage.html");
        }
        else if(strstr(requestBuffer, "xml=1")){ // next butonu
            if(strstr(requestBuffer, "modify=1")){
                if(strstr(requestBuffer,"value=")){
                    char* startOfModifiedValue = strstr(requestBuffer,"value=")+6;
                    modifiedValue = malloc(sizeof(char)*strlen(startOfModifiedValue));
                    if(decode(startOfModifiedValue,modifiedValue) > 0){
                        modify=1;
                    }
                    else{
                        free(modifiedValue);
                        modifiedValue = NULL;
                    }
                }
                else if(strstr(requestBuffer,"ip=") && strstr(requestBuffer,"port=")){
                    ipModifyValueTaker(requestBuffer); //ip handler yapılacak
                    char* startOfPortValue = strstr(requestBuffer,"port=")+5;
                    port = atoi(startOfPortValue);
                    if(port > 0 && ipaddr){
                        modify=1;
                    }
                }
            }
            int value = sList.length;
            flagForNext = 1;
            while(1){
                nanosleep(&ts, NULL);
                if(sList.length == 0){ //Means no system call remains
                    close(*fd_client);
                    returnForRequestHandler = 0;
                    pthread_exit(&returnForRequestHandler);
                }
                if(sList.length>value){
                    break; //indicates modify is completed.
                }
            }
            sendAllSysCalls(fd_client);
        }
        else if(strstr(requestBuffer,"xml=2")){
            processListStateFlag = 1;
            while(1){
                if(processListStateFlag == 0){
                    break;
                }
            }
            write(*fd_client,responseHeader,strlen(responseHeader));
            write(*fd_client,htmlStart,strlen(htmlStart));
            sendProcessListTable(fd_client);
        }
        else if(strstr(requestBuffer, "operation=")){
            char *c = strstr(requestBuffer,"operation=")+10;
            int key = *c - '0';
            switch (key) {
                case 0: //exit part
                write(*fd_client,"GOODBYE MY MASTER",17);
                close(*fd_client);
                returnForRequestHandler = 1;
                processListStateFlag = 2;
                pthread_exit(&returnForRequestHandler);
                break;
            }
        }
        else{
            //TODO USER MADE UNKNOWN POST REQUEST
        }
    }
    else{
        processListStateFlag = 1;
        while(1){
            if(processListStateFlag == 0){
                break;
            }
            nanosleep(&ts, NULL);
        }
        if(isStartedPtrace){
            detachFromButton();
        }
        HTMLPageSender(fd_client,"mainPage.html");
    }
    close(*fd_client);
    returnForRequestHandler = 0;
    pthread_exit(&returnForRequestHandler);
}
