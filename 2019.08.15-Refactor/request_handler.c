#include "util.h"
#include "request_handler.h"
#include "process_list.h"
#include "ptrace.h"
#include "defs.h"
#include <sys/socket.h>
#include "sys_read_modify.h"


void sendProcessInformationPID(int* fd_client,struct process* chosenProcess){
  char buffer[5012];
  write(*fd_client,responseHeader,strlen(responseHeader));
  write(*fd_client,htmlStart,strlen(htmlStart));
  sprintf(buffer,"<p>Name of Process: %s </p>\n",chosenProcess->name);
  write(*fd_client,buffer,strlen(buffer));
  sprintf(buffer,"<p>Process Id: %s </p>\n",chosenProcess->pid);
  write(*fd_client,buffer,strlen(buffer));
  sprintf(buffer,"<p>Parent' Process Id: %s </p>\n",chosenProcess->ppid);
  write(*fd_client,buffer,strlen(buffer));
  sprintf(buffer,"<p>Process Owner: %s </p>\n",chosenProcess->user);
  write(*fd_client,buffer,strlen(buffer));
  if(strlen(chosenProcess->cmdline) == 0){
    sprintf(buffer,"<p>CommandLineArguments: </p>\n");
  }
  else{
    sprintf(buffer,"<p>CommandLineArguments: %s </p>\n",chosenProcess->cmdline);
  }
  write(*fd_client,buffer,strlen(buffer));
  sprintf(buffer,"<button onclick = 'nextSyscall()'> Next </button>\n");
  write(*fd_client,buffer,strlen(buffer));
  write(*fd_client,xmlSysCallScript,strlen(xmlSysCallScript));
  write(*fd_client,xmlFirstSysCallScript,strlen(xmlFirstSysCallScript));
  write(*fd_client,xmlSysCallModifyScript,strlen(xmlSysCallModifyScript));
  write(*fd_client,htmlEnd,strlen(htmlEnd));
}


void startPtraceFromPID(int* fd_client,char* request){
  if(isStartedPtrace == 0){
    char *starterOfStringPID = strstr(request,"pid=") + 4;
    char *pid = malloc(sizeof(char));
    int i=0;
    struct process* chosenProcess = NULL;
    while(*starterOfStringPID != EOF && *starterOfStringPID != '\n'){
      pid[i++] = *starterOfStringPID++;
      pid = realloc(pid,sizeof(char)*(i+1));
    }
    pid[i] = '\0';
    chosenProcess = searchByPID(pid);
    if(chosenProcess == NULL){
      perror("WRONG PID");
    }
    else{
      sendProcessInformationPID(fd_client,chosenProcess);
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

void sendProcessInformationPath(int* fd_client,char* path){
  char buffer[5012];
  write(*fd_client,responseHeader,strlen(responseHeader));
  write(*fd_client,htmlStart,strlen(htmlStart));
  sprintf(buffer,"<p>Given Path: %s </p>\n",path);
  write(*fd_client,buffer,strlen(buffer));
  sprintf(buffer,"<button onclick = 'nextSyscall()'> Next </button>\n");
  write(*fd_client,buffer,strlen(buffer));
  write(*fd_client,xmlSysCallScript,strlen(xmlSysCallScript));
  write(*fd_client,xmlFirstSysCallScript,strlen(xmlFirstSysCallScript));
  write(*fd_client,xmlSysCallModifyScript,strlen(xmlSysCallModifyScript));
  write(*fd_client,htmlEnd,strlen(htmlEnd));
}


void startPtraceFromPath(int* fd_client,char* request){
  if(isStartedPtrace == 0){
    char *starterOfStringPath = strstr(request,"path=")+5;
    char *path = malloc(sizeof(char)*strlen(starterOfStringPath));
    if(decode(starterOfStringPath, path) > 0){
      sendProcessInformationPath(fd_client,path);
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

void sendRegistersFromIndex(int *fd_client,int i){
  char buffer[5012];
  sprintf(buffer,"<p> register rdx: %lld </p>",sList.array[i].regs->rdx);
  write(*fd_client,buffer,strlen(buffer));
  sprintf(buffer,"<p> register rax: %lld </p>",sList.array[i].regs->rax);
  write(*fd_client,buffer,strlen(buffer));
  sprintf(buffer,"<p> register rdi: %lld </p>",sList.array[i].regs->rdi);
  write(*fd_client,buffer,strlen(buffer));
  sprintf(buffer,"<p> register rbx: %lld </p>",sList.array[i].regs->rbx);
  write(*fd_client,buffer,strlen(buffer));
  sprintf(buffer,"<p> register rcx: %lld </p>",sList.array[i].regs->rcx);
  write(*fd_client,buffer,strlen(buffer));
  sprintf(buffer,"<p> register rsi: %lld </p>",sList.array[i].regs->rsi);
  write(*fd_client,buffer,strlen(buffer));
}

void sendSyscallNameFromIndex(int *fd_client,int i){
  char buffer[5012];
  if(sList.array[i].regs->orig_eax == SYS_write){
    sprintf(buffer,"<p>SYS_WRITE</p>");
    write(*fd_client,buffer,strlen(buffer));
  }
  else if(sList.array[i].regs->orig_eax == SYS_sendto){
    sprintf(buffer,"<p>SYS_SENDTO</p>");
    write(*fd_client,buffer,strlen(buffer));
  }
  else if(sList.array[i].regs->orig_eax == SYS_connect){
    sprintf(buffer,"<p>SYS_CONNECT</p>");
    write(*fd_client,buffer,strlen(buffer));
  }
  else if(sList.array[i].regs->orig_eax == SYS_accept4){
    sprintf(buffer,"<p>SYS_ACCEPT</p>");
    write(*fd_client,buffer,strlen(buffer));
  }
  else if(sList.array[i].regs->orig_eax == SYS_recvfrom){
    sprintf(buffer,"<p>SYS_RECVFROM</p>");
    write(*fd_client,buffer,strlen(buffer));
  }
  else if(sList.array[i].regs->orig_eax == SYS_read){
    sprintf(buffer,"<p>SYS_READ</p>");
    write(*fd_client,buffer,strlen(buffer));
  }
  else if(sList.array[i].regs->orig_eax == SYS_openat){
    sprintf(buffer,"<p>SYS_OPENAT</p>");
    write(*fd_client,buffer,strlen(buffer));
  }
  else if(sList.array[i].regs->orig_eax == SYS_close){
    sprintf(buffer,"<p>SYS_CLOSE</p>");
    write(*fd_client,buffer,strlen(buffer));
    sprintf(buffer,"<p>File Descriptor: %lld",sList.array[i].regs->rdi);
    write(*fd_client,buffer,strlen(buffer));
  }
}

void sendSyscallDataFromIndex(int* fd_client,int i){
  char buffer[5012];
    if(sList.array[i].regs->orig_eax == SYS_connect){
      struct sockaddr_in* connectStruct = (struct sockaddr_in*) sList.array[i].data;
      sprintf(buffer,"<p> Ip adress: %s </p>",inet_ntoa(connectStruct->sin_addr));
      write(*fd_client,buffer,strlen(buffer));
      sprintf(buffer,"<p> Port: %d </p>",htons(connectStruct->sin_port));
      write(*fd_client,buffer,strlen(buffer));
    }
    else if(sList.array[i].regs->orig_eax == SYS_accept4){
      struct sockaddr_in* connectStruct = (struct sockaddr_in*) sList.array[i].data;
      sprintf(buffer,"<p> Ip adress: %s </p>",inet_ntoa(connectStruct->sin_addr));
      write(*fd_client,buffer,strlen(buffer));
      sprintf(buffer,"<p> Port: %d </p>",htons(connectStruct->sin_port));
      write(*fd_client,buffer,strlen(buffer));
    }
    else if(sList.array[i].regs->orig_eax == SYS_read && i==sList.length-1){
      if(sList.array[i].entry_exit_flag == 1){
          sprintf(buffer, "<table border=1><tr>");
          write(*fd_client,buffer,strlen(buffer));
          sprintf(buffer,"<td><p> Data: %s </p><button onclick = 'nextSyscall()'> Next </button></td>",sList.array[i].data);
          write(*fd_client,buffer,strlen(buffer));
          sprintf(buffer,"<td><p><textarea rows=\"4\" cols=\"50\"  id = 'modifiedValue'>%s</textarea><br><button onclick = 'modifySyscall()'> Modify & Continue </button></p>",sList.array[i].data);
          write(*fd_client,buffer,strlen(buffer));
          sprintf(buffer, "</td>");
          write(*fd_client,buffer,strlen(buffer));
          sprintf(buffer, "</tr></table>");
          write(*fd_client,buffer,strlen(buffer));
          sprintf(buffer,"<p> System call exit</p>");
          write(*fd_client,buffer,strlen(buffer));
      }
      else if(sList.array[i].entry_exit_flag == 0){
        sprintf(buffer, "<table border=1><tr>");
        write(*fd_client,buffer,strlen(buffer));
        if(sList.array[i].data){
        sprintf(buffer,"<td><p> Data: %s </p><button onclick = 'nextSyscall()'> Next </button></td>",sList.array[i].data);
        }
        else{
          sprintf(buffer,"<td><p> Data: </p><button onclick = 'nextSyscall()'> Next </button></td>");
        }
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<td><p>In SYS_READ, on the entry of system call, you can't manipulate the data.</p>");
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer, "</td>");
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer, "</tr></table>");
        write(*fd_client,buffer,strlen(buffer));
        sprintf(buffer,"<p> System call entry</p>");
        write(*fd_client,buffer,strlen(buffer));
      }
    }
    else{
      if(sList.array[i].data){
        sprintf(buffer,"<p> Data: %s </p>",sList.array[i].data);
      }
      else{
        sprintf(buffer,"<p> Data: </p>");
      }
      write(*fd_client,buffer,strlen(buffer));
      if(sList.array[i].entry_exit_flag == 1){
          sprintf(buffer,"<p> System call exit</p>");
          write(*fd_client,buffer,strlen(buffer));
      }
      else if(sList.array[i].entry_exit_flag == 0){
          sprintf(buffer,"<p> System call entry </p>");
          write(*fd_client,buffer,strlen(buffer));
      }
    }
}

void sendAllSysCalls(int* fd_client){
  char buffer[5012];
  write(*fd_client,responseHeader,strlen(responseHeader));
  write(*fd_client,htmlStart,strlen(htmlStart));
  for(int i=sList.length-1;i>=0;i--){
    sendSyscallNameFromIndex(fd_client,i);
    sendRegistersFromIndex(fd_client,i);
    sendSyscallDataFromIndex(fd_client,i);
  }
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
  sprintf(buffer,"<td> <input type=\"radio\" name=\"pid\" value=\"%s\"> </td>",pList.array[i].pid);
  write(*fd_client,buffer,strlen(buffer));
  write(*fd_client,"</tr>\n",6);
  }
  write(*fd_client,tableEnd,strlen(tableEnd));
  write(*fd_client,xmlProcessListScript,strlen(xmlProcessListScript));
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
        printf("%s\n",requestBuffer);
        if(!strncmp(requestBuffer, "GET /favicon.ico",16)){
              //  write(*fd_client,responseHeader,strlen(responseHeader));
              //  write(*fd_client," ",1);
              //not yet completed...
        }
        else if(!strncmp(requestBuffer,"POST /",6)){
	         if(strstr(requestBuffer,"pid=")){
	            startPtraceFromPID(fd_client,requestBuffer);
	         }
           else if(strstr(requestBuffer, "path=")){
           	  startPtraceFromPath(fd_client,requestBuffer);
           }
        else if(strstr(requestBuffer, "attach=")){
          while(1){
              nanosleep(&ts, NULL);
              if(sList.length){
                break;
              }
          }
          sendAllSysCalls(fd_client);
        }
        else if(strstr(requestBuffer, "xml=1")){ // next butonu
            if(strstr(requestBuffer, "modify=1")){
              char* startOfModifiedValue = strstr(requestBuffer,"value=")+6;
              modifiedValue = malloc(sizeof(char)*strlen(startOfModifiedValue));
              if(decode(startOfModifiedValue,modifiedValue) > 0){
                    modify=1;
                  }
              }
              int value = sList.length;
              flagForNext = 1;
              while(1){
                  nanosleep(&ts, NULL);
                  if(sList.length == 0){
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
        }
        else{
            processListStateFlag = 1;
            while(1){
                if(processListStateFlag == 0){
                  break;
                }
                nanosleep(&ts, NULL);
            }
            write(*fd_client,responseHeader,strlen(responseHeader));
            write(*fd_client,htmlStartWithCSS,strlen(htmlStartWithCSS));
            write(*fd_client,mainPanelHTML,strlen(mainPanelHTML));
            sendProcessListTable(fd_client);
  			}
        close(*fd_client);
        returnForRequestHandler = 0;
        pthread_exit(&returnForRequestHandler);
}
