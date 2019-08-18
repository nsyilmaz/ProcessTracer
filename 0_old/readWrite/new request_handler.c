#include "util.h"
#include "request_handler.h"
#include "process_list.h"
#include "ptrace.h"
#include "defs.h"
// AJAX CALL
void* requestHandler(void *ptr){
        int *fd_client = (int *)ptr;
        char buf[2048]; //content sent by browser
        int fdimg; //for favicon
        char buffer[5012];
        memset(buf,0,2048);
        read(*fd_client, buf, 2047);
        printf("%s\n",buf);
        if(!strncmp(buf, "GET /favicon.ico",16)){
          fdimg = open("secrove.ico", O_RDONLY);
          sendfile(*fd_client,fdimg,NULL,372000); // size, favicon size
          close(fdimg);
        }
        else if(!strncmp(buf,"POST /",6)){
          // xml http request header ayrımı ajax request geldi mi geldiyse orada thread create edilecek
	         if(strstr(buf,"pid=")){
	            if(isStartedPtrace == 0){
              char *c = strstr(buf,"pid=") + 4;
              char *pid = malloc(sizeof(char));
              int i=0;
              struct process* chosenProcess = NULL;
              while(*c != EOF && *c != '\n'){
                pid[i++] = *c++;
                pid = realloc(pid,sizeof(char)*(i+1));
              }
              pid[i] = '\0';
              chosenProcess = searchByPID(pid);
              if(chosenProcess == NULL){
                perror("WRONG PID");
              }
              else{
                write(*fd_client,responseHeader,strlen(responseHeader));
                sprintf(buffer,"<p> Name of Process: %s </p>\n",chosenProcess->name);
                write(*fd_client,buffer,strlen(buffer));
                sprintf(buffer,"<p>Process Id: %s </p>\n",chosenProcess->pid);
                write(*fd_client,buffer,strlen(buffer));
                sprintf(buffer,"<p>Parent' Process Id: %s </p>\n",chosenProcess->ppid);
                write(*fd_client,buffer,strlen(buffer));
                sprintf(buffer,"<p>Process Owner: %s </p>\n",chosenProcess->user);
                write(*fd_client,buffer,strlen(buffer));
                if(strlen(chosenProcess->cmdline) == 0){
                  sprintf(buffer,"<p>CommandLineArguments: EMPTY </p>\n");
                }
                else{
                  sprintf(buffer,"<p>CommandLineArguments: %s </p>\n",chosenProcess->cmdline);
                }
                write(*fd_client,buffer,strlen(buffer));
                write(*fd_client,responseEnd,strlen(responseEnd));
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
        else if(strstr(buf, "path=")){
	          if(isStartedPtrace == 0){
           	   char *c = strstr(buf,"path=")+5;
          	   char *path = malloc(sizeof(char)*strlen(c));
               if(decode(c, path) > 0){
                 // response + yeni thread oluşumu path için process çalıştırılacak
		                isStartedPtrace = 1;
                    write(*fd_client,responseHeader,strlen(responseHeader));
                    sprintf(buffer,"<p>Given Path: %s </p>\n",path);
                    write(*fd_client,buffer,strlen(buffer));
                    write(*fd_client,responseEnd,strlen(responseEnd));
                    int err = pthread_create(&threadFork,NULL,ptraceFork,path);
                    flagForNext = 0;
                    if(err != 0){
                        perror("Running Process Tracer By PID Error:");
                        exit(0);
                    }
              }
	          }
        }
        else if(strstr(buf, "xml=1")){ // next butonu
                for(int i=0;i<sList.length;i++){
                  if(sList.array[i].regs->orig_eax == SYS_write){
                    sprintf(buffer,"<p>SYS_WRITE</p>");
                    write(*fd_client,buffer,strlen(buffer));
                  }
                  else if(sList.array[i].regs->orig_eax == SYS_read){
                    sprintf(buffer,"<p>SYS_READ</p>");
                    write(*fd_client,buffer,strlen(buffer));
                  }
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
                  if(sList.array[i].data){
                    sprintf(buffer,"<p> Data: %s </p>",sList.array[i].data);
                    write(*fd_client,buffer,strlen(buffer));
                  }
                  if(sList.array[i].entry_exit_flag == 1){
                      sprintf(buffer,"<p> System call exit</p>");
                      write(*fd_client,buffer,strlen(buffer));
                  }
                  else if(sList.array[i].entry_exit_flag == 0){
                      sprintf(buffer,"<p> System call entry </p>");
                      write(*fd_client,buffer,strlen(buffer));
                  }
                }
                flagForNext = 1;
        }
        else if(strstr(buf,"xml=2")){
            processListStateFlag = 1;
            while(1){
              if(processListStateFlag == 0){
                break;
              }
            }
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
        }
        else if(strstr(buf, "operation=")){
            char *c = strstr(buf,"operation=")+10;
            int key = *c - '0';
            switch (key) {
              case 0:
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
            }
            write(*fd_client,responseBuffer,strlen(responseBuffer));
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
            write(*fd_client,end,strlen(end));
  			}
        close(*fd_client);
        returnForRequestHandler = 0;
        pthread_exit(&returnForRequestHandler);
}
