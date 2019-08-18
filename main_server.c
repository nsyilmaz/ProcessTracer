#include "util.h"
#include "process_list.h"
#include "request_handler.h"


int main(void){
    pthread_t processListThread;
    int err1 = pthread_create(&processListThread,NULL,addProcessList,NULL);
    if(err1 != 0){
      perror("AddList Error:");
      exit(0);
    }
    int *returnValue;
    struct sockaddr_in server_addr, client_addr;
    socklen_t sin_len = sizeof(client_addr);
    int fd_server,fd_client; //return value from socket
    char buf[2048]; //content sent by browser
    int fdimg; //for favicon
    int on=1;
    int *connfd = malloc(sizeof(int));
    int threadCount = 0;
    pthread_t *httpThreads = malloc(sizeof(pthread_t));
    fd_server = socket(AF_INET,SOCK_STREAM,0); // create socket
    if(fd_server < 0){
      perror("socket error:");
      exit(1);
    }
    setsockopt(fd_server,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(int));
    server_addr.sin_family = AF_INET;	//bind part
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(8081); //initialized
    if(bind(fd_server, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1){
      perror("bind error");
      close(fd_server);
    }
    while(1){
    	if( listen(fd_server, 10) != 0) {
    		perror("Listen Error");
    	}
    	connfd[threadCount] = accept(fd_server,(struct sockaddr *) &client_addr, &sin_len);
    	if (connfd[threadCount] < 0) {
    		perror("Accept Error");
    	}
    	pthread_create(&httpThreads[threadCount], NULL, requestHandler, &connfd[threadCount]);		//create a thread and receive data
    	pthread_join(httpThreads[threadCount], (void**) &returnValue);												//finish the thread;
      if(*returnValue == 1){
        break;
      }
    	threadCount++;
      connfd = realloc(connfd,(threadCount+1)*sizeof(int));
      httpThreads = realloc(httpThreads,(threadCount+1)*sizeof(pthread_t));
    }
    close(fd_server);
    free(connfd);
    free(httpThreads);
    connfd = NULL;
    httpThreads = NULL;
    pthread_join(processListThread,NULL); //Bitmesini bekliyoruz ?
    return 0;
}
