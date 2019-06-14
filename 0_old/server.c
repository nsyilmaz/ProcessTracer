#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sendfile.h>

char webpage[] = //response
"HTTP/1.1 200 OK\r\n"
"Content-Type: text/html; charset=UTF-8\r\n\r\n"
"<!DOCTYPE html>\r\n"
"<html><head><title>Deneme</title>\r\n"
"<style>body { background-color: #FFF000 }</style></head>\r\n"
"<body><center><h1>Neydiin ağam</h1>\r\n"
"<img src=\"test.jpg\"></center></body></html>\r\n";
char responseBuffer[] =  "HTTP/1.1 200 OK\r\n"
"Content-Type: text/html; charset=UTF-8\r\n\r\n";
int main(int argc, char* argv[])
{
	struct sockaddr_in server_addr, client_addr;
	socklen_t sin_len = sizeof(client_addr);
	int fd_server,fd_client; //return value from socket
	char buf[2048]; //content sent by browser
	int fdimg; //for favicon
	int on=1;

	fd_server = socket(AF_INET,SOCK_STREAM,0); // create socket
	if(fd_server < 0){
		printf("Error");
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
	if(listen(fd_server, 10) == -1){ // 10 means maximum number of pending connections that can be queued up before connections are refused
		perror("listen error");
		close(fd_server);
		exit(1);
	}

	while(1){

		if((fd_client = accept(fd_server, (struct sockaddr *) &client_addr, &sin_len)) < 0){
				//		perror("SIFIR SIKINTIIII \n");
			continue;
		}

		printf("Gel baba gel ... \n");
		if(!fork()){
			//for child
			close(fd_server);
			memset(buf,0,2048);
			read(fd_client, buf, 2047);
			printf("%s\n", buf);

			if(!strncmp(buf, "GET /favicon.ico",16)){
				fdimg = open("secrove.ico", O_RDONLY);
				sendfile(fd_client,fdimg,NULL,372000); // size, favicon size
				close(fdimg);
				exit(0);
			}
			else if(!strncmp(buf, "GET /test.jpg",13)){
				fdimg = open("test.jpg", O_RDONLY);
				printf("Burası mı sıkıntı");
				sendfile(fd_client,fdimg,NULL,14000); //img size
				close(fdimg);
				exit(0);
			}
			else if(!strncmp(buf, "GET /test.html",13)){
				FILE *fp1;
				char line[100];

				char *c;
				fp1 = fopen("test.html","r");
			//	write(fd_client, responseBuffer, sizeof(responseBuffer) -1);
				do {
					c = fgets(line,99,fp1); // bir satir okuyalim

					if (c != NULL){
						unsigned int len = strlen(line);
						line[len] = '\n';
						line[len+1] = '\0';
					//	write(fd_client,line,sizeof(line) -1);
		/*			if(strstr(line,"</html>")){
						char end[] ="</html>\0";
						strcat(responseBuffer,end);
						break;
					} */
					strcat(responseBuffer,line);
				}
	 				} while (c != NULL);
					printf("%s",responseBuffer);
			 		fclose(fp1);
					write(fd_client, responseBuffer, sizeof(webpage) -1);
					close(fdimg);
					exit(0);
			}
			else{
			write(fd_client, webpage, sizeof(webpage) -1);
				close(fd_client);
				printf("TAMAMDIRRR\n");
				exit(0);
			}

		}
		//for parent
		close(fd_client);

	}

	return 0;
}
