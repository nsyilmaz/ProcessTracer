#include "defs.h"
#include "util.h"
#include "process_list.h"
#include "request_handler.h"

//free the whole process list
void freeList(){
  if(pList.array != NULL){
    for(int i=0;i<pList.length;i++){
      free(pList.array[i].name);
      free(pList.array[i].pid);
      free(pList.array[i].user);
      free(pList.array[i].cmdline);
      free(pList.array[i].ppid);
      pList.array[i].name = NULL;
      pList.array[i].pid = NULL;
      pList.array[i].user = NULL;
      pList.array[i].cmdline = NULL;
      pList.array[i].ppid=NULL;
    }
    free(pList.array);
    pList.array = NULL;
    pList.length = 0;
  }
}

// Generate the process list
void* addList(void* ptr){
  struct timespec ts;
  ts.tv_sec=0;
  ts.tv_nsec=10000000; // 10 milliseconds
  while(1){
    nanosleep(&ts, NULL); // to prevent %100 CPU
    if(processListStateFlag == 0){ //means there is no need to refresh just go idle
      continue;
    }
    else if(processListStateFlag == 2){ //coming from request handler and indicates program ends
      break;
    }
    else{
      freeList(); // first delete all list
      int firstTime = 0;
      struct dirent *de;
      DIR *dr = opendir("/proc"); // Open proc directory and visit all directories
      if(dr == NULL){
        perror("Can't open the dirs");
        exit(0);
      }
      pList.length++; // hold number of processes
      pList.array = malloc(sizeof(struct process)); //here we take a memory region from heap
      while((de = readdir(dr)) != NULL){
            int length = strlen(de->d_name); //read all files/dirs inside the proc one by one
            char buffer[length+1];
            FILE *fp1; //For cmd and status files
            int counterForCmd=0;
            char line[100];
            char ch;
            int flag;
            char *c;
            char *f; // return value from fgets
            char *statusPath ="/proc/"; // It will show the status file
            char *cmdPath = "/proc/"; // It will show the cmdfile
            int flagForCommandLine = 0;
            strncpy(buffer,de->d_name,length);
            buffer[length] = '\0';
            if(checkInt(buffer)){ //We are checking whether it is integer since all processes' dirs' names are numeric
              if(firstTime != 0){ //firstTime indicates that initially we take malloc we filled it then realloc
                pList.length++;
                pList.array = realloc(pList.array,pList.length*sizeof(struct process));
              }
            firstTime = 1;
            cats(&cmdPath,de->d_name); //cats function is similar to strcat only difference is use memcpy
            cats(&cmdPath,"/cmdline");
            cats(&statusPath,de->d_name);
            cats(&statusPath,"/status");
            fp1 = fopen(cmdPath,"r"); // Copy contents of cmdline arguments
            if(fp1 == NULL){
              perror("Can't open process' cmdline file: ");
              exit(0);
            }
            pList.array[pList.length-1].cmdline = NULL;
            while((ch = fgetc(fp1)) != EOF){
              if(flagForCommandLine == 0){
              pList.array[pList.length-1].cmdline = malloc(sizeof(char));
              flagForCommandLine = 1;
              }
              if(flagForCommandLine == 1){
                if(ch == '\0'){
                  ch = ' ';
                }
                pList.array[pList.length-1].cmdline[counterForCmd++]=ch;
                pList.array[pList.length-1].cmdline = realloc(pList.array[pList.length-1].cmdline,sizeof(char)*(counterForCmd+1));
              }
            }
            pList.array[pList.length-1].cmdline = realloc(pList.array[pList.length-1].cmdline,sizeof(char)*(counterForCmd+1));
            pList.array[pList.length-1].cmdline[counterForCmd++]= '\0';
            fclose(fp1); //Open status file
            fp1 = fopen(statusPath,"r");
            if( fp1 == NULL ) {
                perror("Can't open process' status file: ");
                exit(0);
              }
            do{ //parse the file
              c = fgets(line,99,fp1);
              if(c != NULL){
                if(strstr(line,"Name:")){
                  f = strstr(line,":") +1;
                  pList.array[pList.length-1].name = malloc(sizeof(char));
                  for(int i=0;f;){
                    if(*f == ' ' | *f=='\t'){
                      f++;
                    }
                    else if(*f == '\n'){
                      pList.array[pList.length-1].name[i] = '\0';
                      break;
                    }
                    else{
                      pList.array[pList.length-1].name[i++] = *f++;
                      pList.array[pList.length-1].name = realloc(pList.array[pList.length-1].name,sizeof(char)*(i+1));
                    }
                  }
                }
                else if(strstr(line,"PPid:")){
                  f = strstr(line,":") +1;
                  pList.array[pList.length-1].ppid = malloc(sizeof(char));
                  for(int i=0;f;){
                    if(*f == ' ' | *f=='\t'){
                      f++;
                    }
                    else if(*f == '\n'){
                      pList.array[pList.length-1].ppid[i] = '\0';
                      break;
                    }
                    else{
                      pList.array[pList.length-1].ppid[i++] = *f++;
                      pList.array[pList.length-1].ppid = realloc(pList.array[pList.length-1].ppid,sizeof(char)*(i+1));
                    }
                  }
                }
                else if(strstr(line,"Pid:")){
                  if(strstr(line,"Tracer") || strstr(line,"PPid")){
                    continue;
                  }
                  f = strstr(line,":") +1;
                  pList.array[pList.length-1].pid = malloc(sizeof(char));
                  for(int i=0;f;){
                    if(*f == ' ' | *f=='\t'){
                      f++;
                    }
                    else if(*f == '\n'){
                      pList.array[pList.length-1].pid[i] = '\0';
                      break;
                    }
                    else{
                      pList.array[pList.length-1].pid[i++] = *f++;
                      pList.array[pList.length-1].pid = realloc(pList.array[pList.length-1].pid,sizeof(char)*(i+1));
                    }
                  }
                }
                else if(strstr(line,"Uid:")){
                  f = strstr(line,":") +1;
                  int firstTabFlag = 0; //in status file uid is splitted by tab character so this is flag to find uid
                  char *string = malloc(sizeof(char));
                  for(int i=0;f;){
                    if(*f == ' ' | *f=='\t'){
                      if(firstTabFlag){
                        string[i] = '\0';
                        break;
                      }
                      f++;
                      firstTabFlag =1;
                    }
                    else{
                      string[i++] = *f++;
                      string = realloc(string,sizeof(char)*(i+1));
                    }
                  }
                  struct passwd* pw;
                  if( ( pw = getpwuid( atoi(string) ) ) != NULL ){ //to find owner name, use uid
                    pList.array[pList.length-1].user = malloc(sizeof(char)*strlen(pw->pw_name)+1);
                    strncpy(pList.array[pList.length-1].user,pw->pw_name,strlen(pw->pw_name)+1);
                  }
                  free(string);
                  string = NULL;
                }
                else{
                  continue;
                }
              }
            }while(c != NULL);
            fclose(fp1);
          }
        }
      closedir(dr);
      processListStateFlag = 0;
    }
  }
}
