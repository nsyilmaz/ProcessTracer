#include "defs.h"
#include "util.h"
#include "process_list.h"
#include "request_handler.h"

//free the whole process list
void freeProcessList(){
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

void getNameOfProcess(char* line){
    char* dataPointer = strstr(line,":") +1;
    pList.array[pList.length-1].name = malloc(sizeof(char));
    for(int i=0;dataPointer;){
        if(*dataPointer == ' ' || *dataPointer=='\t'){
            dataPointer++;
        }
        else if(*dataPointer == '\n'){
            pList.array[pList.length-1].name[i] = '\0';
            break;
        }
        else{
            pList.array[pList.length-1].name[i++] = *dataPointer++;
            pList.array[pList.length-1].name = realloc(pList.array[pList.length-1].name,sizeof(char)*(i+1));
        }
    }
}

void getParentPIDOfProcess(char* line){
    char *dataPointer = strstr(line,":") +1;
    pList.array[pList.length-1].ppid = malloc(sizeof(char));
    for(int i=0;dataPointer;){
        if(*dataPointer == ' ' || *dataPointer=='\t'){
            dataPointer++;
        }
        else if(*dataPointer == '\n'){
            pList.array[pList.length-1].ppid[i] = '\0';
            break;
        }
        else{
            pList.array[pList.length-1].ppid[i++] = *dataPointer++;
            pList.array[pList.length-1].ppid = realloc(pList.array[pList.length-1].ppid,sizeof(char)*(i+1));
        }
    }
}

void getPIDOfProcess(char* line){
    char* dataPointer = strstr(line,":") +1;
    pList.array[pList.length-1].pid = malloc(sizeof(char));
    for(int i=0;dataPointer;){
        if(*dataPointer == ' ' || *dataPointer=='\t'){
            dataPointer++;
        }
        else if(*dataPointer == '\n'){
            pList.array[pList.length-1].pid[i] = '\0';
            break;
        }
        else{
            pList.array[pList.length-1].pid[i++] = *dataPointer++;
            pList.array[pList.length-1].pid = realloc(pList.array[pList.length-1].pid,sizeof(char)*(i+1));
        }
    }
}

void getOwnerOfProcess(char* line){
    char *dataPointer = strstr(line,":") +1;
    struct passwd* pw;
    int firstTabFlag = 0; //in status file uid is splitted by tab character so this is flag to find uid
    char *string = malloc(sizeof(char));
    for(int i=0;dataPointer;){
        if(*dataPointer == ' ' || *dataPointer=='\t'){
            if(firstTabFlag){
                string[i] = '\0';
                break;
            }
            dataPointer++;
            firstTabFlag =1;
        }
        else{
            string[i++] = *dataPointer++;
            string = realloc(string,sizeof(char)*(i+1));
        }
    }
    if( ( pw = getpwuid( atoi(string) ) ) != NULL ){ //to find owner name, use uid
        pList.array[pList.length-1].user = malloc(sizeof(char)*strlen(pw->pw_name)+1);
        strncpy(pList.array[pList.length-1].user,pw->pw_name,strlen(pw->pw_name)+1);
    }
    free(string);
    string = NULL;
}

void takeProcessStatusInformation(FILE* statusFileDescriptor){
    char *checkFileEnded;
    char line[100];
    do{ //parse the file
        checkFileEnded = fgets(line,99,statusFileDescriptor);
        if(checkFileEnded != NULL){
            if(strstr(line,"Name:")){
                getNameOfProcess(line);
            }
            else if(strstr(line,"PPid:")){
                getParentPIDOfProcess(line);
            }
            else if(strstr(line,"Pid:")){
                if(strstr(line,"Tracer") || strstr(line,"PPid")){
                    continue;
                }
                getPIDOfProcess(line);
            }
            else if(strstr(line,"Uid:")){
                getOwnerOfProcess(line);
            }
            else{
                continue;
            }
        }
    }while(checkFileEnded != NULL);
}

//void take Command Line Arguments of processes
void takeCommandLineArguments(FILE* cmdFileDescriptor){
    int counterForCmd=0;
    int firstTimeFlag = 0;
    char readedCharFromFile;
    pList.array[pList.length-1].cmdline = NULL;
    while((readedCharFromFile = fgetc(cmdFileDescriptor)) != EOF){
        if(firstTimeFlag == 0){
            pList.array[pList.length-1].cmdline = malloc(sizeof(char));
            firstTimeFlag = 1;
        }
        if(firstTimeFlag == 1){
            if(readedCharFromFile == '\0'){
                readedCharFromFile = ' ';
            }
            pList.array[pList.length-1].cmdline[counterForCmd++]=readedCharFromFile;
            pList.array[pList.length-1].cmdline = realloc(pList.array[pList.length-1].cmdline,sizeof(char)*(counterForCmd+1));
        }
    }
    pList.array[pList.length-1].cmdline = realloc(pList.array[pList.length-1].cmdline,sizeof(char)*(counterForCmd+1));
    pList.array[pList.length-1].cmdline[counterForCmd++]= '\0';
}


// Generate the process list
void* addProcessList(void* ptr){
    struct timespec ts;
    ts.tv_sec=0;
    ts.tv_nsec=10000000; // 10 milliseconds
    while(1){
        nanosleep(&ts, NULL); // to avoid %100 CPU
        if(processListStateFlag == 0){ //means there is no need to refresh just go idle
            continue;
        }
        else if(processListStateFlag == 2){ //coming from request handler and indicates program ends
            break;
        }
        else{
            freeProcessList(); // first delete all list
            int firstTime = 0;
            struct dirent *de;
            DIR *procDirectory = opendir("/proc"); // Open proc directory and visit all directories
            if(procDirectory == NULL){
                perror("Can't open the dirs");
                exit(0);
            }
            pList.length++; // hold number of processes
            pList.array = malloc(sizeof(struct process)); //here we take a memory region from heap
            while((de = readdir(procDirectory)) != NULL){
                int lengthOfDirectory = strlen(de->d_name); //read all files/dirs inside the proc one by one
                char directoryName[lengthOfDirectory+1];
                FILE *fileDescriptorForProcessInfo; //For cmd and status files
                char *statusPath ="/proc/"; // It will show the status file
                char *cmdPath = "/proc/"; // It will show the cmdfile
                strncpy(directoryName,de->d_name,lengthOfDirectory);
                directoryName[lengthOfDirectory] = '\0';
                if(checkInt(directoryName)){ //We are checking whether it is integer since all processes' dirs' names are numeric
                    if(firstTime != 0){ //firstTime indicates that initially we take malloc we filled it then realloc
                        pList.length++;
                        pList.array = realloc(pList.array,pList.length*sizeof(struct process));
                    }
                    firstTime = 1;
                    cats(&cmdPath,de->d_name); //cats function is similar to strcat only difference is use memcpy
                    cats(&cmdPath,"/cmdline");
                    cats(&statusPath,de->d_name);
                    cats(&statusPath,"/status");
                    fileDescriptorForProcessInfo = fopen(cmdPath,"r"); // Copy contents of cmdline arguments
                    if(fileDescriptorForProcessInfo == NULL){
                        perror("Can't open process' cmdline file: ");
                        exit(0);
                    }
                    takeCommandLineArguments(fileDescriptorForProcessInfo);
                    fclose(fileDescriptorForProcessInfo); //Close cmdline arguments file
                    fileDescriptorForProcessInfo = fopen(statusPath,"r"); //Open status file
                    if(fileDescriptorForProcessInfo == NULL ) {
                        perror("Can't open process' status file: ");
                        exit(0);
                    }
                    takeProcessStatusInformation(fileDescriptorForProcessInfo);
                    fclose(fileDescriptorForProcessInfo);
                }
            }
            closedir(procDirectory);
            processListStateFlag = 0;
        }
    }
}
