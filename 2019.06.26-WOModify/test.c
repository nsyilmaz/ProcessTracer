#include <unistd.h>
#include <stdio.h>

int main(){
	char a;
	printf("%ld",read(0,&a,1));
	return 0;
}
