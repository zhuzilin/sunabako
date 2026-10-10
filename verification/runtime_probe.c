#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc,char **argv) {
    if(argc<2)return 2;
    if(!strcmp(argv[1],"readonly")) {
        if(argc<3)return 2;
        int fd=open(argv[2],O_WRONLY);if(fd>=0){close(fd);return 3;}
        if(syscall(SYS_truncate,argv[2],0)==0)return 4;
        fd=open(argv[2],O_RDONLY|O_TRUNC);if(fd>=0){close(fd);return 5;}
        puts("readonly write/truncate denied");return 0;
    }
    if(!strcmp(argv[1],"memory")) {
        if(fork()>0)return 0;
        setsid();if(fork()>0)_exit(0);
        // Bounded at 128 MiB, including if the watchdog is broken.
        for(int i=0;i<128;i++){void *p=malloc(1<<20);if(!p)return 7;memset(p,0x5a,1<<20);usleep(10000);}
        sleep(10);return 8;
    }
    if(!strcmp(argv[1],"network")) {
        int fd=socket(AF_INET,SOCK_STREAM,0), client=socket(AF_INET,SOCK_STREAM,0);
        struct sockaddr_in a={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
        socklen_t n=sizeof(a);
        if(bind(fd,(struct sockaddr*)&a,n)||listen(fd,1)||getsockname(fd,(struct sockaddr*)&a,&n))return 9;
        if(connect(client,(struct sockaddr*)&a,n))return 10;
        int peer=accept(fd,NULL,NULL);if(peer<0)return 11;
        close(peer);close(client);close(fd);
        fd=socket(AF_INET,SOCK_STREAM,0);a.sin_addr.s_addr=htonl(0x01010101);a.sin_port=htons(80);
        if(connect(fd,(struct sockaddr*)&a,n)==0||errno!=ENETUNREACH)return 12;
        puts("private loopback works; outside network unreachable");return 0;
    }
    return 2;
}
