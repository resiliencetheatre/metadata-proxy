#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#define MAX 65507
#define TRACK (1u<<28)
static volatile sig_atomic_t stop;
static void halt(int s) {
    (void)s;
    stop=1;
}
static double now(void) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t))exit(1);
    return (double)t.tv_sec+t.tv_nsec/1e9;
}
static void put(unsigned char *b,uint64_t n) {
    for(int i=7;i>=0;i--) {
        b[i]=(unsigned char)n;
        n>>=8;
    }
}
static uint64_t get(const unsigned char *b) {
    uint64_t n=0;
    for(int i=0;i<8;i++)n=n*256+b[i];
    return n;
}
static int sock(unsigned port,int bind_it) {
    int fd=socket(AF_INET,SOCK_DGRAM,0);
    struct sockaddr_in a= {
        .sin_family=AF_INET,.sin_port=htons((uint16_t)port)
    };
    a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(fd<0||(bind_it?bind(fd,(struct sockaddr *)&a,sizeof a):connect(fd,(struct sockaddr *)&a,sizeof a))) {
        perror("socket");
        exit(1);
    }
    return fd;
}
int main(int argc,char **argv) {
    if(argc<4) {
        fprintf(stderr,"benchmark-only tool: send PORT SIZE SECONDS RATE | sink PORT SECONDS [SIZE] | relay LISTEN_PORT FORWARD_PORT SECONDS\nRATE=0 saturation; payload size >=8; IPv4 loopback only\n");
        return 1;
    }
    signal(SIGTERM,halt);
    signal(SIGINT,halt);
    unsigned port=(unsigned)strtoul(argv[2],NULL,10);
    if(!port||port>65535)return 1;
    unsigned char b[MAX];
    uint64_t sent=0,received=0,duplicates=0,reordered=0,invalid=0,errors=0,high=0;
    int have=0;
    double start=now();
    int fd;
    double duration;
    int rcv=0,snd=0;
    socklen_t sl=sizeof(int);
    if(!strcmp(argv[1],"send")) {
        if(argc!=6)return 1;
        size_t size=(size_t)strtoul(argv[3],NULL,10);
        duration=strtod(argv[4],NULL);
        double rate=strtod(argv[5],NULL);
        if(size<8||size>MAX||duration<=0||rate<0)return 1;
        fd=sock(port,0);
        for(size_t j=8;j<size;j++)b[j]=(unsigned char)(j*31u+7u);
        uint64_t seq=0;
        while(!stop&&now()-start<duration&&seq<TRACK) {
            put(b,seq++);
            ssize_t n=send(fd,b,size,MSG_DONTWAIT);
            if(n==(ssize_t)size)sent++;
            else errors++;
            if(rate>0) {
                double target=start+seq/rate;
                struct timespec t= {
                    (time_t)target,(long)((target-(time_t)target)*1e9)
                };
                int e;
                do {
                    e=clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&t,NULL);
                }
                while(e==EINTR&&!stop);
            }
        }
    }
    else  {
        int relay=!strcmp(argv[1],"relay");
        if(!relay&&strcmp(argv[1],"sink"))return 1;
        if(relay ? argc != 5 : (argc != 4 && argc != 5))return 1;
        size_t expected_size = !relay && argc == 5 ? (size_t)strtoul(argv[4], NULL, 10) : 0;
        if(expected_size > MAX || (expected_size && expected_size < 8))return 1;
        duration=strtod(argv[relay?4:3],NULL);
        if(duration<=0)return 1;
        fd=sock(port,1);
        int out=relay?sock((unsigned)strtoul(argv[3],NULL,10),0):-1;
        unsigned char *seen=calloc(TRACK/8,1);
        if(!seen)return 1;
        while(!stop&&now()-start<duration) {
            struct pollfd p= {
                fd,POLLIN,0
            };
            int r=poll(&p,1,100);
            if(r<0) {
                if(errno==EINTR)continue;
                errors++;
                break;
            }
            if(r>0) {
                struct iovec iov= {
                    b,sizeof b
                };
                struct msghdr msg= {
                    0
                };
                msg.msg_iov=&iov;
                msg.msg_iovlen=1;
                ssize_t n=recvmsg(fd,&msg,0);
                if(n<0) {
                    if(errno!=EINTR)errors++;
                    continue;
                }
                if(msg.msg_flags&MSG_TRUNC) {
                    invalid++;
                    continue;
                }
                if(relay) {
                    if(send(out,b,(size_t)n,MSG_DONTWAIT)!=n)errors++;
                    else sent++;
                    continue;
                }
                if(n<8 || (expected_size && (size_t)n != expected_size)) {
                    invalid++;
                    continue;
                }
                uint64_t seq=get(b);
                int bad=seq>=TRACK;
                for(ssize_t i=8;i<n;i++)if(b[i]!=(unsigned char)((size_t)i*31u+7u)) {
                    bad=1;
                    break;
                }
                if(bad) {
                    invalid++;
                    continue;
                }
                if(seen[seq/8]&(1u<<(seq%8))) {
                    duplicates++;
                    continue;
                }
                seen[seq/8]|=(unsigned char)(1u<<(seq%8));
                if(have&&seq<high)reordered++;
                if(!have||seq>high)high=seq;
                have=1;
                received++;
            }
        }
        free(seen);
        if(out>=0)close(out);
    }
    getsockopt(fd,SOL_SOCKET,SO_RCVBUF,&rcv,&sl);
    getsockopt(fd,SOL_SOCKET,SO_SNDBUF,&snd,&sl);
    close(fd);
    printf("{\"sent\":%"PRIu64",\"received\":%"PRIu64",\"duplicates\":%"PRIu64",\"reordered\":%"PRIu64",\"invalid\":%"PRIu64",\"errors\":%"PRIu64",\"elapsed\":%.9f,\"rcvbuf\":%d,\"sndbuf\":%d}\n",sent,received,duplicates,reordered,invalid,errors,now()-start,rcv,snd);
    return 0;
}
