#define _POSIX_C_SOURCE 200809L
#include "mdpx.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <inttypes.h>
static volatile sig_atomic_t stop;
static void stopped(int sig) {
    (void)sig;
    stop=1;
}
uint64_t realtime_ms(void) {
    struct timespec t;
    if(clock_gettime(CLOCK_REALTIME,&t)||t.tv_sec<=0||t.tv_nsec<0||t.tv_nsec>=1000000000L||(uint64_t)t.tv_sec>(UINT64_MAX-(uint64_t)t.tv_nsec/1000000)/1000) {
        fprintf(stderr,"unusable CLOCK_REALTIME\n");
        exit(1);
    }
    return (uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;
}
double monotime(void) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t)) {
        perror("CLOCK_MONOTONIC");
        exit(1);
    }
    return (double)t.tv_sec+(double)t.tv_nsec/1e9;
}
static void help(void) {
    puts("metadata-proxy keygen --secret FILE --public FILE\nmetadata-proxy encap --listen HOST:PORT --peer HOST:PORT --label HOST-A --secret FILE [--max-datagram 1200] [--stats-interval 5]\nmetadata-proxy decap --listen HOST:PORT --forward HOST:PORT --trust FILE [--max-datagram 1200] [--max-age-ms 30000] [--future-skew-ms 5000] [--max-sessions 1024] [--stats-interval 5]\nmetadata-proxy inspect --packet FILE --trust FILE\nmetadata-proxy bench [--seconds 5] [--sizes 0,64,160,512,1024]\nIPv6 endpoints must be bracketed: [::1]:5000. max-datagram is total UDP payload (116..65507).");
}
struct options  {
    const char *listen,*peer,*forward,*label,*secret,*public,*trust,*packet,*sizes;
    uint64_t cap,age,skew,sessions,interval,seconds;
};
static int number(const char *s,uint64_t *v) {
    if(!*s)return -1;
    uint64_t n=0;
    for(;*s;s++) {
        if(*s<'0'||*s>'9'||n>(UINT64_MAX-(unsigned)(*s-'0'))/10)return -1;
        n=n*10+(unsigned)(*s-'0');
    }
    *v=n;
    return 0;
}
static int options(int argc,char **argv,struct options *o) {
    *o=(struct options) {
        .cap=1200,.age=30000,.skew=5000,.sessions=1024,.interval=5,.seconds=5,.sizes="0,64,160,512,1024"
    };
    const char *cmd=argv[1];
    for(int i=2;i<argc;i+=2) {
        if(i+1>=argc)return -1;
        const char *k=argv[i],*v=argv[i+1];
#define STR(name,allow) if(!strcmp(k,"--" #name)&& (allow)){o->name=v;continue;}
#define NUM(name,field,allow) if(!strcmp(k,name)&&(allow)){if(number(v,&o->field))return -1;continue;}
        int enc=!strcmp(cmd,"encap"),dec=!strcmp(cmd,"decap"),key=!strcmp(cmd,"keygen"),ins=!strcmp(cmd,"inspect"),bench=!strcmp(cmd,"bench");
        STR(listen,enc||dec) STR(peer,enc) STR(forward,dec) STR(label,enc) STR(secret,enc||key) STR(public,key) STR(trust,dec||ins) STR(packet,ins) STR(sizes,bench) NUM("--max-datagram",cap,enc||dec) NUM("--max-age-ms",age,dec) NUM("--future-skew-ms",skew,dec) NUM("--max-sessions",sessions,dec) NUM("--stats-interval",interval,enc||dec) NUM("--seconds",seconds,bench) return -1;
    }
    return o->cap<116||o->cap>CAP||!o->sessions||o->sessions>65536||o->interval>86400||!o->seconds||o->seconds>86400?-1:0;
}
static int endpoint(const char *s,int listener) {
    char host[256],port[6];
    const char *p;
    size_t n;
    if(s[0]=='[') {
        p=strchr(s,']');
        if(!p||p[1]!=':')return -1;
        n=(size_t)(p-s-1);
        if(!n||n>=sizeof host)return -1;
        memcpy(host,s+1,n);
        p+=2;
    }
    else {
        p=strchr(s,':');
        if(!p||strchr(p+1,':'))return -1;
        n=(size_t)(p-s);
        if(!n||n>=sizeof host)return -1;
        memcpy(host,s,n);
        p++;
    }
    host[n]=0;
    uint64_t pn;
    if(strlen(p)>5||number(p,&pn)||!pn||pn>65535)return -1;
    strcpy(port,p);
    struct addrinfo hints= {
        0
    },*list=NULL;
    hints.ai_family=AF_UNSPEC;
    hints.ai_socktype=SOCK_DGRAM;
    hints.ai_flags=AI_NUMERICSERV;
    int rc=getaddrinfo(host,port,&hints,&list);
    if(rc) {
        fprintf(stderr,"getaddrinfo: %s\n",gai_strerror(rc));
        return -1;
    }
    int fd=-1;
    for(struct addrinfo *a=list;a;a=a->ai_next) {
        fd=socket(a->ai_family,SOCK_DGRAM,0);
        if(fd<0)continue;
        int on=1;
        if(a->ai_family==AF_INET6&&setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&on,sizeof on)) {
            close(fd);
            fd=-1;
            continue;
        }
#ifdef __linux__
        int mode=a->ai_family==AF_INET?IP_PMTUDISC_DO:IPV6_PMTUDISC_DO;
        int level=a->ai_family==AF_INET?IPPROTO_IP:IPPROTO_IPV6;
        int opt=a->ai_family==AF_INET?IP_MTU_DISCOVER:IPV6_MTU_DISCOVER;
        if(setsockopt(fd,level,opt,&mode,sizeof mode)) {
            close(fd);
            fd=-1;
            continue;
        }
#endif
#ifdef SO_RXQ_OVFL
        if(listener&&setsockopt(fd,SOL_SOCKET,SO_RXQ_OVFL,&on,sizeof on))fprintf(stderr,"SO_RXQ_OVFL unavailable: %s\n",strerror(errno));
#endif
        if((listener?bind(fd,a->ai_addr,a->ai_addrlen):connect(fd,a->ai_addr,a->ai_addrlen))==0) {
            int flags=fcntl(fd,F_GETFL);
            if(flags>=0&&fcntl(fd,F_SETFL,flags|O_NONBLOCK)==0)break;
        }
        close(fd);
        fd=-1;
    }
    freeaddrinfo(list);
    return fd;
}
struct counters  {
    uint64_t input_packets,input_bytes,forwarded_packets,forwarded_bytes,oversize,truncation,drops[9],socket_errors,send_failures,kernel_drops;
};
static void stats(const struct counters *s) {
    fprintf(stderr,"stats input_packets=%"PRIu64" input_bytes=%"PRIu64" forwarded_packets=%"PRIu64" forwarded_bytes=%"PRIu64" oversize=%"PRIu64" truncation=%"PRIu64" parse_errors=%"PRIu64" unknown_keys=%"PRIu64" unauthorized_labels=%"PRIu64" invalid_signatures=%"PRIu64" stale=%"PRIu64" future=%"PRIu64" replay_drops=%"PRIu64" session_cap_drops=%"PRIu64" socket_errors=%"PRIu64" send_failures=%"PRIu64" kernel_receive_drops=%"PRIu64"\n",s->input_packets,s->input_bytes,s->forwarded_packets,s->forwarded_bytes,s->oversize,s->truncation,s->drops[PARSE],s->drops[UNKNOWN],s->drops[UNAUTHORIZED],s->drops[SIGNATURE],s->drops[STALE],s->drops[FUTURE],s->drops[REPLAY],s->drops[FULL],s->socket_errors,s->send_failures,s->kernel_drops);
}
static int run(const struct options *o,int enc) {
    int rc=1,in=-1,out=-1;
    unsigned char pk[32]= {
        0
    },sk[64]= {
        0
    },sid[16];
    struct trust *trust=calloc(1,sizeof *trust);
    struct session *sessions=calloc((size_t)o->sessions,sizeof *sessions);
    struct workspace *w=malloc(sizeof *w);
    unsigned char *buf=malloc(CAP),*wire=malloc(CAP);
    struct counters c= {
        0
    };
    if(!trust||!sessions||!w||!buf||!wire) {
        fprintf(stderr,"allocation failed\n");
        goto done;
    }
    if(!o->listen||(enc?(!o->peer||!o->label||!o->secret):(!o->forward||!o->trust))) {
        fprintf(stderr,"missing required options\n");
        goto done;
    }
    if(enc) {
        if(!label_valid((const unsigned char *)o->label,strlen(o->label))||115+strlen(o->label)>o->cap||secret_load(o->secret,pk,sk)) {
            fprintf(stderr,"invalid label, size cap, or secret file\n");
            goto done;
        }
        randombytes_buf(sid,sizeof sid);
    }
    else if(trust_load(o->trust,trust)) {
        fprintf(stderr,"invalid trust file\n");
        goto done;
    }
    in=endpoint(o->listen,1);
    out=endpoint(enc?o->peer:o->forward,0);
    if(in<0||out<0) {
        fprintf(stderr,"cannot open endpoint: %s\n",strerror(errno));
        goto done;
    }
    int receive_buffer = 0, send_buffer = 0;
    socklen_t buffer_length = sizeof(int);
    if (getsockopt(in, SOL_SOCKET, SO_RCVBUF, &receive_buffer, &buffer_length) ||
        getsockopt(out, SOL_SOCKET, SO_SNDBUF, &send_buffer, &buffer_length)) {
        perror("socket buffer query");
        goto done;
    }
    fprintf(stderr, "socket_buffers receive=%d send=%d bytes\n", receive_buffer, send_buffer);
    (void)realtime_ms();
    struct sigaction sa= {
        0
    };
    sa.sa_handler=stopped;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,&sa,NULL);
    sigaction(SIGTERM,&sa,NULL);
    double next=monotime()+(double)o->interval;
    uint64_t seq=0;
    uint32_t last_kernel=0;
    rc=0;
    while(!stop) {
        struct pollfd pfd= {
            in,POLLIN,0
        };
        int r=poll(&pfd,1,100);
        if(r<0) {
            if(errno==EINTR)continue;
            c.socket_errors++;
            rc=1;
            break;
        }
        if(r>0&&(pfd.revents&(POLLERR|POLLNVAL|POLLHUP))) {
            int error=0;
            socklen_t len=sizeof error;
            getsockopt(in,SOL_SOCKET,SO_ERROR,&error,&len);
            c.socket_errors++;
            if(pfd.revents&(POLLNVAL|POLLHUP)){rc=1;break;}
        }
        if(r>0&&(pfd.revents&POLLIN)) {
            struct iovec iov= {
                buf,(size_t)o->cap
            };
            union  {
                struct cmsghdr alignment;
                unsigned char data[128];
            }
            control;
            struct msghdr msg= {
                0
            };
            msg.msg_iov=&iov;
            msg.msg_iovlen=1;
            msg.msg_control=control.data;
            msg.msg_controllen=sizeof control.data;
            ssize_t n=recvmsg(in,&msg,MSG_TRUNC);
            if(n<0) {
                if(errno!=EINTR&&errno!=EAGAIN&&errno!=EWOULDBLOCK)c.socket_errors++;
            }
            else {
                c.input_packets++;
                c.input_bytes+=(uint64_t)n;
#ifdef SO_RXQ_OVFL
                for(struct cmsghdr *h=CMSG_FIRSTHDR(&msg);h;h=CMSG_NXTHDR(&msg,h))if(h->cmsg_level==SOL_SOCKET&&h->cmsg_type==SO_RXQ_OVFL&&h->cmsg_len>=CMSG_LEN(sizeof(uint32_t))) {
                    uint32_t value;
                    memcpy(&value,CMSG_DATA(h),sizeof value);
                    c.kernel_drops+=(uint32_t)(value-last_kernel);
                    last_kernel=value;
                }
#else
                (void)last_kernel;
#endif
                const unsigned char *sendbuf=NULL;
                size_t sendlen=0;
                if(msg.msg_flags&MSG_TRUNC) {
                    c.truncation++;
                    if((size_t)n>o->cap)c.oversize++;
                }
                else if(enc) {
                    if((size_t)n>o->cap-115-strlen(o->label))c.oversize++;
                    else if(seq==UINT64_MAX) {
                        fprintf(stderr,"sequence exhausted; restart required\n");
                        rc=1;
                        stop=1;
                    }
                    else if(encode(w,wire,&sendlen,buf,(size_t)n,o->label,pk,sk,sid,realtime_ms(),seq++)) {
                        fprintf(stderr,"signing failed\n");
                        rc=1;
                        stop=1;
                    }
                    else sendbuf=wire;
                }
                else {
                    struct packet p;
                    const struct identity *who=NULL;
                    enum result result=decode(buf,(size_t)n,&p)?PARSE:OK;
                    if(result==OK)result=authorize(w,&p,trust,&who);
                    uint64_t now=realtime_ms();
                    if(result==OK)result=fresh(p.timestamp,now,o->age,o->skew);
                    if(result==OK)result=replay(sessions,(size_t)o->sessions,who,&p,now,o->age);
                    if(result!=OK)c.drops[result]++;
                    else {
                        sendbuf=p.payload;
                        sendlen=p.payload_length;
                    }
                }
                if(sendbuf) {
                    ssize_t sent;
                    do {
                        sent=send(out,sendbuf,sendlen,0);
                    }
                    while(sent<0&&errno==EINTR&&!stop);
                    if(sent<0||(size_t)sent!=sendlen)c.send_failures++;
                    else {
                        c.forwarded_packets++;
                        c.forwarded_bytes+=sendlen;
                    }
                }
            }
        }
        if(o->interval&&monotime()>=next) {
            stats(&c);
            next=monotime()+(double)o->interval;
        }
    }
    stats(&c);
    done:if(in>=0)close(in);
    if(out>=0)close(out);
    sodium_memzero(sk,sizeof sk);
    free(trust);
    free(sessions);
    free(w);
    free(buf);
    free(wire);
    return rc;
}
static int inspect(const struct options *o)  {
    if (!o->packet || !o->trust) return 1;
    struct trust *t = calloc(1, sizeof *t);
    struct workspace *w = malloc(sizeof *w);
    unsigned char *b = malloc(CAP + 1);
    int rc = 1;
    if (!t || !w || !b) goto done;
    if (trust_load(o->trust, t))  {
        fprintf(stderr, "invalid trust file\n");
        goto done;
    }
    FILE *f = fopen(o->packet, "rb");
    if (!f)  {
        perror("packet");
        goto done;
    }
    size_t n = fread(b, 1, CAP + 1, f);
    int bad = ferror(f);
    if (fclose(f)) bad = 1;
    if (bad)  {
        fprintf(stderr, "packet read failed\n");
        goto done;
    }
    struct packet p;
    if (decode(b, n, &p))  {
        puts("structural_validity=false known_key=unavailable authorized_label=unavailable signature_validity=unavailable timestamp=unavailable");
        goto done;
    }
    const struct identity *key = NULL;
    int authorized = 0;
    for (size_t i = 0; i < t->count; i++)  {
        if (!memcmp(p.id, t->entries[i].id, 8))  {
            key = &t->entries[i];
            if (!strcmp(p.label, key->label)) authorized = 1;
        }
    }
    int valid = key && !verify(w, &p, key->pk);
    printf("structural_validity=true known_key=%s authorized_label=%s signature_validity=%s timestamp_ms=%"PRIu64" label=%s sequence=%"PRIu64" payload_bytes=%zu offline_freshness=%d replay_protection=none\n", key ? "true" : "false", authorized ? "true" : "false", !key ? "unavailable" : valid ? "true" : "false", p.timestamp, p.label, p.sequence, p.payload_length, fresh(p.timestamp, realtime_ms(), 30000, 5000));
    rc = authorized && valid ? 0 : 1;
    done: free(t);
    free(w);
    free(b);
    return rc;
}
int main(int argc,char **argv) {
    if(sodium_init()<0) {
        fprintf(stderr,"sodium_init failed\n");
        return 1;
    }
    for(int i=1;i<argc;i++)if(!strcmp(argv[i],"--help")) {
        help();
        return 0;
    }
    if(argc<2) {
        help();
        return 1;
    }
    struct options o;
    if(options(argc,argv,&o)) {
        fprintf(stderr,"invalid options; see --help\n");
        return 1;
    }
    if(!strcmp(argv[1],"keygen")) {
        if(!o.secret||!o.public)return 1;
        if(keygen(o.secret,o.public)) {
            perror("keygen (an already-created file may remain)");
            return 1;
        }
        return 0;
    }
    if(!strcmp(argv[1],"encap"))return run(&o,1);
    if(!strcmp(argv[1],"decap"))return run(&o,0);
    if(!strcmp(argv[1],"inspect"))return inspect(&o);
    if(!strcmp(argv[1],"bench"))return benchmark((double)o.seconds,o.sizes);
    help();
    return 1;
}
