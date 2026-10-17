#define _POSIX_C_SOURCE 200809L
#include "mdpx.h"
#include <sodium.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
/* 128-packet corpus, replay reset once per complete pass, outside timing. */
#define CORPUS 128
static int one(double seconds,size_t z) {
    unsigned char pk[32],sk[64],sid[16]= {
        0
    },sig[64],payload[CAP]= {
        0
    };
    struct workspace *w=malloc(sizeof *w);
    struct trust *t=calloc(1,sizeof *t);
    size_t n=121+z;
    unsigned char *corpus=malloc(n*CORPUS);
    if(!w||!t||!corpus) {
        free(w);
        free(t);
        free(corpus);
        return 1;
    }
    crypto_sign_keypair(pk,sk);
    t->count=1;
    memcpy(t->entries[0].pk,pk,32);
    key_id(t->entries[0].id,pk);
    strcpy(t->entries[0].label,"HOST-A");
    uint64_t ts=realtime_ms();
    for(unsigned i=0;i<CORPUS;i++)if(encode(w,corpus+i*n,&n,payload,z,"HOST-A",pk,sk,sid,ts,i))abort();
    struct packet p;
    const struct identity *who=NULL;
    int failed=0;
    const char *modes[]= {
        "sign_only","verify_only","invalid_signature_verify","serialization_sign","full_encapsulation","decode_authorize_verify_freshness_replay"
    };
    for(unsigned mode=0;mode<6;mode++) {
        uint64_t ops=0;
        double elapsed=0;
        /* Warm-up uses identical primitives; never timed. */for(unsigned j=0;j<64;j++) {
            decode(corpus,n,&p);
            if(verify(w,&p,pk))abort();
        }
        decode(corpus,n,&p);
        size_t m=message(w,&p);
        memcpy(sig,p.signature,64);
        if(mode==2)sig[0]^=1;
        while(elapsed<seconds) {
            /* Refresh aging corpus outside the measured verification loop. */
            uint64_t wall_now = realtime_ms();
            if (mode == 5 && (wall_now < ts || wall_now - ts > 10000)) {
                ts = wall_now;
                for (unsigned j = 0; j < CORPUS; j++)
                    if (encode(w, corpus + j*n, &n, payload, z, "HOST-A",
                               pk, sk, sid, ts, j)) abort();
            }
            struct session session= {
                0
            };
            double start=monotime();
            for(unsigned j=0;j<CORPUS;j++) {
                int r=0;
                switch(mode) {
                    case 0:r=crypto_sign_detached(sig,NULL,w->message,m,sk);
                    break;
                    case 1:case 2:r=crypto_sign_verify_detached(sig,w->message,m,pk);
                    if(mode==2)r=(r==0);
                    break;
                    case 3:m=message(w,&p);
                    r=crypto_sign_detached(sig,NULL,w->message,m,sk);
                    break;
                    case 4:r=encode(w,corpus+j*n,&n,payload,z,"HOST-A",pk,sk,sid,realtime_ms(),j);
                    break;
                    default: {
                        uint64_t now = realtime_ms();
                        r=decode(corpus+j*n,n,&p);
                        if(!r)r=authorize(w,&p,t,&who);
                        if(!r)r=fresh(p.timestamp,now,30000,5000);
                        if(!r)r=replay(&session,1,who,&p,now,30000);
                        break;
                    }
                }
                failed|=r!=0;
            }
            elapsed+=monotime()-start;
            ops+=CORPUS;
        }
        printf("%s,%zu,6,%zu,%zu,%u,%zu,%.6f,%"PRIu64",%.2f,%.2f\n",modes[mode],z,17+57+z,n,CORPUS,n*CORPUS,elapsed,ops,(double)ops/elapsed,elapsed*1e9/(double)ops);
    }
    sodium_memzero(sk,sizeof sk);
    free(corpus);
    free(t);
    free(w);
    return failed;
}
int benchmark(double seconds,const char *sizes) {
    puts("operation,payload_bytes,label_bytes,signed_message_bytes,outer_bytes,corpus_packets,corpus_bytes,seconds,operations,ops_per_second,ns_per_operation");
    if (!*sizes || sizes[0] == ',' || sizes[strlen(sizes)-1] == ',' || strstr(sizes, ",,")) return 1;
    for (const char *s = sizes; *s; s++)
        if ((*s < '0' || *s > '9') && *s != ',') return 1;
    char *copy=strdup(sizes);
    if(!copy)return 1;
    int rc=0;
    char *save=NULL;
    for(char *s=strtok_r(copy,",",&save);s;s=strtok_r(NULL,",",&save)) {
        char *end;
        unsigned long n=strtoul(s,&end,10);
        if(!*s||*end||*s=='-'||n>CAP-121) {
            rc=1;
            break;
        }
        if(one(seconds,(size_t)n)) {
            rc=1;
            break;
        }
    }
    free(copy);
    return rc;
}
