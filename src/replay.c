#include "mdpx.h"
#include <string.h>
enum result replay(struct session *table,size_t count,const struct identity *key,const struct packet *p,uint64_t now,uint64_t age)  {
    struct session *s=NULL,*empty=NULL;
    for(size_t i=0;i<count;i++) {
        struct session *q=table+i;
        if(q->used&&now>q->latest&&now-q->latest>age)q->used=0;
        if(!q->used) {
            if(!empty)empty=q;
        }
        else if(!memcmp(q->pk,key->pk,32)&&!memcmp(q->id,p->session,16))s=q;
    }
    if(!s) {
        if(!empty)return FULL;
        s=empty;
        memset(s,0,sizeof(*s));
        s->used=1;
        memcpy(s->pk,key->pk,32);
        memcpy(s->id,p->session,16);
        s->high=p->sequence;
        s->latest=p->timestamp;
        s->bits[0]=1;
        return OK;
    }
    if(p->sequence>s->high) {
        uint64_t d=p->sequence-s->high;
        uint64_t shifted[16]= {
            0
        };
        if(d<1024)for(unsigned i=0;i<1024-(unsigned)d;i++)if(s->bits[i/64]&(UINT64_C(1)<<(i%64))) {
            unsigned j=i+(unsigned)d;
            shifted[j/64]|=UINT64_C(1)<<(j%64);
        }
        memcpy(s->bits,shifted,sizeof shifted);
        s->high=p->sequence;
    }
    uint64_t d=s->high-p->sequence;
    if(d>=1024||(s->bits[d/64]&(UINT64_C(1)<<(d%64))))return REPLAY;
    s->bits[d/64]|=UINT64_C(1)<<(d%64);
    if(p->timestamp>s->latest)s->latest=p->timestamp;
    return OK;
}
