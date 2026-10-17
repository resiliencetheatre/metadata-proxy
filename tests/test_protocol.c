#include "mdpx.h"
#include <sodium.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static struct workspace w;
static unsigned char b[CAP],copy[CAP],payload[CAP],pk[32],sk[64],sid[16];
static struct trust trust;
static void build(size_t z,const char *label,uint64_t seq,uint64_t ts,size_t *n) {
    assert(!encode(&w,b,n,payload,z,label,pk,sk,sid,ts,seq));
}
int main(void) {
    assert(sodium_init()>=0);
    unsigned char seed[32];
    for(int i=0;i<32;i++)seed[i]=(unsigned char)i;
    for(int i=0;i<16;i++)sid[i]=(unsigned char)(0xa0+i);
    crypto_sign_seed_keypair(pk,sk,seed);
    for(size_t i=0;i<CAP;i++)payload[i]=(unsigned char)i;
    size_t n;
    struct packet p;
    char label[64];
    memset(label,'A',63);
    label[63]=0;
    size_t sizes[]= {
        0,4,160,1024,1079,CAP-178
    };
    for(size_t i=0;i<sizeof sizes/sizeof *sizes;i++) {
        build(sizes[i],label,0,1000,&n);
        assert(!decode(b,n,&p));
        assert(!verify(&w,&p,pk));
        assert(p.payload_length==sizes[i]&&!memcmp(p.payload,payload,sizes[i]));
    }
    build(4,"HOST-A",UINT64_C(0x0102030405060708),UINT64_C(0x0000018bcfe56800),&n);
    assert(n==125&&b[6]==0&&b[7]==121&&b[8]==6&&b[9]==0&&b[10]==4);
    assert(p.label_length==63);
    assert(!decode(b,n,&p));
    assert(p.sequence==UINT64_C(0x0102030405060708));
    assert(!memcmp(b+27,sid,16));
    assert(!memcmp(b+121,payload,4));
    FILE *fixture=fopen("tests/fixture.hex","r");
    assert(fixture);
    char hex[252];
    assert(fgets(hex,sizeof hex,fixture));
    assert(!fclose(fixture));
    unsigned char expected[125];
    assert(!sodium_hex2bin(expected,sizeof expected,hex,250,NULL,NULL,NULL));
    assert(!memcmp(expected,b,125));
    memcpy(copy,b,n);
    for(size_t i=0;i<n;i++)assert(decode(b,i,&p));
    for(size_t i=0;i<n;i++) {
        memcpy(b,copy,n);
        b[i]^=0x80;
        if(!decode(b,n,&p))assert(verify(&w,&p,pk));
    }
    memcpy(b,copy,n);
    b[n]=0;
    assert(decode(b,n+1,&p));
    assert(decode(b,CAP+1,&p));
    trust.count=1;
    memcpy(trust.entries[0].pk,pk,32);
    key_id(trust.entries[0].id,pk);
    strcpy(trust.entries[0].label,"HOST-A");
    const struct identity *who;
    build(4,"HOST-A",0,1000,&n);
    assert(!decode(b,n,&p));
    assert(authorize(&w,&p,&trust,&who)==OK);
    b[11]^=1;
    assert(!decode(b,n,&p));
    assert(authorize(&w,&p,&trust,&who)==UNKNOWN);
    build(4,"HOST-B",0,1000,&n);
    assert(!decode(b,n,&p));
    assert(authorize(&w,&p,&trust,&who)==UNAUTHORIZED);
    build(4,"HOST-A",0,1000,&n);
    assert(!decode(b,n,&p));
    b[57]^=1;
    assert(authorize(&w,&p,&trust,&who)==SIGNATURE);
    assert(fresh(100,130,30,5)==OK);
    assert(fresh(100,131,30,5)==STALE);
    assert(fresh(105,100,30,5)==OK);
    assert(fresh(106,100,30,5)==FUTURE);
    assert(fresh(UINT64_MAX,0,30,5)==FUTURE);
    assert(fresh(0,UINT64_MAX,30,5)==STALE);
    struct session table[2]= {
        0
    };
    p.session=sid;
    p.timestamp=1000;
    p.sequence=1024;
    who=trust.entries;
    assert(replay(table,1,who,&p,1000,30)==OK);
    assert(replay(table,1,who,&p,1000,30)==REPLAY);
    p.sequence=1;
    assert(replay(table,1,who,&p,1000,30)==OK);
    p.sequence=0;
    assert(replay(table,1,who,&p,1000,30)==REPLAY);
    p.sequence=1025;
    p.timestamp=990;
    assert(replay(table,1,who,&p,1000,30)==OK);
    assert(table[0].latest==1000);
    p.sequence=1024;
    assert(replay(table,1,who,&p,1000,30)==REPLAY);
    p.sequence=UINT64_MAX;
    assert(replay(table,1,who,&p,1000,30)==OK);
    p.sequence=UINT64_MAX-1023;
    assert(replay(table,1,who,&p,1000,30)==OK);
    p.sequence=UINT64_MAX-1024;
    assert(replay(table,1,who,&p,1000,30)==REPLAY);
    sid[0]^=1;
    p.sequence=0;
    assert(replay(table,1,who,&p,1030,30)==FULL);
    assert(replay(table,1,who,&p,900,30)==FULL);
    assert(replay(table,1,who,&p,1031,30)==OK);
    assert(replay(table,1,who,&p,1000,30)==REPLAY);
    memset(table,0,sizeof table);
    assert(replay(table,1,who,&p,1000,30)==OK);
    struct identity second=*who;
    second.pk[0]^=1;
    assert(replay(table,2,&second,&p,1000,30)==OK);
    for(unsigned shift=1;shift<=1025;shift++) {
        memset(table,0,sizeof table);
        p.sequence=0;
        assert(replay(table,1,who,&p,1000,30)==OK);
        p.sequence=shift;
        assert(replay(table,1,who,&p,1000,30)==OK);
        p.sequence=0;
        assert(replay(table,1,who,&p,1000,30)==REPLAY);
        if(shift>1) {
            p.sequence=shift-1;
            assert(replay(table,1,who,&p,1000,30)==OK);
            assert(replay(table,1,who,&p,1000,30)==REPLAY);
        }
    }
    /* Parsing random bounded input must never read outside its declared size. */
    for (unsigned trial = 0; trial < 10000; trial++) {
        size_t length = trial % 257;
        randombytes_buf(b, length);
        (void)decode(b, length, &p);
    }
    unsigned char wrong_pk[32], wrong_sk[64];
    crypto_sign_keypair(wrong_pk, wrong_sk);
    build(0, "HOST-A", 0, 1000, &n);
    assert(!decode(b, n, &p));
    assert(verify(&w, &p, wrong_pk));
    for (unsigned c = 0; c < 256; c++) {
        unsigned char ch = (unsigned char)c;
        int expected = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                       (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        assert(label_valid(&ch, 1) == expected);
    }
    assert(!label_valid((const unsigned char *)"", 0));
    assert(encode(&w, b, &n, payload, CAP - 120, "HOST-A", pk, sk, sid, 0, 0));
    sodium_memzero(wrong_sk, sizeof wrong_sk);
    sodium_memzero(sk,sizeof sk);
    puts("protocol: deterministic fixture, round trips, every-byte tamper/truncation, authorization, freshness, replay boundaries passed");
    return 0;
}
