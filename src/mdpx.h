#ifndef MDPX_H
#define MDPX_H
#include <stdint.h>
#include <stddef.h>
#define CAP 65507
#define TRUST_CAP 4096
struct workspace  {
    unsigned char message[CAP+17];
};
struct packet  {
    const unsigned char *raw,*payload,*signature,*session,*id;
    size_t length, payload_length, label_length;
    char label[64];
    uint64_t timestamp,sequence;
};
struct identity  {
    unsigned char pk[32],id[8];
    char label[64];
};
struct trust  {
    struct identity entries[TRUST_CAP];
    size_t count;
};
struct session  {
    unsigned char pk[32],id[16];
    uint64_t high,latest,bits[16];
    int used;
};
enum result  {
    OK, PARSE, UNKNOWN, UNAUTHORIZED, SIGNATURE, STALE, FUTURE, REPLAY, FULL
};
int label_valid(const unsigned char *,size_t);
void key_id(unsigned char *,const unsigned char *);
uint64_t get64(const unsigned char *);
void put64(unsigned char *,uint64_t);
int encode(struct workspace *,unsigned char *,size_t *,const unsigned char *,size_t,const char *,const unsigned char *,const unsigned char *,const unsigned char *,uint64_t,uint64_t);
int decode(const unsigned char *,size_t,struct packet *);
size_t message(struct workspace *,const struct packet *);
int verify(struct workspace *,const struct packet *,const unsigned char *);
enum result authorize(struct workspace *,const struct packet *,const struct trust *,const struct identity **);
enum result fresh(uint64_t,uint64_t,uint64_t,uint64_t);
enum result replay(struct session *,size_t,const struct identity *,const struct packet *,uint64_t,uint64_t);
int trust_load(const char *,struct trust *);
int secret_load(const char *,unsigned char *,unsigned char *);
int keygen(const char *,const char *);
uint64_t realtime_ms(void);
double monotime(void);
int benchmark(double,const char *);
#endif
