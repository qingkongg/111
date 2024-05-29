#include <stdio.h>
#include "cache.h"
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#define SEED 4938

uint8_t  memory[1024*1024] = {0};
static FILE * log;


void rand_reset() { srand(SEED); }
uint8_t rand_u8() { return (uint8_t)rand(); }

uint64_t ts = 0;

uint64_t get_timestamp(){
    return ts++;
}

void mem_store(uint8_t * src, uint32_t addr,uint32_t count){
    fprintf(log,"mem write at %u\n",addr);
    memcpy(memory+addr,src,count);
}

void mem_load(uint8_t * dst, uint32_t addr, uint32_t count){
    fprintf(log,"mem read at %u\n",addr);
    memcpy(dst,memory+addr,count);
}
// write wrapper
static void write(struct cache * cache,uint32_t addr, uint8_t byte) {
    bool hit = cache_write_byte(cache, addr, byte);
    fprintf(log,"write %4u to %u: %s\n",byte,addr,hit? "HIT" : "MISS");
}

// read wrapper
static uint8_t read(struct cache * cache, uint32_t addr) {
    uint8_t byte = 0;
    bool hit = cache_read_byte(cache, addr, &byte);
    fprintf(log,"read %4u from %u: %s\n",byte,addr,hit? "HIT" : "MISS");
    return byte;
}

// dot product trace
void dot_test(struct cache * L1, uint64_t N) {
    uint32_t a_base=0;
    uint32_t b_base=N;
    uint32_t dot_base=2*N; 

    for (uint64_t i = 0; i < N; i++) {
        uint8_t a = rand_u8();
        uint8_t b = rand_u8();
        write(L1,a_base + i, a);
        write(L1,b_base + i, b);
    }

    write(L1,dot_base,0);

    for (uint64_t i = 0; i < N; i++) {
        uint8_t ai = read(L1,a_base + i);
        uint8_t bi = read(L1,b_base + i);
        uint8_t doti = read(L1,dot_base);
        write(L1,dot_base, doti + ai * bi);
    }
}

int main(){
    struct cache_config L1_config={
    .address_bits = 32,
    .line_size = 4,
    .lines = 16,
    .size = 4*16,
    .ways = 4,
    .write_back = true};

    // struct cache_config L2_config={
    // .address_bits = 32,
    // .line_size = 4,
    // .lines = 32,
    // .size = 4*32,
    // .ways = 8,
    // .write_back = true};

    // To test single-level cache, just assign NULL to L2 and do not desstroy L2 below
    //struct cache * L2 = cache_create(L2_config,NULL);
    struct cache * L1 = cache_create(L1_config,NULL);

    log = fopen("./log","w");

    dot_test(L1,64);

    // we will make sure to first destroy L1 and then L2
    cache_destroy(L1);

    
    fclose(log);

    return 0;
}