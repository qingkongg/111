#ifndef CACHE_H
#define CACHE_H

#include "stdint.h"
#include "stdbool.h"
#include <time.h>
#include <stdio.h>

// Configuration of the cache
struct cache_config {
    // address space size in bits: A=T+I+O
    uint32_t address_bits;
    // size of each cache line in bytes: guaranteed to be power of 2
    uint32_t line_size;
    // number of lines in the cache: guaranteed to be power of 2
    uint32_t lines;
    // N-way associative cache: guaranteed to be power of 2
    uint32_t ways;
    // total data bytes in the cache
    uint32_t size;
    // write back policy or write through policy
    bool write_back;
};

// Cache line data structure
struct cache_line {
    // the valid bit and dirty bit, initialized to 0
    bool valid, dirty;
    // tag bits of this cache line, initialized to 0
    uint32_t tag;
    // last access timestamp
    // update to `get_timestamp()` on access, initialized to 0
    uint64_t last_access;
    // the data bytes in this cache line, initialized to 0
    uint8_t *data;
};

struct cache {
    // cache simulator configuration
    struct cache_config config;

    // number of bits in tag segment; bit mask for extracting the tag bits.
    uint32_t tag_bits, tag_mask;
    // number of bits in index segment; bit mask for extracting the tag bits.
    uint32_t index_bits, index_mask;
    // number of bits in offset segment; bit mask for extracting the offset bits.
    uint32_t offset_bits, offset_mask;

    // you may use arbitrary memory layout to store them.
    struct cache_line *lines;

    // lower level cache. should be NULL if the cache is the last level cache
    struct cache * lower_cache;
};

/*DO NOT MODIFY FUNCTION DECLARATIONS BELOW*/

struct cache * cache_create(struct cache_config config,struct cache * lower_cache);
void cache_destroy(struct cache* cache);
bool cache_read_byte(struct cache * cache, uint32_t addr, uint8_t *byte);
bool cache_write_byte(struct cache * cache, uint32_t addr, uint8_t byte);

uint64_t get_timestamp();

// DO NOT directly dereference `addr`, you will get a `SIGSEG`
void mem_store(uint8_t * src, uint32_t addr,uint32_t count);
void mem_load(uint8_t * dst, uint32_t addr,uint32_t count);

/*DO NOT MODIFY FUNCTION DECLARATIONS ABOVE*/

#endif