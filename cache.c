#include "cache.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>

uint32_t findline(struct cache* cache, uint32_t set) {
    uint64_t time = cache->lines[set].last_access;
    uint32_t line = set;
    for (uint32_t round = 0; round < cache->config.ways; round++) {
        uint32_t index = round * (cache->config.lines / cache->config.ways) + set;
        if (cache->lines[index].last_access < time) {
            time = cache->lines[index].last_access;
            line = index;
        }
    }
    return line;
}

uint32_t log21(uint32_t num) {
    uint32_t x = 0;
    while (num > 1) {
        num = num >> 1;
        x++;
    }
    return x;
}

struct cache* cache_create(struct cache_config config, struct cache* lower_level) {
    struct cache* current = (struct cache*)malloc(sizeof(struct cache));
    if (current == NULL) {
        return NULL;
    }

    current->offset_bits = log21(config.line_size);
    current->index_bits = log21(config.lines) - log21(config.ways);
    current->tag_bits = config.address_bits - current->index_bits - current->offset_bits;
    current->lower_cache = lower_level;
    current->config = config;
    current->tag_mask = ((1 << current->tag_bits) - 1) << (current->index_bits + current->offset_bits);
    current->index_mask = ((1 << current->index_bits) - 1) << current->offset_bits;
    current->offset_mask = (1 << current->offset_bits) - 1;
    current->lines = (struct cache_line*)malloc(config.lines * sizeof(struct cache_line));
    if (current->lines == NULL) {
        free(current);
        return NULL;
    }

    for (uint32_t i = 0; i < config.lines; i++) {
        current->lines[i].valid = false;
        current->lines[i].dirty = false;
        current->lines[i].tag = 0;
        current->lines[i].last_access = 0;
        current->lines[i].data = (uint8_t*)malloc(config.line_size * sizeof(uint8_t));
        if (current->lines[i].data == NULL) {
            cache_destroy(current);
            return NULL;
        }
    }

    return current;
}

void cache_destroy(struct cache* cache) {
    if (cache == NULL) {
        return;
    }

    if (cache->lower_cache) {
        cache_destroy(cache->lower_cache);
        free(cache->lower_cache);
    }

    for (uint32_t i = 0; i < cache->config.lines; i++) {
        if (cache->lines[i].valid && cache->lines[i].dirty) {
            uint32_t addr = (cache->lines[i].tag << (cache->index_bits + cache->offset_bits)) | 
                            ((i % (cache->config.lines / cache->config.ways)) << cache->offset_bits);
            mem_store(cache->lines[i].data, addr, cache->config.line_size);
        }
        free(cache->lines[i].data);
    }

    free(cache->lines);
    free(cache);
}


bool cache_read_byte(struct cache* cache, uint32_t addr, uint8_t* byte) {
    if (byte == NULL) {
        return false;
    }

    uint32_t tag = (addr & cache->tag_mask) >> (cache->index_bits + cache->offset_bits);
    uint32_t set = (addr & cache->index_mask) >> cache->offset_bits;
    uint32_t offset = addr & cache->offset_mask;

    for (uint32_t round = 0; round < cache->config.ways; round++) {
        uint32_t index = round * (cache->config.lines / cache->config.ways) + set;
        if (cache->lines[index].valid && cache->lines[index].tag == tag) {
            cache->lines[index].last_access = get_timestamp();
            *byte = cache->lines[index].data[offset];
            return true;
        }
    }

    uint32_t evict = findline(cache, set);
    struct cache_line* line = &cache->lines[evict];

    if (line->dirty) {
        uint32_t evict_addr = (line->tag << (cache->index_bits + cache->offset_bits)) | (set << cache->offset_bits);
        mem_store(line->data, evict_addr, cache->config.line_size);
        line->dirty = false;
    }

    uint32_t block_addr = addr & ~(cache->config.line_size - 1);
    mem_load(line->data, block_addr, cache->config.line_size);

    line->tag = tag;
    line->valid = true;
    line->last_access = get_timestamp();

    *byte = line->data[offset];
    return false;
}

bool cache_write_byte(struct cache* cache, uint32_t addr, uint8_t byte) {
    uint32_t tag = (addr & cache->tag_mask) >> (cache->index_bits + cache->offset_bits);
    uint32_t set = (addr & cache->index_mask) >> cache->offset_bits;
    uint32_t offset = addr & cache->offset_mask;

    for (uint32_t round = 0; round < cache->config.ways; round++) {
        uint32_t index = round * (cache->config.lines / cache->config.ways) + set;
        if (!cache->lines[index].valid) {
            cache->lines[index].tag = tag;
            cache->lines[index].data[offset] = byte;
            cache->lines[index].last_access = get_timestamp();
            cache->lines[index].valid = true;
            if (cache->config.write_back) {
                cache->lines[index].dirty = true;
            } else {
                mem_store(&byte, addr, 1);
            }
            return false;
        } else if (cache->lines[index].valid && cache->lines[index].tag == tag) {
            cache->lines[index].data[offset] = byte;
            cache->lines[index].dirty = true;
            cache->lines[index].last_access = get_timestamp();
            return true;
        }
    }

    uint32_t evict = findline(cache, set);
    struct cache_line* line = &cache->lines[evict];

    if (line->dirty) {
        uint32_t evict_addr = (line->tag << (cache->index_bits + cache->offset_bits)) | (set << cache->offset_bits);
        mem_store(line->data, evict_addr, cache->config.line_size);
        line->dirty = false;
    }

    uint32_t block_addr = addr & ~(cache->config.line_size - 1);
    mem_load(line->data, block_addr, cache->config.line_size);

    line->data[offset] = byte;
    line->tag = tag;
    line->valid = true;
    line->last_access = get_timestamp();
    if (cache->config.write_back) {
        line->dirty = true;
    } else {
        mem_store(&byte, addr, 1);
    }

    return false;
}

   
