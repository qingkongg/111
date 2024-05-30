#include "cache.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>

uint32_t findline(struct cache * cache,uint32_t set){
    uint64_t time = cache->lines[set].last_access;
    uint32_t line = set;
    for(uint32_t round = 0;round < cache->config.ways;round++){
        uint32_t index =  round * (cache->config.lines / cache->config.ways) + set;
        if(cache->lines[index].last_access < time){
            time = cache->lines[index].last_access;
            line = index;
        }
    }
    return line;
}

uint32_t log21(uint32_t num){
    uint32_t x = 0;
    while(num != 1){
        num = num >> 1;
        x++;
    }
    return x;
}
/* Create a cache simulator according to the config */
struct cache * cache_create(struct cache_config config,struct cache * lower_level){
    struct cache *current = (struct cache*)malloc(sizeof(struct cache));
    
    if(current == NULL){
        return NULL;
    }
    current->offset_bits = log21(config.line_size);
    current->index_bits = log21(config.lines) - log21(config.ways);
    current->tag_bits = config.address_bits - current->index_bits - current->offset_bits;
    current->lower_cache = lower_level;
    current->config = config;
    current->tag_mask = ((1<<(current->tag_bits-1))-1+(1<<(current->tag_bits-1)))*(1<<(current->index_bits + current->offset_bits));
    current->index_mask = ((1 << current->index_bits) - 1) << current->offset_bits;
    current->offset_mask = (1 << current->offset_bits) - 1;
    current->lines = (struct cache_line *)malloc(config.lines * sizeof(struct cache_line));
    
    if(current->lines == NULL){
        return NULL;
    }
    for (uint32_t i = 0; i < config.lines; i++) {
        current->lines[i].valid = false;
        current->lines[i].dirty = false;
        current->lines[i].tag = 0;
        current->lines[i].last_access = 0;
        current->lines[i].data = (uint8_t *)malloc(config.line_size * sizeof(uint8_t));
        if (current->lines[i].data == NULL) {
            cache_destroy(current);
            return NULL;
            }
        }
    return current;
}

void cache_destroy(struct cache* cache){
    for (uint32_t way = 0; way < cache->config.ways ; way++) {
        for (uint32_t set = 0; set < (cache->config.lines / cache->config.ways); set++) {
            uint32_t index = set * cache->config.ways + way;
            struct cache_line *line = &cache->lines[index];
            // 如果行是有效的并且是脏的，则写回
            if (line->valid && line->dirty) {
                // 计算地址
                uint32_t addr = (line->tag << (cache->index_bits + cache->offset_bits)) | (set << cache->offset_bits);
                // 写回数据到下一级缓存或内存
                mem_store(line->data, addr, cache->config.line_size);
                }
            // 释放行数据的内存
            if(cache->lines[index].data)
                free(cache->lines[index].data);
        }
    }
    
    free(cache->lines);
    free(cache);   
}

/* Read one byte at a specific address. return hit=true/miss=false */
bool cache_read_byte(struct cache * cache, uint32_t addr, uint8_t *byte){
    uint32_t tag = (addr & cache->tag_mask) >> (cache->index_bits + cache->offset_bits);
    uint32_t set = (addr & cache->index_mask) >> cache->offset_bits;
    uint32_t offset = addr & cache->offset_mask;
    for(uint32_t round = 0;round < cache->config.ways;round++){
        uint32_t index = round * (cache->config.lines / cache->config.ways) + set;
        if(cache->lines[index].valid){
            if(cache->lines[index].tag == tag){
                cache->lines[index].last_access = get_timestamp();
                *byte = cache->lines[index].data[offset];

                return true;
            }
            //low_level did not exit or not find,find from memory
        }  
    }
    
    // Cache miss, find a line to replace
    uint32_t evict = findline(cache, set);
    struct cache_line *line = &cache->lines[evict];

    // Write back if dirty
    if(line->dirty){
        uint32_t evict_addr = (line->tag << (cache->index_bits + cache->offset_bits)) | (set << cache->offset_bits);
        mem_store(line->data, evict_addr, cache->config.line_size);       
        line->dirty = false;
    }

    // Load the entire line from memory
    uint32_t block_addr = addr & ~(cache->config.line_size - 1);
    mem_load(line->data, block_addr, cache->config.line_size);

    // Update the cache line fields
    line->tag = tag;
    line->valid = true;
    line->last_access = get_timestamp();

    // Return the requested byte
    *byte = line->data[offset];
    return false;
}
/* Write one byte into a specific address. return hit=true/miss=false*/
bool cache_write_byte(struct cache* cache, uint32_t addr, uint8_t byte) {
    uint32_t tag = (addr & cache->tag_mask) >> (cache->index_bits + cache->offset_bits);
    uint32_t set = (addr & cache->index_mask) >> cache->offset_bits;
    uint32_t offset = addr & cache->offset_mask;
    uint32_t block_addr = addr & ~(cache->config.line_size - 1);
    for (uint32_t round = 0; round < cache->config.ways; round++) {
        uint32_t index = round * (uint32_t)((cache->config.lines / cache->config.ways)) + set;
        if (cache->lines[index].valid == false) {
            mem_load(cache->lines[index].data,addr,cache->config.line_size);
            cache->lines[index].tag = tag;
            cache->lines[index].data[offset] = byte;
            cache->lines[index].last_access = get_timestamp();
            cache->lines[index].valid = true;
            if(cache->config.write_back)
                cache->lines[index].dirty = true;
            else if(cache->config.write_back == false){
                mem_store(cache->lines[index].data,block_addr,cache->config.line_size);
            }
            return false;
        }
        else if (cache->lines[index].valid && cache->lines[index].tag == tag) {
            cache->lines[index].data[offset] = byte;
            
            cache->lines[index].last_access = get_timestamp();
            if(cache->config.write_back)
                cache->lines[index].dirty = true;
            else if(cache->config.write_back == false)
                mem_store(cache->lines[index].data,block_addr,cache->config.line_size);
            return true;
        }
    }

    uint32_t evict = findline(cache, set);
    struct cache_line* line = &cache->lines[evict];

    if (cache->lines[evict].dirty && cache->config.write_back) {

        uint32_t addr1 = (line->tag << (cache->index_bits + cache->offset_bits)) | (set << cache->offset_bits);
        // 写回数据到下一级缓存或内存
        mem_store(line->data, addr1, cache->config.line_size );
        line->dirty = false;
    }
    // Update the specific byte
    mem_load(line->data, addr, cache->config.line_size );
    line->data[offset] = byte;
    line->tag = tag;
    line->valid = true;
    line->last_access = get_timestamp();
    if(cache->config.write_back){
        line->dirty = true;
    }
    else{
        mem_store(line->data,block_addr,cache->config.line_size);
    }
    return false;
}


