/*
 * cache.c - A cache simulator that can replay traces from Valgrind
 *     and output statistics such as number of hits, misses, and
 *     evictions, both dirty and clean.  The replacement policy is LRU. 
 *     The cache is a writeback cache. 
 * 
 * Updated 2021: M. Hinton
 */
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include "cache.h"

#define ADDRESS_LENGTH 64
#define BYTES_IN_WORD 8

/* Counters used to record cache statistics in printSummary().
   test-cache uses these numbers to verify correctness of the cache. */

//Increment when a miss occurs
int miss_count = 0;

//Increment when a hit occurs
int hit_count = 0;

//Increment when a dirty eviction occurs
int dirty_eviction_count = 0;

//Increment when a clean eviction occurs
int clean_eviction_count = 0;

/* TODO: add more globals, structs, macros if necessary */
int count = 0;

/*
 * Initialize the cache according to specified arguments
 * Called by cache-runner so do not modify the function signature
 *
 * The code provided here shows you how to initialize a cache structure
 * defined above. It's not complete and feel free to modify/add code.
 */
cache_t *create_cache(int s_in, int b_in, int E_in, int d_in)
{
    /* see cache-runner for the meaning of each argument */
    cache_t *cache = malloc(sizeof(cache_t));
    cache->s = s_in;
    cache->b = b_in;
    cache->E = E_in;
    cache->d = d_in;
    unsigned int S = (unsigned int) pow(2, cache->s);
    unsigned int B = (unsigned int) pow(2, cache->b);

    cache->sets = (cache_set_t*) calloc(S, sizeof(cache_set_t));
    for (unsigned int i = 0; i < S; i++){
        cache->sets[i].lines = (cache_line_t*) calloc(cache->E, sizeof(cache_line_t));
        for (unsigned int j = 0; j < cache->E; j++){
            cache->sets[i].lines[j].valid = 0;
            cache->sets[i].lines[j].tag   = 0;
            cache->sets[i].lines[j].lru   = 0;
            cache->sets[i].lines[j].dirty = 0;
            cache->sets[i].lines[j].data  = calloc(B, sizeof(byte_t));
        }
    }

    /* TODO: add more code for initialization */

    return cache;
}

cache_t *create_checkpoint(cache_t *cache) {
    unsigned int S = (unsigned int) pow(2, cache->s);
    unsigned int B = (unsigned int) pow(2, cache->b);
    cache_t *copy_cache = malloc(sizeof(cache_t));
    memcpy(copy_cache, cache, sizeof(cache_t));
    copy_cache->sets = (cache_set_t*) calloc(S, sizeof(cache_set_t));
    for (unsigned int i = 0; i < S; i++) {
        copy_cache->sets[i].lines = (cache_line_t*) calloc(cache->E, sizeof(cache_line_t));
        for (unsigned int j = 0; j < cache->E; j++) {
            memcpy(&copy_cache->sets[i].lines[j], &cache->sets[i].lines[j], sizeof(cache_line_t));
            copy_cache->sets[i].lines[j].data = calloc(B, sizeof(byte_t));
            memcpy(copy_cache->sets[i].lines[j].data, cache->sets[i].lines[j].data, sizeof(byte_t));
        }
    }
    
    return copy_cache;
}

void display_set(cache_t *cache, unsigned int set_index) {
    unsigned int S = (unsigned int) pow(2, cache->s);
    if (set_index < S) {
        cache_set_t *set = &cache->sets[set_index];
        for (unsigned int i = 0; i < cache->E; i++) {
            printf ("Valid: %d Tag: %llx Lru: %lld Dirty: %d\n", set->lines[i].valid, 
                set->lines[i].tag, set->lines[i].lru, set->lines[i].dirty);
        }
    } else {
        printf ("Invalid Set %d. 0 <= Set < %d\n", set_index, S);
    }
}

/*
 * Free allocated memory. Feel free to modify it
 */
void free_cache(cache_t *cache)
{
    unsigned int S = (unsigned int) pow(2, cache->s);
    for (unsigned int i = 0; i < S; i++){
        for (unsigned int j = 0; j < cache->E; j++) {
            free(cache->sets[i].lines[j].data);
        }
        free(cache->sets[i].lines);
    }
    free(cache->sets);
    free(cache);
}

/* TODO:
 * Get the line for address contained in the cache
 * On hit, return the cache line holding the address
 * On miss, returns NULL
 */
cache_line_t *get_line(cache_t *cache, uword_t addr)
{
    uword_t block_addr = addr / (unsigned int) pow(2, cache->b);
    cache_set_t *block_set = &cache->sets[block_addr % (unsigned int) pow(2, cache->s)];
    uword_t block_tag = block_addr / (unsigned int) pow(2, cache->s);
    cache_line_t *curr_line;

    for(int i = 0; i < cache->E; i++){
        curr_line = &block_set->lines[i];
        if(curr_line->valid && block_tag == curr_line->tag){
            return curr_line;
        }
    }
    return NULL;
}

/* TODO:
 * Select the line to fill with the new cache line
 * Return the cache line selected to filled in by addr
 */
cache_line_t *select_line(cache_t *cache, uword_t addr)
{
    /* your implementation */
    cache_set_t *block_set = &cache->sets[(addr / (unsigned int) pow(2, cache->b)) % (unsigned int) pow(2, cache->s)];
    cache_line_t *lru_line = &block_set->lines[0];
    cache_line_t *curr_line = lru_line;
    unsigned int index = 0;

    while(index < cache->E && curr_line->valid){
        if(curr_line->lru < lru_line->lru) lru_line = curr_line; 
        index++;
        curr_line++;
    }

    if(index == cache->E){
        return lru_line;
    } else {
        return curr_line;
    }
}

/* TODO:
 * Check if the address is hit in the cache, updating hit and miss data.
 * Return true if pos hits in the cache.
 */
bool check_hit(cache_t *cache, uword_t addr, operation_t operation)
{
    /* your implementation */
    cache_line_t *line = get_line(cache, addr);
    if(line == NULL){
        miss_count++;
        return false;
    } else {
        hit_count++;
        if(operation == WRITE){
            line->dirty = true;
        }
        // line is now the most recently used line
        line->lru = count++;
        return true;
    }
}

// /* TODO:
//  * Handles Misses, evicting from the cache if necessary.
//  * Fill out the evicted_line_t struct with info regarding the evicted line.
//  */
evicted_line_t *handle_miss(cache_t *cache, uword_t addr, operation_t operation, byte_t *incoming_data)
{
    size_t B = (size_t)pow(2, cache->b);
    evicted_line_t *evicted_line = malloc(sizeof(evicted_line_t));
    evicted_line->data = (byte_t *) calloc(B, sizeof(byte_t));

    cache_line_t *inserted_line = select_line(cache, addr);
    evicted_line->valid = false;
    evicted_line->dirty = false;
        
    evicted_line->addr = ((inserted_line->tag << ((cache->b + cache->s))) | 
    ((unsigned int) (addr / pow(2, cache->b)) % (unsigned int) pow(2, cache->s) << cache->b));

    for(int i = 0; i < B; i++){
        evicted_line->data[i] = inserted_line->data[i];
    }

    if(inserted_line->valid){
        evicted_line->valid = inserted_line->valid;
        evicted_line->dirty = inserted_line->dirty;
        if(inserted_line->dirty) {
            dirty_eviction_count++;
        } else {
            clean_eviction_count++;
        }
    }

    inserted_line->valid = true;
    inserted_line->tag = addr / (unsigned int) pow(2, cache->s + cache->b);
    if(operation == WRITE) {
       inserted_line->dirty = true;
    } else {
        inserted_line->dirty = false;
    }
    inserted_line->lru = count++;
    long offset = (addr & ((int)pow(2, cache->b) - 1));
    if(incoming_data != NULL){
        for(int i = 0; i < B - offset; i++){
            inserted_line->data[i] = incoming_data[i];
        }        
    }
    return evicted_line;
}

// /* TODO:
//  * Get a byte from the cache and write it to dest.
//  * Preconditon: pos is contained within the cache.
//  */
void get_byte_cache(cache_t *cache, uword_t addr, byte_t *dest) {
    cache_line_t *line = get_line(cache, addr);
    uword_t addr_offset = addr % (unsigned int) pow(2, cache->b);
    *dest = line->data[addr_offset];
}


// /* TODO:
//  * Get 8 bytes from the cache and write it to dest.
//  * Preconditon: pos is contained within the cache.
//  */
void get_word_cache(cache_t *cache, uword_t addr, word_t *dest) {
    cache_line_t *line = get_line(cache, addr);
    uword_t addr_offset = addr % (unsigned int) pow(2, cache->b);

    word_t val= 0;
    for (int i = 0; i < 8; i++) {
        word_t b =  line->data[addr_offset + i] & 0xFF;
        val = val | (b <<(8*i));
    }
    *dest = val;
}


// /* TODO:
//  * Set 1 byte in the cache to val at pos.
//  * Preconditon: pos is contained within the cache.
//  */
void set_byte_cache(cache_t *cache, uword_t addr, byte_t val)
{
    cache_line_t *line = select_line(cache, addr);
    uword_t addr_offset = addr % (unsigned int) pow(2, cache->b);
    line->data[addr_offset] = val;
}

// /* TODO:
//  * Set 8 bytes in the cache to val at pos.
//  * Preconditon: pos is contained within the cache.
//  */
void set_word_cache(cache_t *cache, uword_t addr, word_t val)
{
    cache_line_t *line = get_line(cache, addr);
    uword_t addr_offset = addr % (unsigned int) pow(2, cache->b);
    for (int i = 0; i < 8; i++) {
	    line->data[addr_offset + i] = (byte_t) val;
	    val >>= 8;
    }
}

/*
 * Access data at memory address addr
 * If it is already in cache, increast hit_count
 * If it is not in cache, bring it in cache, increase miss count
 * Also increase eviction_count if a line is evicted
 *
 * Called by cache-runner; no need to modify it if you implement
 * check_hit() and handle_miss()
 */
void access_data(cache_t *cache, uword_t addr, operation_t operation)
{
    if(!check_hit(cache, addr, operation))
        free(handle_miss(cache, addr, operation, NULL));
}