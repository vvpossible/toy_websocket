#ifndef _SS_WS_MEM_H_
#define _SS_WS_MEM_H_

#include "gen.h"
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>

#define CACHE_SIZE 4096

struct cache;
struct sub_pool;

typedef struct block 
{
    struct block *next;

    struct cache *owner;

    s8 data[0];

} mem_blk_t;

typedef struct cache
{
    list_head_t cache_list;

    mem_blk_t *avail_blk;

    u16 n_blk;

    u16 n_free_blk;

    struct sub_pool *sp;

} cache_t;


typedef struct sub_pool 
{
    list_head_t cache_head;

    u16 cap;

    u16 curr_cap;

    u32 blk_sz;

    u32 n_ext_alloc;

} sub_pool_t;


typedef struct mem_pool_cfg
{
    u16 blk_sz;

    u16 cap;

} mem_pool_cfg_t;


typedef struct mem_pool
{
    sub_pool_t *subpool;

    u32 n_sys_alloc;

    u8 init;

} mem_pool_t;



#ifdef USE_MEM_POOL

extern void* mem_alloc_real(s32, const s8*, const s8*, s32);
extern void mem_free_real(void* p, const s8*, const s8*, s32);
extern s16 mem_init();
extern void mem_deinit();

#define mem_alloc(size) mem_alloc_real(size, __FILE__, __FUNCTION__, __LINE__)

#define mem_free(p) mem_free_real(p, __FILE__, __FUNCTION__, __LINE__)

#else

#define mem_init()   rok
#define mem_deinit() 
#define mem_alloc malloc
#define mem_free  free

#endif

#endif
